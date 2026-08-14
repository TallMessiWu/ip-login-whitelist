#!/usr/bin/env python3
"""
IP Login Whitelist Manager
通过 iptables 管理服务器 SSH 登录 IP 白名单，支持批量下发生效。
"""

import json
import os
import re
import sys
import base64
import hashlib
import secrets
import argparse
import datetime
import subprocess
import threading
import ipaddress
import getpass
from pathlib import Path
from urllib.parse import urlparse

# 所有 config.json 读写必须持有此锁，防止并发写覆盖和 TOCTOU 竞态
CONFIG_LOCK = threading.RLock()

CONFIG_FILE = Path(__file__).parent / "config.json"

# 进程内密码缓存，key = "user@host"，避免同一次运行反复提示
_password_cache: dict = {}

# 远端脚本执行/读输出超时（秒）。给慢服务器（firewalld reload / iptables 持久化 /
# IP 条目多）留足余量，避免脚本实际已成功却因读输出超时被误判失败。
# 注意：「慢」由并发下发 + 连接超时（各路径 30s）解决，本超时只兜底脚本真卡死。
EXEC_TIMEOUT = 120

DEFAULT_CONFIG = {
    "whitelist": [],
    "public_key_whitelist": [],
    "servers": [],
    "settings": {
        "ssh_port": 22,
        "persist_rules": True,
        "proxy": "",
        "auto_deploy": {
            "enabled": False,
            "interval_minutes": 5
        }
    }
}

def _resolve_proxy(server: dict, config: dict) -> str:
    """按优先级解析代理：per-server > 全局 settings > 环境变量"""
    if server.get("proxy"):
        return server["proxy"]
    if config.get("settings", {}).get("proxy"):
        return config["settings"]["proxy"]
    for env in ("ALL_PROXY", "all_proxy", "SOCKS_PROXY", "socks_proxy"):
        v = os.environ.get(env, "")
        if v:
            return v
    return ""


# ─── 配置管理 ────────────────────────────────────────────────────────────────

def load_config(purge: bool = True) -> dict:
    with CONFIG_LOCK:
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    config = json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                corrupt = CONFIG_FILE.with_suffix(".json.corrupted")
                try:
                    os.replace(CONFIG_FILE, corrupt)
                    print(f"[WARN] config.json 已损坏({e})，已备份为 {corrupt.name}，使用默认配置")
                except OSError:
                    print(f"[WARN] config.json 已损坏({e})，无法备份，使用默认配置")
                return json.loads(json.dumps(DEFAULT_CONFIG))
            config.setdefault("whitelist", [])
            config.setdefault("public_key_whitelist", [])
            config.setdefault("servers", [])
            for server in config["servers"]:
                server.setdefault("whitelist", [])
                server.setdefault("public_key_whitelist", [])
            if purge:
                removed = purge_expired_entries(config)
                if removed:
                    # 静默回写，不触发 save_config 的 "[OK] 配置已保存" 提示
                    _encrypt_passwords(config)
                    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(config, f, indent=2, ensure_ascii=False)
                    for scope, e in removed:
                        label = e.get("ip") or f"{e.get('linux_user', '')} {e.get('fingerprint', '')}".strip()
                        print(f"[INFO] 已自动清除过期白名单: [{scope}] {label} (过期于 {e['expire_at']})")
            _decrypt_passwords(config)
            return config
        return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(config: dict):
    # 加密 → 写盘 → 再解密回内存，确保调用者后续仍能取到明文密码（_encrypt_passwords
    # 是原地修改：若不在此处复原，调用者拿到的 srv["password"] 会变成 "enc:..." 加密串，
    # 再传给 SSH 子进程就会认证失败。
    _encrypt_passwords(config)
    with CONFIG_LOCK:
        tmp = CONFIG_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_FILE)
    _decrypt_passwords(config)
    print(f"[OK] 配置已保存到 {CONFIG_FILE}")


def _ensure_encryption_key(config: dict) -> bytes:
    """确保 config 中有加密密钥，不存在则生成。返回密钥 bytes。"""
    settings = config.setdefault("settings", {})
    key_b64 = settings.get("encryption_key")
    if key_b64:
        return base64.urlsafe_b64decode(key_b64.encode())
    key = secrets.token_bytes(32)
    settings["encryption_key"] = base64.urlsafe_b64encode(key).decode()
    return key


_ENCRYPT_MARKER = "enc:"


def _encrypt_passwords(config: dict):
    """加密 config 中所有 server 的 password 字段（跳过已加密的）。"""
    servers = config.get("servers", [])
    if not servers:
        return
    key = _ensure_encryption_key(config)
    for srv in servers:
        pw = srv.get("password", "")
        if not pw or pw.startswith(_ENCRYPT_MARKER):
            continue
        # PBKDF2 派生每个密码独立的加密密钥
        salt = secrets.token_bytes(16)
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 100_000, dklen=len(pw.encode()))
        encrypted = bytes(a ^ b for a, b in zip(pw.encode(), derived))
        encrypted_b64 = base64.urlsafe_b64encode(salt + encrypted).decode()
        srv["password"] = _ENCRYPT_MARKER + encrypted_b64


def _decrypt_passwords(config: dict):
    """解密 config 中所有 server 的 password 字段（仅解密 enc: 前缀的）。"""
    settings = config.get("settings", {})
    key_b64 = settings.get("encryption_key")
    if not key_b64:
        return
    key = base64.urlsafe_b64decode(key_b64.encode())
    for srv in config.get("servers", []):
        pw = srv.get("password", "")
        if not pw.startswith(_ENCRYPT_MARKER):
            continue
        raw = base64.urlsafe_b64decode(pw[len(_ENCRYPT_MARKER):])
        salt = raw[:16]
        encrypted = raw[16:]
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 100_000, dklen=len(encrypted))
        srv["password"] = bytes(a ^ b for a, b in zip(encrypted, derived)).decode()


def validate_ip_or_cidr(ip_str: str) -> bool:
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


_PUBLIC_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
_LINUX_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,30}\$?$")


def validate_linux_user(linux_user: str) -> bool:
    """校验可安全用于远端文件名和 getent 的 Linux 用户名。"""
    return bool(_LINUX_USER_RE.fullmatch((linux_user or "").strip()))


def normalize_public_key(public_key: str) -> tuple[str, bytes]:
    """校验并规范化 OpenSSH 公钥，返回 (type + base64, decoded_blob)。

    只接受无 authorized_keys options 的普通公钥；注释会被丢弃。
    """
    raw = (public_key or "").strip()
    if not raw or "PRIVATE KEY" in raw:
        raise ValueError("公钥不能为空，且不能提交私钥")
    parts = raw.split()
    if len(parts) < 2 or parts[0] not in _PUBLIC_KEY_TYPES:
        raise ValueError("不支持的公钥格式、密钥类型或 authorized_keys 选项")
    key_type, encoded = parts[0], parts[1]
    try:
        blob = base64.b64decode(encoded, validate=True)
    except Exception as e:
        raise ValueError("公钥 Base64 内容无效") from e
    if len(blob) < 4:
        raise ValueError("公钥内容不完整")
    type_len = int.from_bytes(blob[:4], "big")
    if type_len <= 0 or 4 + type_len > len(blob):
        raise ValueError("公钥内容结构无效")
    try:
        embedded_type = blob[4:4 + type_len].decode("ascii")
    except UnicodeDecodeError as e:
        raise ValueError("公钥内部类型无效") from e
    if embedded_type != key_type:
        raise ValueError("公钥声明类型与内容不一致")
    return f"{key_type} {encoded}", blob


def _public_key_identity(public_key: str, linux_user: str) -> tuple[str, str, str]:
    user = (linux_user or "").strip()
    if not validate_linux_user(user):
        raise ValueError("Linux 用户名格式无效")
    normalized, blob = normalize_public_key(public_key)
    digest = hashlib.sha256(blob).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    key_id = hashlib.sha256(user.encode() + b"\0" + blob).hexdigest()
    return normalized, fingerprint, key_id


# ─── 时效管理 ────────────────────────────────────────────────────────────────

_EXPIRE_FMT = "%Y-%m-%d %H:%M:%S"


def parse_expire(expire_str: str) -> str | None:
    """解析过期时间字符串，返回 '%Y-%m-%d %H:%M:%S' 格式，或 None（永久）。

    支持格式：
      - 留空 / 'never' / '永久' → 永久（返回 None）
      - '7d' / '24h' / '30m'   → 相对于当前时刻的相对时间
      - '2025-12-31'            → 当天结束（23:59:59）
      - '2025-12-31 23:59:59'   → 绝对时间
      - '2025-12-31T23:59'      → datetime-local 格式（来自 HTML input）
    """
    if not expire_str or expire_str.strip().lower() in ('', 'never', '永久', 'permanent'):
        return None
    s = expire_str.strip()
    m = re.match(r'^(\d+)([dhm])$', s.lower())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {'d': datetime.timedelta(days=n),
                 'h': datetime.timedelta(hours=n),
                 'm': datetime.timedelta(minutes=n)}[unit]
        return (datetime.datetime.now() + delta).strftime(_EXPIRE_FMT)
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(s, fmt).strftime(_EXPIRE_FMT)
        except ValueError:
            continue
    try:
        # 仅日期：设为当天 23:59:59
        return datetime.datetime.strptime(s, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59).strftime(_EXPIRE_FMT)
    except ValueError:
        pass
    raise ValueError(
        f"无效的过期时间格式: {expire_str!r}，"
        "支持：7d / 24h / 30m / 2025-12-31 / 2025-12-31 23:59:59"
    )


def is_entry_expired(entry: dict) -> bool:
    """判断白名单条目是否已过期。无 expire_at 字段视为永久有效。"""
    expire_at = entry.get("expire_at")
    if not expire_at:
        return False
    try:
        return datetime.datetime.now() > datetime.datetime.strptime(expire_at, _EXPIRE_FMT)
    except (ValueError, TypeError):
        return False


def purge_expired_entries(config: dict) -> list:
    """清除 config 中已过期的白名单条目（原地修改）。
    返回被清除的条目列表，每项为 (scope: str, entry: dict)。"""
    removed = []

    valid, expired = [], []
    for e in config.get("whitelist", []):
        (expired if is_entry_expired(e) else valid).append(e)
    config["whitelist"] = valid
    removed.extend(("全局", e) for e in expired)

    valid, expired = [], []
    for e in config.get("public_key_whitelist", []):
        (expired if is_entry_expired(e) else valid).append(e)
    config["public_key_whitelist"] = valid
    removed.extend(("全局公钥", e) for e in expired)

    for srv in config.get("servers", []):
        valid, expired = [], []
        for e in srv.get("whitelist", []):
            (expired if is_entry_expired(e) else valid).append(e)
        srv["whitelist"] = valid
        scope = srv.get("name") or srv["host"]
        removed.extend((scope, e) for e in expired)

        valid, expired = [], []
        for e in srv.get("public_key_whitelist", []):
            (expired if is_entry_expired(e) else valid).append(e)
        srv["public_key_whitelist"] = valid
        removed.extend((f"{scope} 公钥", e) for e in expired)

    return removed


# ─── IP 白名单管理 ────────────────────────────────────────────────────────────

def _find_server(config: dict, host_or_name: str) -> dict | None:
    """按 host 或 name 查找服务器，找不到返回 None。"""
    for s in config.get("servers", []):
        if s["host"] == host_or_name or s.get("name") == host_or_name:
            return s
    return None


def _make_ip_entry(ip: str, desc: str, expire_at: str = None, added_by: str = None) -> dict:
    entry = {
        "ip": ip,
        "description": desc or "",
        "added_by": added_by or getpass.getuser(),
        "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if expire_at:
        entry["expire_at"] = expire_at
    return entry


def get_merged_whitelist(server: dict, global_whitelist: list) -> list:
    """合并全局白名单与服务器专属白名单（去重、过滤已过期）。"""
    seen = set()
    merged = []
    for entry in global_whitelist + server.get("whitelist", []):
        if entry["ip"] not in seen and not is_entry_expired(entry):
            seen.add(entry["ip"])
            merged.append(entry)
    return merged


def get_merged_public_keys(server: dict, global_public_keys: list) -> list:
    """合并全局与服务器专属公钥（按用户+密钥去重、过滤过期）。"""
    seen = set()
    merged = []
    for entry in global_public_keys + server.get("public_key_whitelist", []):
        identity = entry.get("id") or (entry.get("linux_user"), entry.get("public_key"))
        if identity not in seen and not is_entry_expired(entry):
            seen.add(identity)
            merged.append(entry)
    return merged


def _make_public_key_entry(public_key: str, linux_user: str, desc: str,
                           expire_at: str = None, added_by: str = None,
                           locked: bool = False) -> dict:
    normalized, fingerprint, key_id = _public_key_identity(public_key, linux_user)
    entry = {
        "id": key_id,
        "public_key": normalized,
        "fingerprint": fingerprint,
        "linux_user": linux_user.strip(),
        "description": desc or "",
        "added_by": added_by or getpass.getuser(),
        "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if expire_at:
        entry["expire_at"] = expire_at
    if locked:
        entry["locked"] = True
    return entry


def cmd_ip_add(args):
    config = load_config()
    ip = args.ip.strip()

    if not validate_ip_or_cidr(ip):
        print(f"[ERROR] 无效的 IP 或 CIDR 格式: {ip}")
        sys.exit(1)

    expire_at = None
    if getattr(args, 'expire', None):
        try:
            expire_at = parse_expire(args.expire)
        except ValueError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)
    expire_label = f"，过期时间: {expire_at}" if expire_at else "（永久）"

    if args.server:
        # 添加到指定服务器的专属白名单
        srv = _find_server(config, args.server)
        if not srv:
            print(f"[ERROR] 未找到服务器: {args.server}")
            sys.exit(1)
        wl = srv.setdefault("whitelist", [])
        if any(e["ip"] == ip for e in wl):
            print(f"[WARN] {ip} 已在 {srv['name']} 的专属白名单中，跳过")
            return
        wl.append(_make_ip_entry(ip, args.desc, expire_at))
        save_config(config)
        print(f"[OK] 已添加 {ip} 到 {srv['name']} 的专属白名单{expire_label}")
    else:
        # 添加到全局白名单
        if any(e["ip"] == ip for e in config["whitelist"]):
            print(f"[WARN] {ip} 已在全局白名单中，跳过")
            return
        new_entry = _make_ip_entry(ip, args.desc, expire_at)
        config["whitelist"].append(new_entry)

        # 全局已覆盖，清理各服务器专属白名单中的重复 IP；继承锁定状态
        cleaned = 0
        inherited_locked = False
        for srv in config.get("servers", []):
            wl = srv.get("whitelist", [])
            for e in wl:
                if e["ip"] == ip and e.get("locked"):
                    inherited_locked = True
                    break
            before = len(wl)
            srv["whitelist"] = [e for e in wl if e["ip"] != ip]
            cleaned += before - len(srv["whitelist"])

        if inherited_locked:
            new_entry["locked"] = True

        save_config(config)
        msg = f"[OK] 已添加 {ip} 到全局白名单{expire_label}"
        if cleaned:
            msg += f"，已从 {cleaned} 台服务器专属白名单中移除（全局已覆盖）"
        if inherited_locked:
            msg += "；已继承原专属白名单的锁定状态"
        print(msg)


def cmd_ip_remove(args):
    config = load_config()
    ip = args.ip.strip()

    if args.server:
        srv = _find_server(config, args.server)
        if not srv:
            print(f"[ERROR] 未找到服务器: {args.server}")
            sys.exit(1)
        before = len(srv.get("whitelist", []))
        srv["whitelist"] = [e for e in srv.get("whitelist", []) if e["ip"] != ip]
        if len(srv["whitelist"]) == before:
            print(f"[WARN] {ip} 不在 {srv['name']} 的专属白名单中")
            return
        save_config(config)
        print(f"[OK] 已从 {srv['name']} 的专属白名单移除 {ip}")
    else:
        before = len(config["whitelist"])
        config["whitelist"] = [e for e in config["whitelist"] if e["ip"] != ip]
        if len(config["whitelist"]) == before:
            print(f"[WARN] {ip} 不在全局白名单中")
            return
        save_config(config)
        print(f"[OK] 已从全局白名单移除 {ip}")


def cmd_ip_list(args):
    config = load_config()

    if args.server:
        srv = _find_server(config, args.server)
        if not srv:
            print(f"[ERROR] 未找到服务器: {args.server}")
            sys.exit(1)
        wl = srv.get("whitelist", [])
        label = f"{srv['name']} 的专属白名单"
    else:
        wl = config["whitelist"]
        label = "全局白名单"

    if not wl:
        print(f"{label} 为空")
        return

    print(f"\n── {label} ──")
    print(f"\n{'IP/CIDR':<20} {'备注':<20} {'添加人':<15} {'添加时间':<22} {'有效期'}")
    print("-" * 95)
    for e in wl:
        if e.get("expire_at"):
            expire_info = e["expire_at"]
            if is_entry_expired(e):
                expire_info += " [已过期]"
        else:
            expire_info = "永久"
        print(f"{e['ip']:<20} {e.get('description',''):<20} {e.get('added_by',''):<15} "
              f"{e.get('added_at',''):<22} {expire_info}")
    print(f"\n共 {len(wl)} 条记录")


def _read_public_key_arg(args) -> str:
    if getattr(args, "key_file", None):
        try:
            return Path(args.key_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"[ERROR] 无法读取公钥文件: {e}")
            sys.exit(1)
    return getattr(args, "public_key", "") or ""


def cmd_pubkey_add(args):
    config = load_config()
    try:
        expire_at = parse_expire(args.expire) if args.expire else None
        entry = _make_public_key_entry(
            _read_public_key_arg(args), args.user, args.desc, expire_at,
            locked=args.lock,
        )
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    if args.server:
        srv = _find_server(config, args.server)
        if not srv:
            print(f"[ERROR] 未找到服务器: {args.server}")
            sys.exit(1)
        wl = srv.setdefault("public_key_whitelist", [])
        if any(e.get("id") == entry["id"] for e in wl):
            print(f"[WARN] {entry['fingerprint']} 已在 {srv['name']} 的公钥白名单中，跳过")
            return
        wl.append(entry)
        label = f"{srv['name']} 的专属公钥白名单"
    else:
        wl = config.setdefault("public_key_whitelist", [])
        if any(e.get("id") == entry["id"] for e in wl):
            print(f"[WARN] {entry['fingerprint']} 已在全局公钥白名单中，跳过")
            return
        inherited_locked = False
        for srv in config.get("servers", []):
            current = srv.get("public_key_whitelist", [])
            inherited_locked = inherited_locked or any(
                e.get("id") == entry["id"] and e.get("locked") for e in current
            )
            srv["public_key_whitelist"] = [e for e in current if e.get("id") != entry["id"]]
        if inherited_locked:
            entry["locked"] = True
        wl.append(entry)
        label = "全局公钥白名单"
    save_config(config)
    print(f"[OK] 已添加 {entry['linux_user']} {entry['fingerprint']} 到{label}")


def _find_public_key_entry(config: dict, key_id: str, server_name: str = None):
    if server_name:
        srv = _find_server(config, server_name)
        if not srv:
            return None, None
        return srv, next((e for e in srv.get("public_key_whitelist", []) if e.get("id") == key_id), None)
    return config, next((e for e in config.get("public_key_whitelist", []) if e.get("id") == key_id), None)


def cmd_pubkey_remove(args):
    config = load_config()
    owner, entry = _find_public_key_entry(config, args.id, args.server)
    if owner is None:
        print(f"[ERROR] 未找到服务器: {args.server}")
        sys.exit(1)
    if not entry:
        print(f"[WARN] 未找到公钥 ID: {args.id}")
        return
    if entry.get("locked"):
        print("[ERROR] 公钥已锁定，请先解锁")
        sys.exit(1)
    owner["public_key_whitelist"] = [e for e in owner.get("public_key_whitelist", []) if e.get("id") != args.id]
    save_config(config)
    print(f"[OK] 已移除 {entry['linux_user']} {entry['fingerprint']}")


def cmd_pubkey_list(args):
    config = load_config()
    if args.server:
        srv = _find_server(config, args.server)
        if not srv:
            print(f"[ERROR] 未找到服务器: {args.server}")
            sys.exit(1)
        wl = srv.get("public_key_whitelist", [])
        label = f"{srv['name']} 的专属公钥白名单"
    else:
        wl = config.get("public_key_whitelist", [])
        label = "全局公钥白名单"
    print(f"\n── {label} ──")
    if not wl:
        print("(空)")
        return
    for e in wl:
        expires = e.get("expire_at") or "永久"
        lock = " [锁定]" if e.get("locked") else ""
        print(f"{e['id']}  {e['linux_user']}  {e['fingerprint']}  {expires}{lock}  {e.get('description', '')}")


def cmd_pubkey_lock(args):
    config = load_config()
    owner, entry = _find_public_key_entry(config, args.id, args.server)
    if owner is None:
        print(f"[ERROR] 未找到服务器: {args.server}")
        sys.exit(1)
    if not entry:
        print(f"[ERROR] 未找到公钥 ID: {args.id}")
        sys.exit(1)
    if args.pubkey_command == "lock":
        entry["locked"] = True
    else:
        entry.pop("locked", None)
    save_config(config)
    print(f"[OK] 已{'锁定' if args.pubkey_command == 'lock' else '解锁'} {entry['fingerprint']}")


# ─── 服务器管理 ───────────────────────────────────────────────────────────────

def cmd_server_add(args):
    config = load_config()
    host = args.host.strip()

    existing = [s["host"] for s in config["servers"]]
    if host in existing:
        print(f"[WARN] 服务器 {host} 已存在")
        return

    server = {
        "host": host,
        "port": args.port if args.port is not None else 22,
        "user": args.user or "root",
        "key_file": args.key or "",
        "name": args.name or host,
        "password": args.password or "",
        "proxy": args.proxy or "",
        "whitelist": [],
        "public_key_whitelist": [],
        "enabled": True
    }
    config["servers"].append(server)
    save_config(config)
    print(f"[OK] 已添加服务器 {server['name']} ({host}:{server['port']})")


def cmd_server_remove(args):
    config = load_config()
    host = args.host.strip()
    before = len(config["servers"])
    config["servers"] = [s for s in config["servers"] if s["host"] != host]

    if len(config["servers"]) == before:
        print(f"[WARN] 服务器 {host} 不存在")
        return

    save_config(config)
    print(f"[OK] 已移除服务器 {host}")


def cmd_server_list(args):
    config = load_config()
    servers = config["servers"]
    if not servers:
        print("服务器列表为空")
        return

    print(f"\n{'名称':<20} {'地址':<20} {'端口':<8} {'用户':<15} {'密钥文件':<20} {'状态':<8} {'代理'}")
    print("-" * 108)
    for s in servers:
        key_info = s.get('key_file') or ('(密码)' if s.get('password') else '(交互)')
        proxy_info = s.get('proxy') or '-'
        status = '启用' if s.get('enabled', True) else '禁用'
        print(f"{s.get('name',''):<20} {s['host']:<20} {s.get('port',22):<8} {s.get('user','root'):<15} {key_info:<20} {status:<8} {proxy_info}")
    print(f"\n共 {len(servers)} 台服务器")


# ─── 生成远端执行脚本 ─────────────────────────────────────────────────────────

def generate_apply_script(whitelist: list, ssh_port: int, persist: bool, audit: bool = False,
                          public_keys: list = None) -> str:
    ip_array_lines = "\n".join(f'"{e["ip"]}"' for e in whitelist)
    public_keys = [e for e in (public_keys or []) if not is_entry_expired(e)]
    keys_by_user = {}
    for entry in public_keys:
        user = entry["linux_user"]
        if not validate_linux_user(user):
            raise ValueError(f"无效的公钥 Linux 用户名: {user}")
        normalized, _ = normalize_public_key(entry["public_key"])
        keys_by_user.setdefault(user, []).append(normalized)
    key_users = list(keys_by_user)
    key_user_lines = "\n".join(f'"{u}"' for u in key_users)
    key_payload_lines = "\n".join(
        f'"{base64.b64encode((chr(10).join(keys_by_user[u]) + chr(10)).encode()).decode()}"'
        for u in key_users
    )
    if whitelist:
        match_address = "*," + ",".join(f'!{e["ip"]}' for e in whitelist)
    else:
        match_address = "*"
    allowed_test_ip = ""
    if whitelist:
        network = ipaddress.ip_network(whitelist[0]["ip"], strict=False)
        allowed_test_ip = str(next(iter(network.hosts()), network.network_address))
    outside_test_ip = ""
    networks = []
    for entry in whitelist:
        try:
            networks.append(ipaddress.ip_network(entry["ip"], strict=False))
        except ValueError:
            pass
    for candidate in ("198.51.100.254", "203.0.113.254", "192.0.2.254", "8.8.8.8"):
        addr = ipaddress.ip_address(candidate)
        if not any(addr.version == net.version and addr in net for net in networks):
            outside_test_ip = candidate
            break
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label = "审计模式（只记录，不拦截）" if audit else "生产模式（真实拦截）"

    script = f"""#!/bin/bash
# IP 登录白名单部署脚本 - 由 whitelist_manager 自动生成
# 生成时间: {ts}
# 运行模式: {mode_label}

SSH_PORT={ssh_port}
WHITELIST_IPS=(
{ip_array_lines}
)
PUBLIC_KEY_USERS=(
{key_user_lines}
)
PUBLIC_KEY_PAYLOADS=(
{key_payload_lines}
)
CHAIN="SSH_WHITELIST"
PERSIST={str(persist).lower()}
AUDIT={str(audit).lower()}
HYBRID_MODE={str(bool(public_keys)).lower()}
MATCH_ADDRESS="{match_address}"
ALLOWED_TEST_IP="{allowed_test_ip}"
OUTSIDE_TEST_IP="{outside_test_ip}"
MANAGED_ROOT="/etc/ssh/ip-login-whitelist"
MANAGED_KEYS="$MANAGED_ROOT/authorized_keys"
SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/90-ip-login-whitelist.conf"
SSHD_INCLUDE_MARKER="# ip-login-whitelist managed include"

echo "=== 开始部署 SSH IP 白名单 [{mode_label}] ==="
echo "服务器: $(hostname)  系统: $(. /etc/os-release 2>/dev/null && echo $NAME $VERSION_ID || uname -r)"
echo "SSH 端口: $SSH_PORT"
echo "白名单 IP: ${{WHITELIST_IPS[*]}}"
echo "托管公钥: ${{#PUBLIC_KEY_USERS[@]}} 个 Linux 用户"
echo ""

SSHD_BIN=$(command -v sshd 2>/dev/null || true)
[ -n "$SSHD_BIN" ] || [ ! -x /usr/sbin/sshd ] || SSHD_BIN=/usr/sbin/sshd

reload_sshd() {{
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
        service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || \
        pkill -HUP -x sshd 2>/dev/null
}}

restore_sshd_backup() {{
    local backup="$1"
    cp -a "$backup/sshd_config" "$SSHD_MAIN"
    if [ -e "$backup/dropin" ]; then
        mkdir -p "$(dirname "$SSHD_DROPIN")"
        cp -a "$backup/dropin" "$SSHD_DROPIN"
    else
        rm -f "$SSHD_DROPIN"
    fi
    rm -rf "$MANAGED_ROOT"
    [ ! -d "$backup/managed_root" ] || cp -a "$backup/managed_root" "$MANAGED_ROOT"
    "$SSHD_BIN" -t && reload_sshd
}}

enable_managed_public_keys() {{
    [ -n "$SSHD_BIN" ] || {{ echo "[ERROR] 未找到 sshd，无法启用公钥白名单"; return 1; }}
    [ -f "$SSHD_MAIN" ] || {{ echo "[ERROR] 未找到 $SSHD_MAIN"; return 1; }}
    for user in "${{PUBLIC_KEY_USERS[@]}}"; do
        getent passwd "$user" >/dev/null || {{ echo "[ERROR] Linux 用户不存在: $user"; return 1; }}
    done

    local backup stage first_match include_line idx user effective_allowed effective_outside
    backup=$(mktemp -d /tmp/ip-login-whitelist-backup.XXXXXX) || return 1
    stage=$(mktemp -d /tmp/ip-login-whitelist-stage.XXXXXX) || {{ rm -rf "$backup"; return 1; }}
    cp -a "$SSHD_MAIN" "$backup/sshd_config"
    [ ! -e "$SSHD_DROPIN" ] || cp -a "$SSHD_DROPIN" "$backup/dropin"
    [ ! -d "$MANAGED_ROOT" ] || cp -a "$MANAGED_ROOT" "$backup/managed_root"

    mkdir -p "$stage/authorized_keys" /etc/ssh/sshd_config.d
    chmod 0755 "$stage" "$stage/authorized_keys"
    idx=0
    for user in "${{PUBLIC_KEY_USERS[@]}}"; do
        printf '%s' "${{PUBLIC_KEY_PAYLOADS[$idx]}}" | base64 -d > "$stage/authorized_keys/$user" || {{ rm -rf "$backup" "$stage"; return 1; }}
        chmod 0644 "$stage/authorized_keys/$user"
        idx=$((idx + 1))
    done

    cat > "$stage/90-ip-login-whitelist.conf" <<EOF_SSHD
# Managed by ip-login-whitelist. Do not edit.
Match Address $MATCH_ADDRESS
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    AuthorizedKeysFile /etc/ssh/ip-login-whitelist/authorized_keys/%u
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    HostbasedAuthentication no
    GSSAPIAuthentication no
    KerberosAuthentication no
Match all
EOF_SSHD
    chmod 0644 "$stage/90-ip-login-whitelist.conf"

    first_match=$(grep -nEi '^[[:space:]]*Match[[:space:]]' "$SSHD_MAIN" | head -1 | cut -d: -f1)
    include_line=$(grep -nEi '^[[:space:]]*Include[[:space:]].*sshd_config\\.d/(\\*\\.conf|90-ip-login-whitelist\\.conf)' "$SSHD_MAIN" | head -1 | cut -d: -f1)
    if [ -z "$include_line" ] || {{ [ -n "$first_match" ] && [ "$include_line" -gt "$first_match" ]; }}; then
        awk -v marker="$SSHD_INCLUDE_MARKER" '
            BEGIN {{ inserted=0 }}
            /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/ && !inserted {{
                print marker; print "Include /etc/ssh/sshd_config.d/90-ip-login-whitelist.conf"; inserted=1
            }}
            {{ print }}
            END {{ if (!inserted) {{ print marker; print "Include /etc/ssh/sshd_config.d/90-ip-login-whitelist.conf" }} }}
        ' "$SSHD_MAIN" > "$stage/sshd_config"
        cp "$stage/sshd_config" "$SSHD_MAIN"
    fi

    mkdir -p "$MANAGED_ROOT"
    rm -rf "$MANAGED_KEYS"
    cp -a "$stage/authorized_keys" "$MANAGED_KEYS"
    cp "$stage/90-ip-login-whitelist.conf" "$SSHD_DROPIN"
    chown -R root:root "$MANAGED_ROOT" "$SSHD_DROPIN" 2>/dev/null || true

    if ! "$SSHD_BIN" -t; then
        echo "[ERROR] sshd -t 校验失败，正在回滚"
        restore_sshd_backup "$backup" || true
        rm -rf "$backup" "$stage"
        return 1
    fi
    if [ -n "$OUTSIDE_TEST_IP" ]; then
        effective_outside=$("$SSHD_BIN" -T -C "user=${{PUBLIC_KEY_USERS[0]}},addr=$OUTSIDE_TEST_IP,host=localhost" 2>/dev/null)
        echo "$effective_outside" | grep -q '^authenticationmethods publickey$' && \
        echo "$effective_outside" | grep -q '^authorizedkeysfile /etc/ssh/ip-login-whitelist/authorized_keys/%u$' || {{
            echo "[ERROR] sshd -T 显示非白名单 IP 未进入托管公钥策略，正在回滚"
            restore_sshd_backup "$backup" || true
            rm -rf "$backup" "$stage"
            return 1
        }}
    fi
    if [ -n "$ALLOWED_TEST_IP" ]; then
        effective_allowed=$("$SSHD_BIN" -T -C "user=${{PUBLIC_KEY_USERS[0]}},addr=$ALLOWED_TEST_IP,host=localhost" 2>/dev/null)
        if echo "$effective_allowed" | grep -q '^authorizedkeysfile /etc/ssh/ip-login-whitelist/authorized_keys/%u$'; then
            echo "[ERROR] 白名单 IP 仍被限制为托管公钥，正在回滚"
            restore_sshd_backup "$backup" || true
            rm -rf "$backup" "$stage"
            return 1
        fi
    fi
    if ! reload_sshd; then
        echo "[ERROR] SSH 服务 reload 失败，正在回滚"
        restore_sshd_backup "$backup" || true
        rm -rf "$backup" "$stage"
        return 1
    fi
    rm -rf "$backup" "$stage"
    echo "[OK] sshd 托管公钥策略已通过语法、有效配置与 reload 校验"
}}

disable_managed_public_keys() {{
    [ -e "$SSHD_DROPIN" ] || grep -qF "$SSHD_INCLUDE_MARKER" "$SSHD_MAIN" 2>/dev/null || return 0
    [ -n "$SSHD_BIN" ] || {{ echo "[ERROR] 未找到 sshd，无法恢复原认证"; return 1; }}
    local backup stage
    backup=$(mktemp -d /tmp/ip-login-whitelist-backup.XXXXXX) || return 1
    stage=$(mktemp -d /tmp/ip-login-whitelist-stage.XXXXXX) || {{ rm -rf "$backup"; return 1; }}
    cp -a "$SSHD_MAIN" "$backup/sshd_config"
    [ ! -d "$MANAGED_ROOT" ] || cp -a "$MANAGED_ROOT" "$backup/managed_root"
    awk -v marker="$SSHD_INCLUDE_MARKER" '
        $0 == marker {{ skip=1; next }}
        skip && $0 == "Include /etc/ssh/sshd_config.d/90-ip-login-whitelist.conf" {{ skip=0; next }}
        {{ skip=0; print }}
    ' "$SSHD_MAIN" > "$stage/sshd_config"
    cp "$stage/sshd_config" "$SSHD_MAIN"
    rm -f "$SSHD_DROPIN"
    if ! "$SSHD_BIN" -t || ! reload_sshd; then
        echo "[ERROR] 恢复原 SSH 认证失败，正在回滚"
        restore_sshd_backup "$backup" || true
        rm -rf "$backup" "$stage"
        return 1
    fi
    rm -rf "$backup" "$stage"
    echo "[OK] 已恢复服务器原 SSH 认证配置（托管公钥文件保留）"
}}

if [ "$AUDIT" != "true" ] && [ "$HYBRID_MODE" = "true" ]; then
    enable_managed_public_keys || exit 1
fi

# ── 检测防火墙管理器 ──────────────────────────────────────────
USE_FIREWALLD=false
USE_IPTABLES=false

if systemctl is-active --quiet firewalld 2>/dev/null; then
    USE_FIREWALLD=true
    echo "[检测] 发现 firewalld 正在运行，使用 firewalld rich-rule 模式"
elif command -v firewall-cmd &>/dev/null && systemctl list-unit-files firewalld.service &>/dev/null; then
    # firewalld 已安装但当前关闭：先启动并设为开机自启，再用 firewalld 模式下发，
    # 避免回退到 iptables 后被随后自启的 firewalld 清空规则、造成白名单失效。
    echo "[检测] firewalld 已安装但未运行，正在启动..."
    systemctl start firewalld 2>/dev/null
    systemctl enable firewalld 2>/dev/null
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        USE_FIREWALLD=true
        # 兜底：firewalld 刚启动，立即 runtime 放行 ssh，避免 start 后到本脚本 --reload
        # 之间默认 zone 不含 ssh 而断连（reload 时会被精确白名单 rich-rule 覆盖）
        firewall-cmd --add-service=ssh 2>/dev/null || true
        echo "[OK] firewalld 已启动并设为开机自启，使用 firewalld rich-rule 模式"
    elif command -v iptables &>/dev/null; then
        USE_IPTABLES=true
        echo "[WARN] firewalld 启动失败，回退到 iptables 模式"
    else
        echo "[ERROR] firewalld 启动失败且未找到 iptables，无法部署"
        exit 1
    fi
elif command -v iptables &>/dev/null; then
    USE_IPTABLES=true
    echo "[检测] 使用 iptables 模式"
else
    echo "[ERROR] 未找到 firewalld 或 iptables，无法部署"
    exit 1
fi

# ── firewalld 模式（openEuler / CentOS 8+ / RHEL 8+ 默认）────
if [ "$USE_FIREWALLD" = "true" ]; then
    # 清理旧的白名单 rich-rule 和审计 log-rule
    while IFS= read -r old_rule; do
        [ -z "$old_rule" ] && continue
        firewall-cmd --permanent --remove-rich-rule="$old_rule" &>/dev/null || true
    done < <(firewall-cmd --list-rich-rules 2>/dev/null | grep -E "port[ =]+[\\"\\']?$SSH_PORT\\b")

    if [ "$AUDIT" = "true" ]; then
        # 审计模式：保留 ssh service 开放（不拦截），仅添加全流量日志规则
        if ! firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
            firewall-cmd --permanent --add-service=ssh
            echo "[INFO] 已开放 ssh service（审计模式不拦截）"
        fi
        # 记录所有 SSH 连接（含白名单和非白名单），用于验证识别效果
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=\\"$SSH_PORT\\" protocol=tcp log prefix=\\"SSH_AUDIT\\" level=\\"warning\\""
       # 单独记录白名单 IP（日志前缀不同，方便区分）
        for ip in "${{WHITELIST_IPS[@]}}"; do
           firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=\\"$ip\\" port port=\\"$SSH_PORT\\" protocol=tcp log prefix=\\"SSH_ALLOWED: \\" level=\\"info\\""
           echo "[+] 白名单 IP（审计）: $ip"
        done
        echo ""
        echo "[审计模式] 所有 SSH 连接均会放行，但会记录日志："
        echo "  SSH_ALLOWED: 前缀 = 白名单 IP 的连接"
        echo "  SSH_AUDIT:   前缀 = 所有 SSH 连接（非白名单的也包含在内）"
        echo "  查看日志: journalctl -k | grep 'SSH_AUDIT\\|SSH_ALLOWED'"
    else
        # 生产模式：移除默认 ssh service，改为精确白名单控制
       if firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
           firewall-cmd --permanent --remove-service=ssh
           echo "[INFO] 已移除默认 ssh service 开放"
       fi
        if [ "$HYBRID_MODE" = "true" ]; then
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=\\"$SSH_PORT\\" protocol=tcp accept"
            echo "[+] 混合模式：SSH 端口交由 sshd 按 IP 或托管公钥认证"
        else
            for ip in "${{WHITELIST_IPS[@]}}"; do
                firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=\\"$ip\\" port port=\\"$SSH_PORT\\" protocol=tcp accept"
                echo "[+] 允许 IP: $ip"
            done
        fi
    fi

    firewall-cmd --reload
    echo ""
    echo "[OK] firewalld 规则已应用"
    echo "当前 SSH 相关 rich-rule:"
    firewall-cmd --list-rich-rules | grep "$SSH_PORT" || echo "(无 rich-rule)"
    if [ "$AUDIT" != "true" ] && [ "$HYBRID_MODE" != "true" ]; then
        disable_managed_public_keys || exit 1
    fi
    echo "=== 部署完成 ==="
    exit 0
fi

# ── iptables 模式（Ubuntu / Debian / openEuler 关闭 firewalld 后）──

# openEuler/RHEL: iptables-nft 兼容层检测
if iptables --version 2>&1 | grep -qi nft; then
    echo "[INFO] 检测到 iptables-nft（nftables 兼容模式）"
fi

# 清理并重建白名单链
iptables -F "$CHAIN" 2>/dev/null || iptables -N "$CHAIN"
iptables -F "$CHAIN"

# 添加白名单 IP；混合模式由 sshd 做 OR 判断，防火墙放行到认证层
if [ "$HYBRID_MODE" = "true" ] && [ "$AUDIT" != "true" ]; then
    iptables -A "$CHAIN" -j ACCEPT
    echo "[+] 混合模式：SSH 端口交由 sshd 按 IP 或托管公钥认证"
else
    for ip in "${{WHITELIST_IPS[@]}}"; do
        iptables -A "$CHAIN" -s "$ip" -j ACCEPT
        echo "[+] 允许 IP: $ip"
    done
fi

if [ "$AUDIT" = "true" ]; then
    # 审计模式：对非白名单 IP 只记录日志，不拦截
    iptables -A "$CHAIN" -j LOG --log-prefix "SSH_BLOCKED: " --log-level 4
    iptables -A "$CHAIN" -j ACCEPT
    echo ""
    echo "[审计模式] 非白名单 IP 的 SSH 连接将被记录但不拦截"
    echo "  查看日志: journalctl -k | grep 'SSH_BLOCKED'"
    echo "  或:       grep 'SSH_BLOCKED' /var/log/messages /var/log/syslog 2>/dev/null"
else
    # 生产模式：直接拒绝
    iptables -A "$CHAIN" -j DROP
fi

# 将 INPUT 链的 SSH 流量导入白名单链
iptables -D INPUT -p tcp --dport "$SSH_PORT" -j "$CHAIN" 2>/dev/null || true
iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j "$CHAIN"

echo "[OK] iptables 规则已应用"
iptables -L "$CHAIN" -n --line-numbers

if [ "$AUDIT" != "true" ] && [ "$HYBRID_MODE" != "true" ]; then
    disable_managed_public_keys || exit 1
fi

# ── 持久化 iptables 规则 ──────────────────────────────────────
if [ "$PERSIST" = "true" ] && command -v iptables-save &>/dev/null; then
    # Ubuntu/Debian: /etc/iptables/
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        echo "[OK] 规则已保存到 /etc/iptables/rules.v4"

    # openEuler / CentOS / RHEL: /etc/sysconfig/
    elif [ -d /etc/sysconfig ]; then
        iptables-save > /etc/sysconfig/iptables
        echo "[OK] 规则已保存到 /etc/sysconfig/iptables"
        # 确保 iptables 服务开机自启
        if systemctl list-unit-files iptables.service &>/dev/null; then
            systemctl enable iptables 2>/dev/null && echo "[OK] iptables 服务已设为开机自启"
        fi

    # 兜底：rc.local
    else
        RULE_FILE="/etc/iptables.whitelist.rules"
        iptables-save > "$RULE_FILE"
        if ! grep -q "iptables-restore.*whitelist" /etc/rc.local 2>/dev/null; then
            echo "iptables-restore < $RULE_FILE" >> /etc/rc.local
            chmod +x /etc/rc.local
        fi
        echo "[OK] 规则已写入 $RULE_FILE 并配置 rc.local 自动恢复"
    fi
fi

echo "=== 部署完成 ==="
"""
    return script


def generate_audit_log_script(ssh_port: int, lines: int) -> str:
    return f"""#!/bin/bash
echo "=== SSH 审计日志（最近 {lines} 条）==="
echo "服务器: $(hostname)  时间: $(date)"
echo ""

# 从 journald 查（systemd 系统）
if command -v journalctl &>/dev/null; then
    echo "─── journalctl（内核日志）───"
    journalctl -k --no-pager -n 2000 2>/dev/null | grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED" | tail -n {lines} || echo "  (无记录)"
    echo ""
fi

# 从传统日志文件查（非 systemd 或两者都查）
for logfile in /var/log/messages /var/log/syslog /var/log/kern.log; do
    if [ -f "$logfile" ]; then
        echo "─── $logfile ───"
        tail -n 5000 "$logfile" | grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED" | tail -n {lines} || echo "  (无记录)"
        echo ""
    fi
done

echo "─── 统计摘要 ───"
ALL_LOGS=$({{ journalctl -k --no-pager -n 2000 2>/dev/null; tail -n 5000 /var/log/messages /var/log/syslog /var/log/kern.log 2>/dev/null; }} | grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED")

BLOCKED=$(echo "$ALL_LOGS" | grep "SSH_BLOCKED" | grep -oE 'SRC=[0-9.]+' | sort | uniq -c | sort -rn)
ALLOWED=$(echo "$ALL_LOGS" | grep "SSH_ALLOWED" | grep -oE 'SRC=[0-9.]+' | sort | uniq -c | sort -rn)
AUDIT=$(echo "$ALL_LOGS" | grep "SSH_AUDIT" | grep -oE 'SRC=[0-9.]+' | sort | uniq -c | sort -rn)

if [ -n "$BLOCKED" ]; then
    echo "被拦截（非白名单）IP 统计:"
    echo "$BLOCKED" | awk '{{printf "  %-8s 次  %s\\n", $1, $2}}'
    echo ""
fi
if [ -n "$ALLOWED" ]; then
    echo "白名单 IP 连接统计:"
    echo "$ALLOWED" | awk '{{printf "  %-8s 次  %s\\n", $1, $2}}'
    echo ""
fi
if [ -z "$BLOCKED" ] && [ -z "$ALLOWED" ] && [ -z "$AUDIT" ]; then
    echo "  暂无审计日志。请确认已用 --audit 模式部署，且有 SSH 连接产生。"
fi
"""


def generate_status_script(ssh_port: int) -> str:
    return f"""#!/bin/bash
echo "=== SSH 白名单状态检查 ==="
echo "服务器: $(hostname)"
echo "系统: $(. /etc/os-release 2>/dev/null && echo $NAME $VERSION_ID || uname -r)"
echo "时间: $(date)"
echo ""

SSHD_DROPIN=/etc/ssh/sshd_config.d/90-ip-login-whitelist.conf
MANAGED_KEYS=/etc/ssh/ip-login-whitelist/authorized_keys
if [ -f "$SSHD_DROPIN" ]; then
    echo "[认证模式] IP 或托管公钥"
    echo "sshd 托管策略: $SSHD_DROPIN"
    grep -E '^(Match Address|[[:space:]]*(AuthenticationMethods|AuthorizedKeysFile|PasswordAuthentication))' "$SSHD_DROPIN" || true
    echo "托管公钥文件:"
    if [ -d "$MANAGED_KEYS" ]; then
        for f in "$MANAGED_KEYS"/*; do
            [ -f "$f" ] || continue
            echo "  $(basename "$f"): $(grep -cve '^[[:space:]]*$' "$f") 把"
            command -v ssh-keygen >/dev/null && ssh-keygen -lf "$f" 2>/dev/null | sed 's/^/    /' || true
        done
    else
        echo "  (无)"
    fi
else
    echo "[认证模式] 纯 IP 白名单 / 原 SSH 认证"
fi
echo ""

if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "[模式] firewalld"
    echo "SSH 相关 rich-rule:"
    firewall-cmd --list-rich-rules 2>/dev/null | grep "{ssh_port}" || echo "  (无)"
    echo ""
    echo "开放的 service:"
    firewall-cmd --list-services 2>/dev/null | tr ' ' '\\n' | grep -i ssh || echo "  (ssh service 未开放)"
elif command -v iptables &>/dev/null; then
    echo "[模式] iptables"
    if iptables -L SSH_WHITELIST -n --line-numbers 2>/dev/null; then
        echo ""
        echo "INPUT 链 SSH 相关规则:"
        iptables -L INPUT -n --line-numbers | grep -E "(SSH_WHITELIST|{ssh_port})" || echo "  (无匹配规则)"
    else
        echo "[WARN] SSH_WHITELIST 链不存在，白名单未部署"
    fi
else
    echo "[WARN] 未找到 firewalld 或 iptables"
fi
"""


def generate_remove_script(ssh_port: int) -> str:
    return f"""#!/bin/bash
echo "=== 移除 SSH IP 白名单 ==="

SSHD_MAIN=/etc/ssh/sshd_config
SSHD_DROPIN=/etc/ssh/sshd_config.d/90-ip-login-whitelist.conf
SSHD_INCLUDE_MARKER="# ip-login-whitelist managed include"
SSHD_BIN=$(command -v sshd 2>/dev/null || true)
[ -n "$SSHD_BIN" ] || [ ! -x /usr/sbin/sshd ] || SSHD_BIN=/usr/sbin/sshd

reload_sshd() {{
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
        service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || \
        pkill -HUP -x sshd 2>/dev/null
}}

if [ -e "$SSHD_DROPIN" ] || grep -qF "$SSHD_INCLUDE_MARKER" "$SSHD_MAIN" 2>/dev/null; then
    [ -n "$SSHD_BIN" ] || {{ echo "[ERROR] 未找到 sshd，拒绝在认证未恢复时开放防火墙"; exit 1; }}
    BACKUP=$(mktemp -d /tmp/ip-login-whitelist-remove.XXXXXX) || exit 1
    cp -a "$SSHD_MAIN" "$BACKUP/sshd_config"
    [ ! -e "$SSHD_DROPIN" ] || cp -a "$SSHD_DROPIN" "$BACKUP/dropin"
    awk -v marker="$SSHD_INCLUDE_MARKER" '
        $0 == marker {{ skip=1; next }}
        skip && $0 == "Include /etc/ssh/sshd_config.d/90-ip-login-whitelist.conf" {{ skip=0; next }}
        {{ skip=0; print }}
    ' "$SSHD_MAIN" > "$BACKUP/sshd_config.new"
    cp "$BACKUP/sshd_config.new" "$SSHD_MAIN"
    rm -f "$SSHD_DROPIN"
    if ! "$SSHD_BIN" -t || ! reload_sshd; then
        cp -a "$BACKUP/sshd_config" "$SSHD_MAIN"
        [ ! -e "$BACKUP/dropin" ] || cp -a "$BACKUP/dropin" "$SSHD_DROPIN"
        "$SSHD_BIN" -t && reload_sshd || true
        rm -rf "$BACKUP"
        echo "[ERROR] 恢复原 SSH 认证失败，防火墙保持不变"
        exit 1
    fi
    rm -rf "$BACKUP"
    echo "[OK] 已恢复原 SSH 认证；托管公钥文件保留但不再生效"
fi

if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "[模式] firewalld"
    # 移除所有白名单 rich-rule
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        firewall-cmd --permanent --remove-rich-rule="$rule" && echo "[OK] 已移除: $rule"
    done < <(firewall-cmd --list-rich-rules 2>/dev/null | grep -E "port[ =]+[\\"\\']?{ssh_port}\\b")
    # 恢复默认 ssh service 开放
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload || {{ echo "[ERROR] firewall-cmd --reload 失败"; exit 1; }}
    echo "[OK] 已恢复默认 ssh 开放（所有 IP 均可登录）"
else
    echo "[模式] iptables"
    iptables -D INPUT -p tcp --dport {ssh_port} -j SSH_WHITELIST 2>/dev/null && echo "[OK] 已从 INPUT 链移除" || echo "[SKIP] 无此规则"
    iptables -F SSH_WHITELIST 2>/dev/null && echo "[OK] 已清空 SSH_WHITELIST 链" || echo "[SKIP] 链不存在"
    iptables -X SSH_WHITELIST 2>/dev/null && echo "[OK] 已删除 SSH_WHITELIST 链" || true
    # 清理持久化
    [ -f /etc/iptables/rules.v4 ] && iptables-save > /etc/iptables/rules.v4 && echo "[OK] 已更新 /etc/iptables/rules.v4"
    [ -d /etc/sysconfig ] && iptables-save > /etc/sysconfig/iptables && echo "[OK] 已更新 /etc/sysconfig/iptables"
fi
echo "=== 白名单已移除 ==="
"""


# ─── SSH 远程执行 ─────────────────────────────────────────────────────────────

def _tail_lines(text: str, n: int = 8) -> str:
    """取文本最后 n 行非空内容；远端脚本未走 stderr 时用它提取报错线索。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines[-n:])


def _friendly_ssh_error(exc) -> str:
    """把底层 SSH/socket 异常翻译成可读的中文原因（附原始信息便于排查）。"""
    msg = str(exc).strip()
    low = msg.lower()
    if "timed out" in low or isinstance(exc, TimeoutError):
        return f"连接超时（30s 内未建立 SSH 连接）：检查主机可达性 / 端口 / 防火墙 / 代理。原始：{msg or type(exc).__name__}"
    if "refused" in low:
        return f"连接被拒绝：目标 SSH 端口未开放或服务未运行。原始：{msg}"
    if "no route to host" in low or "unreachable" in low:
        return f"网络不可达：检查路由 / 代理 / 目标是否在线。原始：{msg}"
    if "getaddrinfo" in low or "name or service not known" in low or "nodename" in low:
        return f"主机名无法解析：检查 host 配置或 DNS。原始：{msg}"
    if "authentication" in low:
        return f"SSH 认证失败：密码或密钥错误。原始：{msg}"
    return msg or type(exc).__name__


def run_on_server(server: dict, script: str, dry_run: bool = False, config: dict = None, interactive: bool = True) -> bool:
    host = server["host"]
    port = server.get("port", 22)
    user = server.get("user", "root")
    key_file = server.get("key_file", "")
    password = server.get("password", "")
    name = server.get("name", host)
    proxy = _resolve_proxy(server, config or {})

    print(f"\n{'='*60}")
    print(f"目标服务器: {name} ({user}@{host}:{port})")
    if proxy:
        print(f"使用代理:   {proxy}")

    if dry_run:
        print("[DRY-RUN] 将执行以下脚本:")
        print("-" * 40)
        print(script)
        print("-" * 40)
        return True

    try:
        import paramiko
        return _run_via_paramiko(host, port, user, key_file, password, script, proxy, interactive=interactive)
    except ImportError:
        return _run_via_subprocess(host, port, user, key_file, password, script, proxy)


def _make_proxy_sock(proxy: str, host: str, port: int):
    """根据代理 URL 创建 socket，供 paramiko 使用。失败时返回 None。"""
    if not proxy:
        return None
    parsed = urlparse(proxy)
    scheme = parsed.scheme.lower()
    proxy_host = parsed.hostname
    proxy_port = parsed.port

    if scheme in ("socks5", "socks5h", "socks4", "socks4a"):
        try:
            import socks  # PySocks
            socks_type = socks.SOCKS5 if scheme.startswith("socks5") else socks.SOCKS4
            sock = socks.create_connection(
                (host, port),
                proxy_type=socks_type,
                proxy_addr=proxy_host,
                proxy_port=proxy_port,
                proxy_username=parsed.username or None,
                proxy_password=parsed.password or None,
            )
            return sock
        except ImportError:
            print("[WARN] 检测到 SOCKS 代理但未安装 PySocks，请运行: pip install PySocks")
            print("[WARN] 将尝试直连（可能超时）")
            return None
    elif scheme in ("http", "https"):
        # HTTP CONNECT 代理
        import socket
        s = socket.create_connection((proxy_host, proxy_port), timeout=30)
        connect_str = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        s.sendall(connect_str.encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        if "200" not in resp.split("\n")[0]:
            print(f"[ERROR] HTTP 代理 CONNECT 失败: {resp.splitlines()[0]}")
            s.close()
            return None
        return s
    else:
        print(f"[WARN] 不支持的代理协议: {scheme}，将直连")
        return None


def _proxy_to_nc_command(proxy: str) -> str:
    """将代理 URL 转为 nc ProxyCommand 字符串（%h %p 占位符）。"""
    if not proxy:
        return ""
    parsed = urlparse(proxy)
    scheme = parsed.scheme.lower()
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 1080
    if scheme in ("socks5", "socks5h"):
        return f"nc -X 5 -x {proxy_host}:{proxy_port} %h %p"
    elif scheme in ("socks4", "socks4a"):
        return f"nc -X 4 -x {proxy_host}:{proxy_port} %h %p"
    elif scheme in ("http", "https"):
        return f"nc -X connect -x {proxy_host}:{proxy_port} %h %p"
    return ""


def _run_via_paramiko(host, port, user, key_file, password, script, proxy="", interactive=True) -> bool:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {"hostname": host, "port": port, "username": user, "timeout": 30}

    if proxy:
        sock = _make_proxy_sock(proxy, host, port)
        if sock is not None:
            connect_kwargs["sock"] = sock

    if key_file:
        key_path = os.path.expanduser(key_file)
        if os.path.exists(key_path):
            connect_kwargs["key_filename"] = key_path
        else:
            print(f"[WARN] 密钥文件不存在: {key_path}")

    cache_key = f"{user}@{host}"
    needs_password = not key_file

    # 密码优先级：config 存储 > 内存缓存 > 交互输入（非交互模式下直接报错）
    if password:
        _password_cache[cache_key] = password  # 存入缓存，认证失败时可清除重问
    elif needs_password and cache_key not in _password_cache:
        if not interactive:
            print(f"[ERROR] {host} 未配置密码或密钥，Web 模式下无法交互输入，请通过 CLI `server add --password` 配置")
            return False
        _password_cache[cache_key] = getpass.getpass(f"  请输入 {user}@{host} 的密码: ")

    if needs_password:
        connect_kwargs["password"] = _password_cache[cache_key]

    # 覆盖 paramiko 内置的 keyboard-interactive handler（默认实现直接调用
    # getpass.getpass，会在终端弹出密码提示，完全绕过 interactive=False 判断）。
    # 用配置的密码静默回应 keyboard-interactive 挑战；若无密码则在非交互模式下
    # 直接拒绝，避免意外阻塞 Web 请求。
    _pwd_for_kbd = _password_cache.get(cache_key, "")

    def _kbd_handler(title, instructions, prompts):
        if _pwd_for_kbd:
            return [_pwd_for_kbd for _ in prompts]
        if not interactive:
            raise paramiko.AuthenticationException("keyboard-interactive: no password configured for non-interactive mode")
        answers = []
        if title:
            print(title.strip())
        if instructions:
            print(instructions.strip())
        for prompt, show_input in prompts:
            if show_input:
                answers.append(input(prompt.strip()))
            else:
                answers.append(getpass.getpass(prompt.strip()))
        return answers

    client._interactive_handler = _kbd_handler  # type: ignore[attr-defined]

    password_updated = False  # 标记是否在认证失败后重新输入了新密码

    for attempt in range(2):  # 最多重试一次（认证失败时重新输入）
        try:
            client.connect(**connect_kwargs)
            break
        except paramiko.AuthenticationException:
            if not needs_password:
                print(f"[FAIL] {host} SSH 认证失败：密钥被拒绝（检查 key_file 是否匹配目标账户）")
                return False
            print(f"[ERROR] {host} 认证失败：密码错误")
            _password_cache.pop(cache_key, None)
            if attempt == 1 or not interactive:
                print(f"[FAIL] {host} SSH 认证失败：密码错误，放弃连接")
                return False
            new_pwd = getpass.getpass(f"  请重新输入 {user}@{host} 的密码: ")
            _password_cache[cache_key] = new_pwd
            connect_kwargs["password"] = new_pwd
            _pwd_for_kbd = new_pwd
            password_updated = True
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client._interactive_handler = _kbd_handler  # type: ignore[attr-defined]
        except Exception as e:
            print(f"[FAIL] {host} 连接失败：{_friendly_ssh_error(e)}")
            return False

    # 认证成功且密码是重新输入的，回写到 config.json
    if password_updated:
        try:
            cfg = load_config()
            for s in cfg["servers"]:
                if s["host"] == host and s.get("user", "root") == user:
                    s["password"] = _password_cache[cache_key]
                    break
            save_config(cfg)
            print(f"[OK] 新密码已保存到 config.json")
        except Exception as e:
            print(f"[WARN] 密码保存失败: {e}")

    try:
        stdin, stdout, stderr = client.exec_command("bash -s")
        stdin.write(script)
        stdin.channel.shutdown_write()

        stdout.channel.settimeout(EXEC_TIMEOUT)  # 最长等待 EXEC_TIMEOUT 秒，防止脚本卡死
        try:
            output = stdout.read().decode("utf-8", errors="replace")
        except Exception:
            # 读输出超时：脚本运行超过 EXEC_TIMEOUT 仍未返回。此时不再读 stderr /
            # 等退出码（同一 channel 会再次阻塞），直接给出明确原因后返回。
            print(f"[FAIL] {host} 执行超时：远端脚本运行超过 {EXEC_TIMEOUT}s 仍未返回。"
                  f"规则可能已部分/全部生效，请用「查看状态」确认；服务器较慢可调大 EXEC_TIMEOUT。")
            return False

        try:
            err_output = stderr.read().decode("utf-8", errors="replace")
        except Exception:
            err_output = ""
        print(output)
        if err_output.strip():
            print(f"[STDERR] {err_output}")

        exit_code = stdout.channel.recv_exit_status()
        if exit_code == 0:
            print(f"[OK] {host} 执行成功")
            return True
        reason = err_output.strip() or _tail_lines(output) or "无错误输出（远端脚本未打印原因）"
        print(f"[FAIL] {host} 远端脚本失败，退出码 {exit_code}。原因：{reason}")
        return False
    except Exception as e:
        print(f"[FAIL] {host} 执行脚本异常：{_friendly_ssh_error(e)}")
        return False
    finally:
        client.close()


def _run_via_subprocess(host, port, user, key_file, password, script, proxy="") -> bool:
    import platform, tempfile

    # 有密码时用 SSH_ASKPASS 静默传递，避免 ssh 打开 /dev/tty 弹交互框；
    # 无密码时加 BatchMode=yes，遇到需要密码的服务器直接报错而非卡住。
    askpass_file = None
    env = None

    if password and not key_file:
        fd = -1
        try:
            is_win = platform.system() == "Windows"
            suffix = ".bat" if is_win else ".sh"
            fd, askpass_file = tempfile.mkstemp(suffix=suffix)
            if is_win:
                with os.fdopen(fd, "w") as f:
                    f.write("@echo off\r\necho %_SSHPWD%\r\n")
            else:
                with os.fdopen(fd, "w") as f:
                    f.write("#!/bin/sh\necho \"$_SSHPWD\"\n")
                os.chmod(askpass_file, 0o700)
            fd = -1  # fd 已被 fdopen 消费

            env = os.environ.copy()
            env["SSH_ASKPASS"] = askpass_file
            env["SSH_ASKPASS_REQUIRE"] = "force"   # OpenSSH 8.4+，不依赖 DISPLAY
            env["_SSHPWD"] = password
        except Exception as e:
            print(f"[WARN] 无法创建 SSH_ASKPASS 脚本: {e}，回退到无密码模式")
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if askpass_file and os.path.exists(askpass_file):
                os.unlink(askpass_file)
            askpass_file = None
            env = None

    cmd = ["ssh", "-p", str(port),
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=30"]
    if not env:  # 无法传递密码时启用 BatchMode，防止终端挂起等待输入
        cmd += ["-o", "BatchMode=yes"]
    if proxy:
        nc_cmd = _proxy_to_nc_command(proxy)
        if nc_cmd:
            cmd += ["-o", f"ProxyCommand={nc_cmd}"]
        else:
            print(f"[WARN] 无法将代理 {proxy} 转为 ProxyCommand，将直连")
    if key_file:
        cmd += ["-i", os.path.expanduser(key_file)]
    cmd += [f"{user}@{host}", "bash -s"]

    try:
        result = subprocess.run(
            cmd, input=script.encode(), capture_output=True, timeout=EXEC_TIMEOUT, env=env
        )
        out_text = result.stdout.decode("utf-8", errors="replace")
        err_text = result.stderr.decode("utf-8", errors="replace")
        print(out_text)
        if err_text.strip():
            print(f"[STDERR] {err_text}")

        if result.returncode == 0:
            print(f"[OK] {host} 执行成功")
            return True
        # ssh 自身的连接/认证错误（如 Connection refused、Permission denied）也走这里，
        # 其原因在 stderr 中，直接呈现给用户。
        reason = err_text.strip() or _tail_lines(out_text) or "无错误输出（远端脚本未打印原因）"
        print(f"[FAIL] {host} 远端脚本失败，退出码 {result.returncode}。原因：{reason}")
        return False
    except subprocess.TimeoutExpired:
        print(f"[FAIL] {host} 执行超时：远端脚本运行超过 {EXEC_TIMEOUT}s 仍未返回。"
              f"规则可能已部分/全部生效，请用「查看状态」确认；服务器较慢可调大 EXEC_TIMEOUT。")
        return False
    except Exception as e:
        print(f"[FAIL] {host} 执行失败：{_friendly_ssh_error(e)}")
        return False
    finally:
        if askpass_file and os.path.exists(askpass_file):
            try:
                os.unlink(askpass_file)
            except OSError:
                pass


# ─── 部署命令 ─────────────────────────────────────────────────────────────────

def get_outgoing_ip(target_host: str = None) -> str | None:
    """检测本机连接目标服务器时使用的出口 IP。优先用 socket trick，回退到公网 API。"""
    import socket
    if target_host:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_host, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass
    try:
        from urllib.request import urlopen
        return urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
    except Exception:
        pass
    return None


def ip_covered_by_whitelist(ip_str: str, whitelist: list) -> bool:
    """检查 ip_str 是否被白名单任一条目覆盖（支持 CIDR）。"""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in whitelist:
        try:
            if addr in ipaddress.ip_network(entry["ip"], strict=False):
                return True
        except ValueError:
            continue
    return False


def _public_key_from_private_file(key_file: str) -> str | None:
    """用 ssh-keygen 从本地私钥导出公钥；无法证明时返回 None。"""
    if not key_file:
        return None
    path = os.path.expanduser(key_file)
    if not os.path.isfile(path):
        return None
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", path], capture_output=True, text=True,
            timeout=10, check=False,
        )
        if result.returncode != 0:
            return None
        normalized, _ = normalize_public_key(result.stdout)
        return normalized
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def has_locked_recovery_path(server: dict, outgoing_ip: str | None,
                             global_whitelist: list, merged_public_keys: list) -> bool:
    """混合模式首次下发前，证明存在永久锁定的管理 IP 或管理密钥。"""
    permanent_locked_ips = [
        e for e in global_whitelist if e.get("locked") and not e.get("expire_at")
    ]
    if outgoing_ip and ip_covered_by_whitelist(outgoing_ip, permanent_locked_ips):
        return True
    management_key = _public_key_from_private_file(server.get("key_file", ""))
    if not management_key:
        return False
    user = server.get("user", "root")
    return any(
        e.get("linux_user") == user
        and e.get("public_key") == management_key
        and e.get("locked")
        and not e.get("expire_at")
        for e in merged_public_keys
    )


def get_target_servers(config: dict, host_filter: str = None) -> list:
    servers = config["servers"]
    if not servers:
        print("[ERROR] 服务器列表为空，请先用 `server add` 添加服务器")
        sys.exit(1)
    if host_filter:
        servers = [s for s in servers if s["host"] == host_filter or s.get("name") == host_filter]
        if not servers:
            print(f"[ERROR] 未找到服务器: {host_filter}")
            sys.exit(1)
    return servers


def cmd_deploy(args):
    config = load_config()
    whitelist = config["whitelist"]
    global_public_keys = config.get("public_key_whitelist", [])

    servers = get_target_servers(config, args.server)

    # 跳过已禁用的服务器（禁用 = 已取消白名单并排除下发）
    disabled = [s for s in servers if not s.get("enabled", True)]
    if disabled:
        names = ", ".join(s.get("name", s["host"]) for s in disabled)
        print(f"[INFO] 跳过 {len(disabled)} 台已禁用服务器: {names}")
    servers = [s for s in servers if s.get("enabled", True)]
    if not servers:
        print("[ERROR] 没有可下发的服务器（目标均已禁用）")
        sys.exit(1)

    ssh_port = args.port or config["settings"].get("ssh_port", 22)
    persist = config["settings"].get("persist_rules", True)

    # 预先计算每台服务器的合并白名单，基于合并结果做安全检查和显示
    server_merged_map = {s["host"]: get_merged_whitelist(s, whitelist) for s in servers}
    server_key_map = {s["host"]: get_merged_public_keys(s, global_public_keys) for s in servers}

    if all(not server_merged_map[s["host"]] and not server_key_map[s["host"]] for s in servers):
        print("[ERROR] 白名单为空：IP 与公钥白名单均无有效条目，手动部署将阻断所有 SSH 登录。")
        print("严格撤权仅由过期调度执行；请先添加恢复通道或有效白名单条目。")
        sys.exit(1)

    print(f"\n[安全检查] 各服务器实际下发白名单（全局 + 专属）:")
    for s in servers:
        merged = server_merged_map[s["host"]]
        label = f"{s.get('name', s['host'])} ({s['host']})"
        server_ips = {e["ip"] for e in s.get("whitelist", [])}
        print(f"  服务器: {label}  共 {len(merged)} 个 IP")
        for e in merged:
            tag = " [专属]" if e["ip"] in server_ips else ""
            print(f"    - {e['ip']}{tag}  {e.get('description', '')}")
        for e in server_key_map[s["host"]]:
            print(f"    - [公钥] {e['linux_user']} {e['fingerprint']}  {e.get('description', '')}")

    print(f"\n将部署到 {len(servers)} 台服务器:")
    for s in servers:
        print(f"  - {s.get('name','')} ({s['host']}:{s.get('port',22)})")

    # 自检：检测本机出口 IP 是否在每台目标服务器的白名单中
    first_host = servers[0]["host"] if servers else None
    my_ip = get_outgoing_ip(first_host)
    locked_out_servers = []
    audit = getattr(args, "audit", False)
    unsafe_hybrid = [
        s for s in servers
        if server_key_map[s["host"]] and not audit and not args.dry_run
        and not has_locked_recovery_path(s, my_ip, whitelist, server_key_map[s["host"]])
    ]
    if unsafe_hybrid:
        print("\n[ERROR] 以下服务器缺少永久锁定的恢复通道，拒绝启用 IP/公钥混合模式：")
        for s in unsafe_hybrid:
            print(f"  - {s.get('name', s['host'])} ({s['host']})")
        print("请锁定管理机全局 IP，或将 server.key_file 对应公钥以管理用户身份永久锁定。")
        sys.exit(1)
    if my_ip:
        for s in servers:
            if (not ip_covered_by_whitelist(my_ip, server_merged_map[s["host"]])
                    and not has_locked_recovery_path(s, my_ip, whitelist, server_key_map[s["host"]])):
                locked_out_servers.append(s)
        if locked_out_servers:
            print(f"\n{'!'*60}")
            print(f"[危险] 检测到本机出口 IP {my_ip} 不在以下服务器的白名单中：")
            for s in locked_out_servers:
                print(f"  - {s.get('name','')} ({s['host']})")
            print("  部署后你将无法通过 SSH 登录这些服务器！")
            print(f"  建议先执行：python whitelist_manager.py ip add {my_ip} --desc \"我的IP\"")
            print(f"{'!'*60}")
            if not args.yes and not args.dry_run:
                confirm = input("\n已了解风险，仍要继续部署？[y/N]: ").strip().lower()
                if confirm != "y":
                    print("已取消")
                    return
        else:
            print(f"\n[OK] 本机出口 IP {my_ip} 已在白名单中，安全")
    else:
        print("\n[WARN] 无法自动检测本机出口 IP，请手动确认自己的 IP 已加入白名单")

    if not args.yes and not args.dry_run and not locked_out_servers:
        confirm = input("\n确认部署？白名单外的 IP 将被拒绝 SSH 登录 [y/N]: ").strip().lower()
        if confirm != "y":
            print("已取消")
            return

    if audit:
        print("\n[审计模式] 所有 SSH 连接仍可正常登录，非白名单 IP 将被记录到系统日志")
        print("  验证完成后，用 deploy（不加 --audit）切换为真实拦截\n")

    success_count = 0
    for server in servers:
        merged = server_merged_map[server["host"]]
        script = generate_apply_script(
            merged, ssh_port, persist, audit=audit,
            public_keys=server_key_map[server["host"]],
        )
        if run_on_server(server, script, dry_run=args.dry_run, config=config):
            success_count += 1

    if not args.dry_run:
        print(f"\n{'='*60}")
        print(f"部署完成: {success_count}/{len(servers)} 台成功")
        if audit:
            print("  [提示] 等待一段时间后，用 `audit-log` 命令查看日志验证效果")


def cmd_status(args):
    config = load_config()
    servers = get_target_servers(config, args.server)
    ssh_port = config["settings"].get("ssh_port", 22)
    script = generate_status_script(ssh_port)
    for server in servers:
        run_on_server(server, script, config=config)


def cmd_remove(args):
    config = load_config()
    servers = get_target_servers(config, args.server)
    ssh_port = config["settings"].get("ssh_port", 22)

    print(f"\n[警告] 将从以下服务器移除 IP 白名单限制：")
    for s in servers:
        print(f"  - {s.get('name','')} ({s['host']})")

    if not args.yes:
        confirm = input("\n确认移除？[y/N]: ").strip().lower()
        if confirm != "y":
            print("已取消")
            return

    script = generate_remove_script(ssh_port)
    for server in servers:
        run_on_server(server, script, config=config)


def cmd_audit_log(args):
    config = load_config()
    servers = get_target_servers(config, args.server)
    ssh_port = config["settings"].get("ssh_port", 22)
    script = generate_audit_log_script(ssh_port, args.lines)
    for server in servers:
        run_on_server(server, script, config=config)


def cmd_settings(args):
    config = load_config()
    if args.ssh_port:
        config["settings"]["ssh_port"] = args.ssh_port
        print(f"[OK] SSH 端口已设为 {args.ssh_port}")
    if args.persist is not None:
        config["settings"]["persist_rules"] = args.persist
        print(f"[OK] 规则持久化: {'开启' if args.persist else '关闭'}")
    if args.proxy is not None:
        config["settings"]["proxy"] = args.proxy
        if args.proxy:
            print(f"[OK] 全局代理已设为 {args.proxy}")
        else:
            print("[OK] 全局代理已清除")
    save_config(config)
    print(f"\n当前设置:\n{json.dumps(config['settings'], indent=2, ensure_ascii=False)}")


# ─── CLI 入口 ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whitelist_manager",
        description="SSH IP 登录白名单管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 添加 IP 到白名单
  python whitelist_manager.py ip add 192.168.1.100 --desc "办公室"
  python whitelist_manager.py ip add 10.0.0.0/24 --desc "内网网段"

  # 管理服务器列表
  python whitelist_manager.py server add 10.0.1.1 --name "生产服务器1" --user root --key ~/.ssh/id_rsa
  python whitelist_manager.py server add 10.0.1.2 --name "生产服务器2" --user root --password mypass

  # 下发白名单到所有服务器
  python whitelist_manager.py deploy

  # 仅下发到指定服务器（用 IP 或别名）
  python whitelist_manager.py deploy --server 10.0.1.1

  # 预览将执行的脚本（不实际执行）
  python whitelist_manager.py deploy --dry-run

  # 查看服务器当前白名单状态
  python whitelist_manager.py status

  # 移除某台服务器的白名单限制
  python whitelist_manager.py remove --server 10.0.1.1
"""
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ip 子命令
    ip_parser = sub.add_parser("ip", help="管理 IP 白名单")
    ip_sub = ip_parser.add_subparsers(dest="ip_command", required=True)

    ip_add = ip_sub.add_parser("add", help="添加 IP 到白名单")
    ip_add.add_argument("ip", help="IP 地址或 CIDR（如 192.168.1.1 或 10.0.0.0/24）")
    ip_add.add_argument("--desc", "-d", help="备注说明")
    ip_add.add_argument("--expire", "-e",
                        metavar="TIME",
                        help="有效期：7d / 24h / 30m（相对）或 2025-12-31 / '2025-12-31 23:59:59'（绝对）。"
                             "不填则永久有效。")
    ip_add.add_argument("--server", "-s", help="添加到指定服务器的专属白名单（不指定则为全局）")
    ip_add.set_defaults(func=cmd_ip_add)

    ip_rm = ip_sub.add_parser("remove", help="从白名单移除 IP")
    ip_rm.add_argument("ip", help="要移除的 IP 或 CIDR")
    ip_rm.add_argument("--server", "-s", help="从指定服务器的专属白名单移除（不指定则为全局）")
    ip_rm.set_defaults(func=cmd_ip_remove)

    ip_ls = ip_sub.add_parser("list", help="查看白名单")
    ip_ls.add_argument("--server", "-s", help="查看指定服务器的专属白名单（不指定则为全局）")
    ip_ls.set_defaults(func=cmd_ip_list)

    # pubkey 子命令
    key_parser = sub.add_parser("pubkey", help="管理 SSH 公钥白名单")
    key_sub = key_parser.add_subparsers(dest="pubkey_command", required=True)

    key_add = key_sub.add_parser("add", help="添加公钥到白名单")
    key_add.add_argument("--user", required=True, help="远端 Linux 用户名")
    key_source = key_add.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--key", dest="public_key", help="OpenSSH 公钥文本")
    key_source.add_argument("--file", dest="key_file", help=".pub 公钥文件路径")
    key_add.add_argument("--desc", "-d", default="", help="备注说明")
    key_add.add_argument("--expire", "-e", help="有效期，格式同 ip add")
    key_add.add_argument("--server", "-s", help="服务器专属公钥；不指定则为全局")
    key_add.add_argument("--lock", action="store_true", help="添加后立即锁定")
    key_add.set_defaults(func=cmd_pubkey_add)

    key_ls = key_sub.add_parser("list", help="查看公钥白名单")
    key_ls.add_argument("--server", "-s", help="查看服务器专属公钥")
    key_ls.set_defaults(func=cmd_pubkey_list)

    key_rm = key_sub.add_parser("remove", help="移除公钥")
    key_rm.add_argument("id", help="公钥条目 ID")
    key_rm.add_argument("--server", "-s", help="从服务器专属公钥白名单移除")
    key_rm.set_defaults(func=cmd_pubkey_remove)

    for command in ("lock", "unlock"):
        key_lock = key_sub.add_parser(command, help=f"{command} 公钥")
        key_lock.add_argument("id", help="公钥条目 ID")
        key_lock.add_argument("--server", "-s", help="服务器专属公钥")
        key_lock.set_defaults(func=cmd_pubkey_lock)

    # server 子命令
    srv_parser = sub.add_parser("server", help="管理服务器列表")
    srv_sub = srv_parser.add_subparsers(dest="srv_command", required=True)

    srv_add = srv_sub.add_parser("add", help="添加服务器")
    srv_add.add_argument("host", help="服务器 IP 或主机名")
    srv_add.add_argument("--port", "-p", type=int, default=22, help="SSH 端口（默认 22）")
    srv_add.add_argument("--user", "-u", default="root", help="SSH 用户名（默认 root）")
    srv_add.add_argument("--key", "-k", help="SSH 私钥文件路径")
    srv_add.add_argument("--password", help="SSH 密码（建议改用密钥）")
    srv_add.add_argument("--name", "-n", help="服务器别名")
    srv_add.add_argument("--proxy", help="代理地址，如 socks5://127.0.0.1:1080 或 http://host:port")
    srv_add.set_defaults(func=cmd_server_add)

    srv_rm = srv_sub.add_parser("remove", help="移除服务器")
    srv_rm.add_argument("host", help="服务器 IP 或主机名")
    srv_rm.set_defaults(func=cmd_server_remove)

    srv_ls = srv_sub.add_parser("list", help="查看服务器列表")
    srv_ls.set_defaults(func=cmd_server_list)

    # deploy 命令
    deploy = sub.add_parser("deploy", help="将白名单下发到服务器")
    deploy.add_argument("--server", "-s", help="指定目标服务器（IP 或别名），不指定则下发全部")
    deploy.add_argument("--port", type=int, help="SSH 端口（覆盖全局设置）")
    deploy.add_argument("--dry-run", action="store_true", help="预览脚本，不实际执行")
    deploy.add_argument("--audit", action="store_true",
                        help="审计模式：记录应被拦截的 IP 到日志，但不实际拦截，用于上线前验证")
    deploy.add_argument("--yes", "-y", action="store_true", help="跳过确认提示")
    deploy.set_defaults(func=cmd_deploy)

    # status 命令
    status = sub.add_parser("status", help="查看服务器当前白名单状态")
    status.add_argument("--server", "-s", help="指定服务器")
    status.set_defaults(func=cmd_status)

    # remove 命令
    remove = sub.add_parser("remove", help="移除服务器上的 IP 白名单限制")
    remove.add_argument("--server", "-s", help="指定服务器，不指定则操作全部")
    remove.add_argument("--yes", "-y", action="store_true", help="跳过确认提示")
    remove.set_defaults(func=cmd_remove)

    # audit-log 命令
    audit_log = sub.add_parser("audit-log", help="查看审计模式下记录的被拦截 IP 日志")
    audit_log.add_argument("--server", "-s", help="指定服务器")
    audit_log.add_argument("--lines", "-n", type=int, default=50, help="显示最近 N 条记录（默认 50）")
    audit_log.set_defaults(func=cmd_audit_log)

    # settings 命令
    settings = sub.add_parser("settings", help="全局设置")
    settings.add_argument("--ssh-port", type=int, help="设置全局 SSH 端口")
    settings.add_argument("--persist", type=lambda x: x.lower() == "true",
                          metavar="true/false", help="是否持久化规则（重启后生效）")
    settings.add_argument("--proxy", metavar="URL",
                          help="全局代理，如 socks5://127.0.0.1:1080（留空字符串可清除）")
    settings.set_defaults(func=cmd_settings)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
