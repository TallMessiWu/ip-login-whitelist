#!/usr/bin/env python3
"""
IP Login Whitelist Manager
通过 iptables 管理服务器 SSH 登录 IP 白名单，支持批量下发生效。
"""

import json
import os
import sys
import argparse
import datetime
import subprocess
import ipaddress
import getpass
from pathlib import Path
from urllib.parse import urlparse

CONFIG_FILE = Path(__file__).parent / "config.json"

# 进程内密码缓存，key = "user@host"，避免同一次运行反复提示
_password_cache: dict = {}

DEFAULT_CONFIG = {
    "whitelist": [],
    "servers": [],
    "settings": {
        "ssh_port": 22,
        "persist_rules": True,
        "proxy": ""
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

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(config: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"[OK] 配置已保存到 {CONFIG_FILE}")


def validate_ip_or_cidr(ip_str: str) -> bool:
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


# ─── IP 白名单管理 ────────────────────────────────────────────────────────────

def _find_server(config: dict, host_or_name: str) -> dict | None:
    """按 host 或 name 查找服务器，找不到返回 None。"""
    for s in config["servers"]:
        if s["host"] == host_or_name or s.get("name") == host_or_name:
            return s
    return None


def _make_ip_entry(ip: str, desc: str) -> dict:
    return {
        "ip": ip,
        "description": desc or "",
        "added_by": getpass.getuser(),
        "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_merged_whitelist(server: dict, global_whitelist: list) -> list:
    """合并全局白名单与服务器专属白名单（去重）。"""
    seen = set()
    merged = []
    for entry in global_whitelist + server.get("whitelist", []):
        if entry["ip"] not in seen:
            seen.add(entry["ip"])
            merged.append(entry)
    return merged


def cmd_ip_add(args):
    config = load_config()
    ip = args.ip.strip()

    if not validate_ip_or_cidr(ip):
        print(f"[ERROR] 无效的 IP 或 CIDR 格式: {ip}")
        sys.exit(1)

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
        wl.append(_make_ip_entry(ip, args.desc))
        save_config(config)
        print(f"[OK] 已添加 {ip} 到 {srv['name']} 的专属白名单")
    else:
        # 添加到全局白名单
        if any(e["ip"] == ip for e in config["whitelist"]):
            print(f"[WARN] {ip} 已在全局白名单中，跳过")
            return
        config["whitelist"].append(_make_ip_entry(ip, args.desc))
        save_config(config)
        print(f"[OK] 已添加 {ip} 到全局白名单")


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
    print(f"\n{'IP/CIDR':<20} {'备注':<20} {'添加人':<15} {'添加时间'}")
    print("-" * 75)
    for e in wl:
        print(f"{e['ip']:<20} {e.get('description',''):<20} {e.get('added_by',''):<15} {e.get('added_at','')}")
    print(f"\n共 {len(wl)} 条记录")


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
        "port": args.port or 22,
        "user": args.user or "root",
        "key_file": args.key or "",
        "name": args.name or host,
        "password": args.password or "",
        "proxy": args.proxy or "",
        "whitelist": []
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

    print(f"\n{'名称':<20} {'地址':<20} {'端口':<8} {'用户':<15} {'密钥文件':<20} {'代理'}")
    print("-" * 100)
    for s in servers:
        key_info = s.get('key_file') or ('(密码)' if s.get('password') else '(交互)')
        proxy_info = s.get('proxy') or '-'
        print(f"{s.get('name',''):<20} {s['host']:<20} {s.get('port',22):<8} {s.get('user','root'):<15} {key_info:<20} {proxy_info}")
    print(f"\n共 {len(servers)} 台服务器")


# ─── 生成远端执行脚本 ─────────────────────────────────────────────────────────

def generate_apply_script(whitelist: list, ssh_port: int, persist: bool, audit: bool = False) -> str:
    ip_list = " ".join(e["ip"] for e in whitelist)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label = "审计模式（只记录，不拦截）" if audit else "生产模式（真实拦截）"

    script = f"""#!/bin/bash
# IP 登录白名单部署脚本 - 由 whitelist_manager 自动生成
# 生成时间: {ts}
# 运行模式: {mode_label}

SSH_PORT={ssh_port}
WHITELIST_IPS="{ip_list}"
CHAIN="SSH_WHITELIST"
PERSIST={str(persist).lower()}
AUDIT={str(audit).lower()}

echo "=== 开始部署 SSH IP 白名单 [{mode_label}] ==="
echo "服务器: $(hostname)  系统: $(. /etc/os-release 2>/dev/null && echo $NAME $VERSION_ID || uname -r)"
echo "SSH 端口: $SSH_PORT"
echo "白名单 IP: $WHITELIST_IPS"
echo ""

# ── 检测防火墙管理器 ──────────────────────────────────────────
USE_FIREWALLD=false
USE_IPTABLES=false

if systemctl is-active --quiet firewalld 2>/dev/null; then
    USE_FIREWALLD=true
    echo "[检测] 发现 firewalld 正在运行，使用 firewalld rich-rule 模式"
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
    done < <(firewall-cmd --list-rich-rules 2>/dev/null | grep "port=\\"$SSH_PORT\\"")

    if [ "$AUDIT" = "true" ]; then
        # 审计模式：保留 ssh service 开放（不拦截），仅添加全流量日志规则
        if ! firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
            firewall-cmd --permanent --add-service=ssh
            echo "[INFO] 已开放 ssh service（审计模式不拦截）"
        fi
        # 记录所有 SSH 连接（含白名单和非白名单），用于验证识别效果
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=\\"$SSH_PORT\\" protocol=tcp log prefix=\\"SSH_AUDIT: \\" level=\\"warning\\""
        # 单独记录白名单 IP（日志前缀不同，方便区分）
        for ip in $WHITELIST_IPS; do
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
        for ip in $WHITELIST_IPS; do
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=\\"$ip\\" port port=\\"$SSH_PORT\\" protocol=tcp accept"
            echo "[+] 允许 IP: $ip"
        done
    fi

    firewall-cmd --reload
    echo ""
    echo "[OK] firewalld 规则已应用"
    echo "当前 SSH 相关 rich-rule:"
    firewall-cmd --list-rich-rules | grep "$SSH_PORT" || echo "(无 rich-rule)"
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

# 添加白名单 IP
for ip in $WHITELIST_IPS; do
    iptables -A "$CHAIN" -s "$ip" -j ACCEPT
    echo "[+] 允许 IP: $ip"
done

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
    journalctl -k --no-pager -n 500 2>/dev/null | grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED" | tail -n {lines} || echo "  (无记录)"
    echo ""
fi

# 从传统日志文件查（非 systemd 或两者都查）
for logfile in /var/log/messages /var/log/syslog /var/log/kern.log; do
    if [ -f "$logfile" ]; then
        echo "─── $logfile ───"
        grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED" "$logfile" 2>/dev/null | tail -n {lines} || echo "  (无记录)"
        echo ""
    fi
done

echo "─── 统计摘要 ───"
ALL_LOGS=$({{ journalctl -k --no-pager -n 5000 2>/dev/null; cat /var/log/messages /var/log/syslog /var/log/kern.log 2>/dev/null; }} | grep -E "SSH_BLOCKED|SSH_AUDIT|SSH_ALLOWED")

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

if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "[模式] firewalld"
    # 移除所有白名单 rich-rule
    for rule in $(firewall-cmd --list-rich-rules 2>/dev/null | grep "port=\\"{ssh_port}\\""); do
        firewall-cmd --permanent --remove-rich-rule="$rule" && echo "[OK] 已移除: $rule"
    done
    # 恢复默认 ssh service 开放
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
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
        return _run_via_subprocess(host, port, user, key_file, script, proxy)


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

    password_updated = False  # 标记是否在认证失败后重新输入了新密码

    for attempt in range(2):  # 最多重试一次（认证失败时重新输入）
        try:
            client.connect(**connect_kwargs)
            break
        except paramiko.AuthenticationException:
            print(f"[ERROR] {host} 认证失败，密码错误")
            if not needs_password:
                return False
            _password_cache.pop(cache_key, None)
            if attempt == 1 or not interactive:
                print(f"[ERROR] {host} 认证仍然失败，放弃连接")
                return False
            new_pwd = getpass.getpass(f"  请重新输入 {user}@{host} 的密码: ")
            _password_cache[cache_key] = new_pwd
            connect_kwargs["password"] = new_pwd
            password_updated = True
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as e:
            print(f"[ERROR] 连接 {host} 失败: {e}")
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
        stdin, stdout, stderr = client.exec_command("bash -s", get_pty=True)
        stdin.write(script)
        stdin.channel.shutdown_write()

        output = stdout.read().decode("utf-8", errors="replace")
        err_output = stderr.read().decode("utf-8", errors="replace")
        print(output)
        if err_output.strip():
            print(f"[STDERR] {err_output}")

        exit_code = stdout.channel.recv_exit_status()
        if exit_code == 0:
            print(f"[OK] {host} 执行成功")
            return True
        else:
            print(f"[ERROR] {host} 执行失败，退出码: {exit_code}")
            return False
    except Exception as e:
        print(f"[ERROR] {host} 执行脚本失败: {e}")
        return False
    finally:
        client.close()


def _run_via_subprocess(host, port, user, key_file, script, proxy="") -> bool:
    cmd = ["ssh", "-p", str(port),
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=30"]
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
        result = subprocess.run(cmd, input=script.encode(), capture_output=True, timeout=60)
        print(result.stdout.decode("utf-8", errors="replace"))
        if result.stderr.strip():
            print(f"[STDERR] {result.stderr.decode('utf-8', errors='replace')}")

        if result.returncode == 0:
            print(f"[OK] {host} 执行成功")
            return True
        else:
            print(f"[ERROR] {host} 执行失败，退出码: {result.returncode}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[ERROR] 连接 {host} 超时")
        return False
    except Exception as e:
        print(f"[ERROR] 执行失败: {e}")
        return False


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

    if not whitelist:
        print("[ERROR] 白名单为空！部署后将阻断所有 SSH 连接，请先用 `ip add` 添加允许的 IP。")
        sys.exit(1)

    servers = get_target_servers(config, args.server)
    ssh_port = args.port or config["settings"].get("ssh_port", 22)
    persist = config["settings"].get("persist_rules", True)

    print(f"\n[安全检查] 当前白名单共 {len(whitelist)} 个 IP:")
    for e in whitelist:
        print(f"  - {e['ip']}  {e.get('description','')}")

    print(f"\n将部署到 {len(servers)} 台服务器:")
    for s in servers:
        print(f"  - {s.get('name','')} ({s['host']}:{s.get('port',22)})")

    # 自检：检测本机出口 IP 是否在每台目标服务器的白名单中
    first_host = servers[0]["host"] if servers else None
    my_ip = get_outgoing_ip(first_host)
    locked_out_servers = []
    if my_ip:
        for s in servers:
            merged = get_merged_whitelist(s, whitelist)
            if not ip_covered_by_whitelist(my_ip, merged):
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

    audit = getattr(args, "audit", False)
    if audit:
        print("\n[审计模式] 所有 SSH 连接仍可正常登录，非白名单 IP 将被记录到系统日志")
        print("  验证完成后，用 deploy（不加 --audit）切换为真实拦截\n")

    success_count = 0
    for server in servers:
        merged = get_merged_whitelist(server, whitelist)
        script = generate_apply_script(merged, ssh_port, persist, audit=audit)
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
    ip_add.add_argument("--server", "-s", help="添加到指定服务器的专属白名单（不指定则为全局）")
    ip_add.set_defaults(func=cmd_ip_add)

    ip_rm = ip_sub.add_parser("remove", help="从白名单移除 IP")
    ip_rm.add_argument("ip", help="要移除的 IP 或 CIDR")
    ip_rm.add_argument("--server", "-s", help="从指定服务器的专属白名单移除（不指定则为全局）")
    ip_rm.set_defaults(func=cmd_ip_remove)

    ip_ls = ip_sub.add_parser("list", help="查看白名单")
    ip_ls.add_argument("--server", "-s", help="查看指定服务器的专属白名单（不指定则为全局）")
    ip_ls.set_defaults(func=cmd_ip_list)

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
