#!/usr/bin/env python3
"""
IP 白名单管理 Web 界面
提供 REST API + 前端页面，在浏览器中管理 SSH 登录白名单。

启动:
    pip install flask paramiko
    python web_app.py [--host 127.0.0.1] [--port 8080]
"""

import sys
import io
import json
import re
import time
import hashlib
import secrets
import threading
import datetime
import getpass
import argparse
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from pathlib import Path

try:
    from flask import Flask, jsonify, request, render_template, session, redirect, url_for
except ImportError:
    print("[ERROR] 请先安装 Flask:  pip install flask")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
from whitelist_manager import (
    load_config, save_config, validate_ip_or_cidr,
    generate_apply_script, generate_status_script,
    generate_remove_script, generate_audit_log_script,
    run_on_server, get_merged_whitelist, _find_server, _make_ip_entry,
    ip_covered_by_whitelist, get_outgoing_ip, parse_expire,
    is_entry_expired, CONFIG_FILE, CONFIG_LOCK,
)
from translations import get_translations, detect_language

app = Flask(__name__)


# ─── 登录速率限制 ─────────────────────────────────────────────────────────────

_LOGIN_RATE_LIMIT: dict = {}          # key=ip, value=[attempt_timestamps]
_LOGIN_MAX_ATTEMPTS = 10              # 每分钟最多尝试次数
_LOGIN_RATE_WINDOW = 60               # 窗口秒数


def _check_login_rate(ip: str) -> bool:
    """检查 IP 是否超过登录频率限制。返回 True 表示允许继续。"""
    now = time.time()
    attempts = _LOGIN_RATE_LIMIT.get(ip, [])
    # 清理过期记录
    attempts = [t for t in attempts if now - t < _LOGIN_RATE_WINDOW]
    _LOGIN_RATE_LIMIT[ip] = attempts
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    return True


# ─── 认证 ─────────────────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(),
                            _PBKDF2_ITERATIONS, dklen=32).hex()
    return f"pbkdf2:{_PBKDF2_ITERATIONS}:{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("sha256:"):
            # 兼容旧版 SHA-256 哈希
            parts = stored.split(":", 2)
            if len(parts) != 3:
                return False
            _, salt, old_hash = parts
            return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest() == old_hash
        if stored.startswith("pbkdf2:"):
            parts = stored.split(":", 3)
            if len(parts) != 4:
                return False
            _, iterations, salt, expected = parts
            h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(),
                                    int(iterations), dklen=32).hex()
            return h == expected
        return False
    except Exception:
        return False


def _get_auth_cfg() -> dict:
    """返回 config.json 中的 auth 配置（不存在则返回默认值）。"""
    try:
        if CONFIG_FILE.exists():
            with CONFIG_LOCK:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    raw = json.load(f)
            return raw.get("settings", {}).get("auth", {})
    except Exception:
        pass
    return {}


def _setup_app_secret():
    """从 config.json 加载或生成 Flask secret_key，并写回 config。"""
    try:
        if CONFIG_FILE.exists():
            with CONFIG_LOCK:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    raw = json.load(f)
            key = raw.get("settings", {}).get("secret_key")
            if key:
                app.secret_key = key
                return
        # 生成新密钥并写入 config
        cfg = load_config()
        new_key = secrets.token_hex(32)
        cfg["settings"]["secret_key"] = new_key
        # 若尚无 auth 配置，设置默认账户
        auth = cfg["settings"].setdefault("auth", {})
        if not auth.get("username"):
            auth["username"] = "admin"
        if not auth.get("password_hash"):
            auth["password_hash"] = _hash_password("admin")
            auth["password_changed"] = False
            print("[INFO] 已初始化默认账户: admin / admin  请登录后及时修改密码")
        save_config(cfg)
        app.secret_key = new_key
    except Exception:
        app.secret_key = secrets.token_hex(32)


_PUBLIC_PATHS: set = set()


def public_route(rule: str, **options):
    """标记路由为公开（无需登录）。用法同 @app.route，额外将路径加入公开集。"""
    _PUBLIC_PATHS.add(rule)
    return app.route(rule, **options)


# ─── 模板上下文注入 ──────────────────────────────────────────────────────────


@app.context_processor
def inject_i18n():
    """向所有模板注入当前语言和翻译字典。"""
    lang = session.get("lang", "zh")
    return {"lang": lang, "T": get_translations(lang)}


def _ensure_csrf_token():
    """确保 session 中存在 CSRF token。"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.before_request
def _require_login():
    """拦截所有未登录请求，公开路径除外。同时校验 CSRF、检测语言。"""
    # 语言检测：session 中无 lang 时从 Accept-Language 推断
    if "lang" not in session:
        session["lang"] = detect_language(request.headers.get("Accept-Language", ""))

    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        _ensure_csrf_token()
        return None
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "message": "未登录"}), 401
        return redirect(url_for("login_page"))

    # CSRF 校验：所有状态变更请求必须携带有效 token
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-CSRF-Token") or ""
        if not token or token != session.get("csrf_token", ""):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "CSRF token 无效"}), 403
            return "CSRF token 无效", 403

    return None


# ─── 认证路由 ──────────────────────────────────────────────────────────────────

@public_route("/login")
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@public_route("/guest")
def guest_page():
    return render_template("guest.html")


@public_route("/apply")
def apply_page():
    return render_template("apply.html")


@public_route("/api/servers-public")
def api_servers_public():
    """公开的服务器列表（不含认证信息），供申请页面使用。"""
    cfg = load_config(purge=False)
    # 仅暴露启用中的服务器：禁用的服务器申请了也无法下发、审核也会跳过
    servers = [{
        "host": s["host"],
        "name": s.get("name", s["host"]),
        "port": s.get("port", 22),
    } for s in cfg.get("servers", []) if s.get("enabled", True)]
    return jsonify({"success": True, "servers": servers})


@public_route("/api/login", methods=["POST"])
def api_login():
    client_ip = request.remote_addr or ""
    if not _check_login_rate(client_ip):
        return jsonify({"success": False, "message": "登录尝试过于频繁，请稍后再试"}), 429

    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    auth = _get_auth_cfg()
    expected_user = auth.get("username") or "admin"
    password_hash = auth.get("password_hash") or ""

    if username != expected_user or not _verify_password(password, password_hash):
        return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    # 重新生成 session 防止 session fixation 攻击
    session.clear()
    session["authenticated"] = True
    session["username"] = username

    # 检查是否需要强制修改默认密码
    need_change = not auth.get("password_changed", False)
    if need_change:
        session["must_change_password"] = True

    _ensure_csrf_token()
    return jsonify({"success": True, "message": "登录成功", "must_change_password": need_change})


@public_route("/api/csrf-token")
def api_csrf_token():
    _ensure_csrf_token()
    return jsonify({"success": True, "token": session["csrf_token"]})


@public_route("/api/lang", methods=["GET", "PATCH"])
def api_lang():
    """获取或切换语言。GET 返回当前语言和全部翻译；PATCH 切换语言。"""
    if request.method == "PATCH":
        data = request.json or {}
        new_lang = (data.get("lang") or "").strip()
        if new_lang in ("zh", "ru", "en"):
            session["lang"] = new_lang
            return jsonify({"success": True, "lang": new_lang})
        return jsonify({"success": False, "message": "不支持的语言"}), 400

    # GET
    lang = session.get("lang", "zh")
    return jsonify({
        "success": True,
        "lang": lang,
        "translations": get_translations(lang),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@public_route("/api/guest/replace", methods=["POST"])
def api_guest_replace():
    """Guest 自助替换 IP：原地更新旧 IP 为新 IP 并立即下发到受影响的服务器。

    隐式凭证 = 旧 IP 必须已存在于白名单。无需管理员审核，下发结果直接返回。
    """
    data = request.json or {}
    old_ip = (data.get("old_ip") or "").strip()
    new_ip = (data.get("new_ip") or "").strip()

    if not old_ip or not new_ip:
        return jsonify({"success": False, "message": "旧 IP 和新 IP 均不能为空"}), 400
    if not validate_ip_or_cidr(old_ip):
        return jsonify({"success": False, "message": f"无效的旧 IP 格式: {old_ip}"}), 400
    if not validate_ip_or_cidr(new_ip):
        return jsonify({"success": False, "message": f"无效的新 IP 格式: {new_ip}"}), 400
    if old_ip == new_ip:
        return jsonify({"success": False, "message": "新旧 IP 相同，无需替换"}), 400

    cfg = load_config()
    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    # 锁定保护：旧 IP 在全局或任一服务器中被标记为 locked 即拒绝替换，
    # 防止 guest 误将关键 IP（如网站服务器 IP）替换掉导致回连失败。
    for entry in cfg.get("whitelist", []):
        if entry["ip"] == old_ip and entry.get("locked"):
            return jsonify({"success": False, "message": f"{old_ip} 已被锁定，无法通过自助换 IP 替换"}), 403
    for srv in cfg.get("servers", []):
        for entry in srv.get("whitelist", []):
            if entry["ip"] == old_ip and entry.get("locked"):
                return jsonify({"success": False, "message": f"{old_ip} 已被锁定，无法通过自助换 IP 替换"}), 403

    # 原地更新旧 IP → 新 IP，保留 description / expire_at 等元数据（仅替换 IP 本身）。
    # added_by 标记为 guest-self-service 以便审计追溯；added_at 刷新为本次替换时间。
    found_global = False
    affected_server_hosts: list[str] = []
    original_description = ""
    original_expire_at = None

    for entry in cfg.get("whitelist", []):
        if entry["ip"] == old_ip:
            original_description = entry.get("description", "") or original_description
            original_expire_at = entry.get("expire_at") or original_expire_at
            entry["ip"] = new_ip
            entry["added_at"] = now_str
            entry["added_by"] = "guest-self-service"
            found_global = True
            break

    for srv in cfg.get("servers", []):
        for entry in srv.get("whitelist", []):
            if entry["ip"] == old_ip:
                original_description = entry.get("description", "") or original_description
                original_expire_at = entry.get("expire_at") or original_expire_at
                entry["ip"] = new_ip
                entry["added_at"] = now_str
                entry["added_by"] = "guest-self-service"
                affected_server_hosts.append(srv["host"])
                break

    if not found_global and not affected_server_hosts:
        return jsonify({"success": False, "message": f"未在白名单中找到 IP: {old_ip}"}), 404

    # 全局 IP 影响所有服务器；否则仅影响包含该 IP 的服务器；已禁用的服务器一律跳过下发
    if found_global:
        servers_to_deploy = [s for s in cfg.get("servers", []) if s.get("enabled", True)]
    else:
        servers_to_deploy = [s for s in cfg.get("servers", [])
                             if s["host"] in affected_server_hosts and s.get("enabled", True)]

    # 立即持久化白名单变更
    save_config(cfg)

    # 立即下发到受影响的服务器
    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)
    global_whitelist = cfg["whitelist"]

    def _replace_deploy_one(server):
        merged = get_merged_whitelist(server, global_whitelist)
        if not merged:
            return {
                "server": server.get("name", server["host"]),
                "host": server["host"],
                "success": False,
                "output": "[SKIP] 白名单已全空，跳过自动下发",
            }
        script = generate_apply_script(merged, ssh_port, persist)
        ok, output = capture_run(server, script, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers_to_deploy, _replace_deploy_one)
    success_count = sum(1 for r in results if r["success"])

    # 记录到独立的自助替换日志（不混入 applications，避免被审核/批量下发流程误处理）
    record_id = now.strftime("%Y%m%d%H%M%S") + "_" + secrets.token_hex(4)
    record = {
        "id": record_id,
        "old_ip": old_ip,
        "new_ip": new_ip,
        "description": original_description,
        "expire_at": original_expire_at,
        "servers": [s["host"] for s in servers_to_deploy],
        "deploy_results": [
            {"host": r["host"], "server": r["server"], "success": r["success"]}
            for r in results
        ],
        "success_count": success_count,
        "total": len(results),
        "all_success": len(results) == 0 or success_count == len(results),
        "created_at": now_str,
    }
    cfg.setdefault("self_service_log", []).append(record)
    save_config(cfg)

    deploy_log = ""
    for r in results:
        deploy_log += f"{'=' * 56}\n"
        deploy_log += f"  服务器: {r['server']} ({r['host']})  {'OK' if r['success'] else 'FAIL'}\n"
        deploy_log += f"{'-' * 56}\n"
        deploy_log += r["output"].rstrip() + "\n\n"
    deploy_log += f"下发完成: {success_count}/{len(results)} 台成功"

    total = len(results)
    # 替换本身已生效；无服务器时视为成功，否则要求全部服务器下发成功
    success = total == 0 or success_count == total
    return jsonify({
        "success": success,
        "message": (
            f"已替换 {old_ip} → {new_ip}，下发 {success_count}/{total} 台成功"
            if total > 0 else f"已替换 {old_ip} → {new_ip}（无需下发的服务器）"
        ),
        "id": record_id,
        "deploy_result": deploy_log if total > 0 else "",
    })


# ─── 自助申请白名单 ──────────────────────────────────────────────────────────

@public_route("/api/apply", methods=["POST"])
def api_apply():
    """用户自助申请加入白名单（无需登录）。"""
    data = request.json or {}
    ip = (data.get("ip") or "").strip()
    name = (data.get("name") or "").strip()
    employee_id = (data.get("employee_id") or "").strip()
    purpose = (data.get("purpose") or "").strip()
    duration = (data.get("duration") or "").strip()
    servers = data.get("servers") or []

    if not ip:
        return jsonify({"success": False, "message": "IP 不能为空"}), 400
    if not validate_ip_or_cidr(ip):
        return jsonify({"success": False, "message": f"无效的 IP 格式: {ip}"}), 400
    if not name:
        return jsonify({"success": False, "message": "姓名不能为空"}), 400
    if not employee_id:
        return jsonify({"success": False, "message": "工号不能为空"}), 400
    if not purpose:
        return jsonify({"success": False, "message": "使用目的不能为空"}), 400
    if not duration:
        return jsonify({"success": False, "message": "请选择使用时长"}), 400
    if not servers or not isinstance(servers, list):
        return jsonify({"success": False, "message": "请至少选择一台服务器"}), 400

    cfg = load_config()
    all_hosts = {s["host"] for s in cfg.get("servers", []) if s.get("enabled", True)}
    for h in servers:
        if h not in all_hosts:
            return jsonify({"success": False, "message": f"服务器不存在或已禁用: {h}"}), 400

    now = datetime.datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")

    # 解析时长：相对时长（1d/7d 等）不预计算，等审批时从审批时间起算
    # 绝对时间（datetime-local / 自定义日期）直接存入，审批时不重新计算
    expire_at = None
    if not re.match(r'^(\d+)([dhm])$', duration.lower()):
        try:
            expire_at = parse_expire(duration)
        except ValueError:
            return jsonify({"success": False, "message": f"无效的时长格式: {duration}"}), 400

    app_id = now.strftime("%Y%m%d%H%M%S") + "_" + secrets.token_hex(4)
    application = {
        "id": app_id,
        "ip": ip,
        "name": name,
        "employee_id": employee_id,
        "purpose": purpose,
        "duration": duration,
        "expire_at": expire_at,
        "servers": servers,
        "status": "pending",
        "approved_servers": [],
        "deployed": False,
        "created_at": created_at,
        "reviewed_at": None,
        "reviewed_by": None,
    }
    cfg.setdefault("applications", []).append(application)
    save_config(cfg)
    return jsonify({"success": True, "message": "申请已提交，请等待管理员审核", "id": app_id})


@app.route("/api/applications", methods=["GET"])
def api_applications_list():
    """获取所有申请列表（管理员）。"""
    cfg = load_config(purge=False)
    apps = cfg.get("applications", [])
    return jsonify({"success": True, "applications": apps})


@app.route("/api/self-service-log", methods=["GET"])
def api_self_service_log():
    """获取 Guest 自助换 IP 历史记录（最新优先）。"""
    cfg = load_config(purge=False)
    records = list(cfg.get("self_service_log", []))
    records.reverse()
    return jsonify({"success": True, "records": records})


@app.route("/api/applications/<app_id>/review", methods=["POST"])
def api_applications_review(app_id):
    """审核申请：批准（可部分）或拒绝。批准仅写入白名单，不下发。"""
    data = request.json or {}
    action = (data.get("action") or "").strip()
    approved_servers = data.get("servers") or []

    if action not in ("approve", "reject"):
        return jsonify({"success": False, "message": "操作必须为 approve 或 reject"}), 400

    cfg = load_config()
    apps = cfg.get("applications", [])
    app = next((a for a in apps if a["id"] == app_id), None)
    if not app:
        return jsonify({"success": False, "message": "申请不存在"}), 404
    if app["status"] != "pending":
        return jsonify({"success": False, "message": f"申请状态为 {app['status']}，无法重复审核"}), 409

    reviewer = session.get("username", "admin")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if action == "reject":
        app["status"] = "rejected"
        app["reviewed_at"] = now_str
        app["reviewed_by"] = reviewer
        save_config(cfg)
        return jsonify({"success": True, "message": "申请已拒绝"})

    # approve（可部分）
    if not approved_servers:
        return jsonify({"success": False, "message": "请至少选择一台服务器批准"}), 400

    valid_hosts = {s["host"] for s in cfg.get("servers", []) if s.get("enabled", True)}
    final_servers = [h for h in approved_servers if h in app["servers"] and h in valid_hosts]
    if not final_servers:
        return jsonify({"success": False, "message": "所选服务器均不在原始申请中、已禁用或已不存在"}), 400

    is_replace = app.get("type") == "replace"

    # replace 模式：删除旧 IP 前先检查锁定状态，与 Guest 自助换 IP / 全局编辑/删除接口
    # 的锁定保护保持一致，避免 locked 的关键 IP（如管理服务器自身）被绕过删除。
    if is_replace:
        old_ip = app.get("old_ip", "")
        locked_scope = None
        for entry in cfg.get("whitelist", []):
            if entry["ip"] == old_ip and entry.get("locked"):
                locked_scope = "全局"
                break
        if locked_scope is None:
            for srv in cfg.get("servers", []):
                for entry in srv.get("whitelist", []):
                    if entry["ip"] == old_ip and entry.get("locked"):
                        locked_scope = srv.get("name") or srv["host"]
                        break
                if locked_scope:
                    break
        if locked_scope:
            return jsonify({
                "success": False,
                "message": f"{old_ip} 在 [{locked_scope}] 已被锁定，无法通过替换申请审批",
            }), 403

    # 审核人可覆盖有效期
    raw_expire = data.get("expire_at")
    if raw_expire is None:
        duration = app.get("duration", "")
        expire_at = app.get("expire_at")
        m = re.match(r'^(\d+)([dhm])$', duration.lower()) if duration else None
        if m:
            n, unit = int(m.group(1)), m.group(2)
            delta = {'d': datetime.timedelta(days=n),
                     'h': datetime.timedelta(hours=n),
                     'm': datetime.timedelta(minutes=n)}[unit]
            expire_at = (datetime.datetime.now() + delta).strftime("%Y-%m-%d %H:%M:%S")
    else:
        stripped = raw_expire.strip()
        if not stripped or stripped.lower() in ('never', '永久', 'permanent'):
            expire_at = None
        else:
            try:
                expire_at = parse_expire(stripped)
            except ValueError:
                return jsonify({"success": False, "message": f"无效的有效期格式: {stripped}"}), 400

    # 构建备注：<姓名> <工号> <目的/自定义备注>
    custom_desc = data.get("description")
    name_part = f"{app.get('name', '')} {app.get('employee_id', '')}".strip()
    if custom_desc is not None and custom_desc.strip():
        description = f"{name_part} {custom_desc.strip()}".strip()
    else:
        description = f"{name_part} {app.get('purpose', '')}".strip()

    # 收集因 IP 已存在被跳过的服务器，让审核人知道审批"成功"但部分服务器未变更——
    # 此时不会覆盖原条目的 description / expire_at / added_by，避免静默改写旧申请的元数据。
    skipped_hosts: list[str] = []

    if is_replace:
        # 替换模式：移除旧 IP，添加新 IP
        old_ip = app.get("old_ip", "")
        # ① 全局白名单中移除旧 IP
        cfg["whitelist"] = [e for e in cfg.get("whitelist", []) if e["ip"] != old_ip]
        # ② 各服务器专属白名单中移除旧 IP
        for srv in cfg.get("servers", []):
            srv["whitelist"] = [e for e in srv.get("whitelist", []) if e["ip"] != old_ip]
        # ③ 添加新 IP 到批准的服务器专属白名单
        for srv in cfg["servers"]:
            if srv["host"] in final_servers:
                wl = srv.setdefault("whitelist", [])
                if any(e["ip"] == app["ip"] for e in wl):
                    skipped_hosts.append(srv.get("name") or srv["host"])
                    continue
                entry = _make_ip_entry(app["ip"], description, expire_at, added_by=reviewer)
                wl.append(entry)
    else:
        # 普通模式：添加 IP 到各服务器专属白名单
        for srv in cfg["servers"]:
            if srv["host"] in final_servers:
                wl = srv.setdefault("whitelist", [])
                if any(e["ip"] == app["ip"] for e in wl):
                    skipped_hosts.append(srv.get("name") or srv["host"])
                    continue
                entry = _make_ip_entry(app["ip"], description, expire_at, added_by=reviewer)
                wl.append(entry)

    app["status"] = "approved"
    app["approved_servers"] = final_servers
    app["deployed"] = False
    if expire_at:
        app["expire_at"] = expire_at
    app["reviewed_at"] = now_str
    app["reviewed_by"] = reviewer
    save_config(cfg)

    msg = f"已批准 {app['ip']} 替换 {app.get('old_ip', '')} ({len(final_servers)} 台服务器)" if is_replace else f"已批准 {app['ip']} 加入 {len(final_servers)} 台服务器白名单（待下发）"
    if skipped_hosts:
        msg += f"；{len(skipped_hosts)} 台因 IP 已存在未覆盖：{', '.join(skipped_hosts)}"
    return jsonify({"success": True, "message": msg})


@app.route("/api/applications/deploy", methods=["POST"])
def api_applications_deploy():
    """下发所有已批准但未部署的申请涉及的服务器。"""
    cfg = load_config()
    apps = cfg.get("applications", [])
    pending_deploy = [a for a in apps if a.get("status") == "approved" and not a.get("deployed")]

    if not pending_deploy:
        return jsonify({"success": False, "message": "没有待下发的申请"}), 400

    # 收集所有需要下发的服务器 host
    affected_hosts = set()
    for a in pending_deploy:
        for h in a.get("approved_servers", []):
            affected_hosts.add(h)

    servers_to_deploy = [s for s in cfg.get("servers", [])
                         if s["host"] in affected_hosts and s.get("enabled", True)]
    if not servers_to_deploy:
        return jsonify({"success": False, "message": "没有找到需要下发的服务器（可能均已禁用）"}), 400

    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)
    global_whitelist = cfg["whitelist"]

    def _app_deploy_one(server):
        merged = get_merged_whitelist(server, global_whitelist)
        if not merged:
            return {
                "server": server.get("name", server["host"]),
                "host": server["host"],
                "success": False,
                "output": "[SKIP] 白名单已全空，跳过自动下发",
            }
        script = generate_apply_script(merged, ssh_port, persist)
        ok, output = capture_run(server, script, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers_to_deploy, _app_deploy_one)
    success_count = sum(1 for r in results if r["success"])

    # 仅标记所有目标服务器都成功部署的申请为已部署
    succeeded_hosts = {r["host"] for r in results if r["success"]}
    for a in pending_deploy:
        app_servers = set(a.get("approved_servers", []))
        if app_servers and app_servers.issubset(succeeded_hosts):
            a["deployed"] = True
    if succeeded_hosts:
        save_config(cfg)

    deploy_log = ""
    for r in results:
        deploy_log += f"{'=' * 56}\n"
        deploy_log += f"  服务器: {r['server']} ({r['host']})  {'OK' if r['success'] else 'FAIL'}\n"
        deploy_log += f"{'-' * 56}\n"
        deploy_log += r["output"].rstrip() + "\n\n"
    deploy_log += f"下发完成: {success_count}/{len(results)} 台成功"

    return jsonify({
        "success": success_count > 0,
        "success_count": success_count,
        "total": len(results),
        "message": f"下发完成: {success_count}/{len(results)} 台成功",
        "deploy_result": deploy_log,
        "results": results,
    })


@app.route("/api/auth/password", methods=["PATCH"])
def api_change_password():
    data = request.json or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""

    if not new_pw or len(new_pw) < 6:
        return jsonify({"success": False, "message": "新密码至少 6 位"}), 400

    cfg = load_config()
    auth = cfg["settings"].setdefault("auth", {})
    stored = auth.get("password_hash") or ""

    if not _verify_password(old_pw, stored):
        return jsonify({"success": False, "message": "旧密码错误"}), 403

    auth["password_hash"] = _hash_password(new_pw)
    auth["password_changed"] = True
    session.pop("must_change_password", None)
    save_config(cfg)
    return jsonify({"success": True, "message": "密码已更新"})


# ─── 自动下发调度器 ────────────────────────────────────────────────────────────

_sched_lock = threading.Lock()
_sched: dict = {
    "enabled": False,
    "interval_minutes": 5,
    "thread": None,
    "last_run_at": None,
    "last_expired": [],    # 上次触发的过期条目摘要
    "last_results": [],    # 上次下发结果
}


def _find_affected_servers(raw_cfg: dict) -> set:
    """扫描原始 config，返回受过期条目影响的服务器 host 集合。
    全局条目过期 → 所有服务器；专属条目过期 → 该服务器。"""
    affected = set()
    all_hosts = {s["host"] for s in raw_cfg.get("servers", [])}

    for e in raw_cfg.get("whitelist", []):
        if is_entry_expired(e):
            return all_hosts          # 全局过期 → 全部受影响，直接返回

    for srv in raw_cfg.get("servers", []):
        for e in srv.get("whitelist", []):
            if is_entry_expired(e):
                affected.add(srv["host"])

    return affected


def _scheduler_run_once():
    """调度器单次执行：检查过期 → 下发受影响服务器。"""
    with _sched_lock:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _sched["last_run_at"] = now_str

        try:
            if not CONFIG_FILE.exists():
                _sched["last_expired"] = []
                _sched["last_results"] = []
                return

            # ① 读原始 config（不触发 load_config 的自动清除写盘），找出过期条目
            with CONFIG_LOCK, open(CONFIG_FILE, encoding="utf-8") as f:
                raw_cfg = json.load(f)

            # 收集过期条目摘要（用于日志展示）
            expired_summary = []
            for e in raw_cfg.get("whitelist", []):
                if is_entry_expired(e):
                    expired_summary.append(f"[全局] {e['ip']}")
            for srv in raw_cfg.get("servers", []):
                for e in srv.get("whitelist", []):
                    if is_entry_expired(e):
                        expired_summary.append(f"[{srv.get('name', srv['host'])}] {e['ip']}")

            _sched["last_expired"] = expired_summary

            if not expired_summary:
                _sched["last_results"] = []
                return

            affected_hosts = _find_affected_servers(raw_cfg)

            # ② load_config 触发清除 + 写盘
            cfg = load_config()

            # ③ 对受影响的服务器重新下发
            ssh_port = cfg["settings"].get("ssh_port", 22)
            persist = cfg["settings"].get("persist_rules", True)

            # 仅对受影响且启用的服务器下发（禁用 = 已取消白名单并排除自动下发）
            targets = [s for s in cfg["servers"]
                       if s["host"] in affected_hosts and s.get("enabled", True)]

            def _sched_deploy_one(server):
                merged = get_merged_whitelist(server, cfg["whitelist"])
                if not merged:
                    return {
                        "server": server.get("name", server["host"]),
                        "host": server["host"],
                        "success": False,
                        "output": "[SKIP] 白名单已全空，跳过自动下发（防止锁死服务器）",
                    }
                script = generate_apply_script(merged, ssh_port, persist)
                ok, output = capture_run(server, script, config=cfg)
                return {
                    "server": server.get("name", server["host"]),
                    "host": server["host"],
                    "success": ok,
                    "output": output,
                }

            _sched["last_results"] = _parallel_run(targets, _sched_deploy_one)

        except Exception as exc:
            _sched["last_expired"] = []
            _sched["last_results"] = [{"server": "—", "host": "—", "success": False,
                                        "output": f"[ERROR] 调度器异常: {exc}"}]


def _scheduler_loop():
    """后台线程主循环。"""
    while _sched["enabled"]:
        interval = max(1, _sched["interval_minutes"]) * 60
        # 分段 sleep，使 enabled=False 时能及时退出
        for _ in range(interval):
            if not _sched["enabled"]:
                return
            time.sleep(1)
        if _sched["enabled"]:
            _scheduler_run_once()


def _start_scheduler():
    """启动调度器后台线程（幂等：已启动则不重复创建）。"""
    t = _sched.get("thread")
    if t and t.is_alive():
        return
    _sched["enabled"] = True
    t = threading.Thread(target=_scheduler_loop, daemon=True, name="whitelist-scheduler")
    _sched["thread"] = t
    t.start()


def _stop_scheduler():
    """停止调度器（通过 enabled=False 让线程自然退出）。"""
    _sched["enabled"] = False
    _sched["thread"] = None


def _init_scheduler_from_config():
    """服务启动时，读取 config.json 中的 auto_deploy 设置并初始化调度器。"""
    try:
        cfg = load_config(purge=False)
        ad = cfg.get("settings", {}).get("auto_deploy", {})
        if ad.get("enabled"):
            _sched["interval_minutes"] = int(ad.get("interval_minutes", 5))
            _start_scheduler()
    except Exception:
        pass


# ─── API：调度器管理 ───────────────────────────────────────────────────────────

@app.route("/api/scheduler", methods=["GET"])
def api_scheduler_get():
    with _sched_lock:
        t = _sched.get("thread")
        result = {
            "enabled": _sched["enabled"] and bool(t and t.is_alive()),
            "interval_minutes": _sched["interval_minutes"],
            "last_run_at": _sched["last_run_at"],
            "last_expired": _sched["last_expired"],
            "last_results": _sched["last_results"],
        }
    return jsonify(result)


@app.route("/api/scheduler", methods=["PATCH"])
def api_scheduler_patch():
    data = request.json or {}
    cfg = load_config()
    ad = cfg.setdefault("settings", {}).setdefault("auto_deploy", {})

    if "enabled" in data:
        enabled = bool(data["enabled"])
        ad["enabled"] = enabled
        if enabled:
            if "interval_minutes" in data:
                mins = max(1, int(data["interval_minutes"]))
                _sched["interval_minutes"] = mins
                ad["interval_minutes"] = mins
            _start_scheduler()
        else:
            _stop_scheduler()

    if "interval_minutes" in data and not ("enabled" in data and not data["enabled"]):
        mins = max(1, int(data["interval_minutes"]))
        _sched["interval_minutes"] = mins
        ad["interval_minutes"] = mins
        # 如果已启动，重启线程使新间隔生效
        if _sched["enabled"]:
            _stop_scheduler()
            time.sleep(0.1)
            _start_scheduler()

    save_config(cfg)
    return jsonify({"success": True, "enabled": _sched["enabled"],
                    "interval_minutes": _sched["interval_minutes"]})


# ─── 工具函数 ──────────────────────────────────────────────────────────────────

# 并发下发的最大并行度：超过的服务器排队，避免压垮代理 / 本机文件描述符。
DEPLOY_MAX_CONCURRENCY = 10


class _ThreadLocalStdout:
    """线程隔离的 stdout 代理。

    run_on_server 及其下游用 print 写 sys.stdout 输出执行日志；并发下发时
    contextlib.redirect_stdout 会替换全局 sys.stdout 导致多线程互相串台。
    本代理给每个线程一个独立 buffer：set_buffer 后该线程的写入只进入自己的
    buffer，未设置的线程（含主线程日志）仍写真实 stdout。
    """

    def __init__(self, real):
        self._real = real
        self._local = threading.local()

    def _target(self):
        return getattr(self._local, "buf", None) or self._real

    def set_buffer(self, buf):
        self._local.buf = buf

    def clear_buffer(self):
        self._local.buf = None

    def write(self, s):
        return self._target().write(s)

    def flush(self):
        target = self._target()
        if hasattr(target, "flush"):
            target.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)


def _install_threadlocal_stdout():
    """幂等地把 sys.stdout 包成线程隔离代理（重复调用不会二次包装）。"""
    if not isinstance(sys.stdout, _ThreadLocalStdout):
        sys.stdout = _ThreadLocalStdout(sys.stdout)


_install_threadlocal_stdout()


def _parallel_run(servers, work_fn):
    """对每台服务器并发执行 work_fn，返回与 servers 入参同序的结果列表。"""
    if not servers:
        return []
    workers = min(len(servers), DEPLOY_MAX_CONCURRENCY)
    if workers <= 1:
        return [work_fn(s) for s in servers]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="deploy") as ex:
        return list(ex.map(work_fn, servers))   # ex.map 保持入参顺序


def capture_run(server: dict, script: str, dry_run: bool = False, config: dict = None):
    """执行脚本并捕获输出，返回 (success: bool, output: str)"""
    buf = io.StringIO()
    proxy = sys.stdout
    if isinstance(proxy, _ThreadLocalStdout):
        # 线程隔离捕获：并发下发时各线程互不串台
        proxy.set_buffer(buf)
        try:
            result = run_on_server(server, script, dry_run=dry_run, config=config, interactive=False)
        except Exception as e:
            return False, f"[ERROR] 执行出错: {e}\n{buf.getvalue()}"
        finally:
            proxy.clear_buffer()
        return result, buf.getvalue()

    # 回退：未安装代理（如 CLI / 测试）时用全局 redirect_stdout，串行安全
    try:
        with redirect_stdout(buf):
            result = run_on_server(server, script, dry_run=dry_run, config=config, interactive=False)
    except Exception as e:
        return False, f"[ERROR] 执行出错: {e}\n{buf.getvalue()}"

    return result, buf.getvalue()


# ─── 页面 ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── API：配置读取 ─────────────────────────────────────────────────────────────

@app.route("/api/config")
def api_config():
    cfg = load_config(purge=False)
    # 不暴露明文密码到前端
    servers_safe = []
    for s in cfg.get("servers", []):
        s2 = dict(s)
        s2["has_password"] = bool(s2.pop("password", ""))
        servers_safe.append(s2)
    cfg["servers"] = servers_safe
    return jsonify(cfg)


# ─── API：白名单管理 ───────────────────────────────────────────────────────────

@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_add():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    description = data.get("description", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "IP 不能为空"}), 400
    if not validate_ip_or_cidr(ip):
        return jsonify({"success": False, "message": f"无效的 IP 或 CIDR 格式: {ip}"}), 400

    expire_at = None
    raw_expire = (data.get("expire_at") or "").strip()
    if raw_expire:
        try:
            expire_at = parse_expire(raw_expire)
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400

    cfg = load_config()
    if ip in [e["ip"] for e in cfg["whitelist"]]:
        return jsonify({"success": False, "message": f"{ip} 已在白名单中"}), 409

    added_by = session.get("username", "admin")
    entry = _make_ip_entry(ip, description, expire_at, added_by=added_by)
    cfg["whitelist"].append(entry)

    # 全局已覆盖，清理各服务器专属白名单中的重复 IP；
    # 继承锁定：任一被清除的专属条目处于锁定状态时，新建的全局条目也默认锁定，
    # 避免"提升到全局"成为绕过锁定的漏洞。
    cleaned = 0
    inherited_locked = False
    for srv in cfg.get("servers", []):
        wl = srv.get("whitelist", [])
        for e in wl:
            if e["ip"] == ip and e.get("locked"):
                inherited_locked = True
                break
        before = len(wl)
        srv["whitelist"] = [e for e in wl if e["ip"] != ip]
        cleaned += before - len(srv["whitelist"])

    if inherited_locked:
        entry["locked"] = True

    save_config(cfg)
    msg = f"已添加 {ip}"
    if cleaned:
        msg += f"，已从 {cleaned} 台服务器专属白名单中移除（全局已覆盖）"
    if inherited_locked:
        msg += "；已继承原专属白名单的锁定状态"
    return jsonify({"success": True, "message": msg, "entry": entry})


@app.route("/api/whitelist/<path:ip>", methods=["DELETE"])
def api_whitelist_remove(ip):
    cfg = load_config()
    entry = next((e for e in cfg["whitelist"] if e["ip"] == ip), None)
    if entry is None:
        return jsonify({"success": False, "message": f"{ip} 不在白名单中"}), 404
    if entry.get("locked"):
        return jsonify({"success": False, "message": f"{ip} 已锁定，请先解锁再删除"}), 403

    cfg["whitelist"] = [e for e in cfg["whitelist"] if e["ip"] != ip]
    save_config(cfg)
    return jsonify({"success": True, "message": f"已移除 {ip}"})


@app.route("/api/whitelist/<path:ip>", methods=["PATCH"])
def api_whitelist_update(ip):
    """更新全局白名单条目（IP、备注、有效期）。"""
    data = request.json or {}
    cfg = load_config()

    entry = next((e for e in cfg["whitelist"] if e["ip"] == ip), None)
    if not entry:
        return jsonify({"success": False, "message": f"{ip} 不在白名单中"}), 404
    if entry.get("locked"):
        return jsonify({"success": False, "message": f"{ip} 已锁定，请先解锁再编辑"}), 403

    if "ip" in data:
        new_ip = data["ip"].strip()
        if new_ip != ip:
            if not validate_ip_or_cidr(new_ip):
                return jsonify({"success": False, "message": f"无效的 IP 或 CIDR: {new_ip}"}), 400
            if any(e["ip"] == new_ip for e in cfg["whitelist"]):
                return jsonify({"success": False, "message": f"{new_ip} 已在白名单中"}), 409
            entry["ip"] = new_ip
            # 全局已覆盖新 IP，清理各服务器专属白名单中的重复并继承锁定
            for srv in cfg.get("servers", []):
                wl = srv.get("whitelist", [])
                for e in wl:
                    if e["ip"] == new_ip and e.get("locked"):
                        entry["locked"] = True
                        break
                srv["whitelist"] = [e for e in wl if e["ip"] != new_ip]

    if "description" in data:
        entry["description"] = data["description"].strip()

    if "expire_at" in data:
        raw = (data["expire_at"] or "").strip()
        if raw:
            try:
                entry["expire_at"] = parse_expire(raw)
            except ValueError as e:
                return jsonify({"success": False, "message": str(e)}), 400
        else:
            entry.pop("expire_at", None)

    save_config(cfg)
    return jsonify({"success": True, "message": "已更新", "entry": entry})


@app.route("/api/whitelist/<path:ip>/lock", methods=["PATCH"])
def api_whitelist_lock(ip):
    """锁定/解锁全局白名单条目。锁定后该条目无法被删除、编辑或被 Guest 自助换 IP。"""
    data = request.json or {}
    if "locked" not in data:
        return jsonify({"success": False, "message": "缺少 locked 字段"}), 400
    locked = bool(data["locked"])

    cfg = load_config()
    entry = next((e for e in cfg["whitelist"] if e["ip"] == ip), None)
    if not entry:
        return jsonify({"success": False, "message": f"{ip} 不在白名单中"}), 404

    if locked:
        entry["locked"] = True
    else:
        entry.pop("locked", None)
    save_config(cfg)
    return jsonify({"success": True, "message": ("已锁定" if locked else "已解锁") + f" {ip}", "entry": entry})


# ─── API：服务器管理 ──────────────────────────────────────────────────────────

@app.route("/api/servers", methods=["POST"])
def api_server_add():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"success": False, "message": "host 不能为空"}), 400

    cfg = load_config()
    if any(s["host"] == host for s in cfg["servers"]):
        return jsonify({"success": False, "message": f"服务器 {host} 已存在"}), 409

    server = {
        "host": host,
        "port": int(data.get("port") or 22),
        "user": data.get("user") or "root",
        "key_file": data.get("key_file") or "",
        "name": data.get("name") or host,
        "password": data.get("password") or "",
        "proxy": data.get("proxy") or "",
        "whitelist": [],
        "enabled": True,
    }
    cfg["servers"].append(server)
    save_config(cfg)
    s2 = dict(server)
    s2["has_password"] = bool(s2.pop("password", ""))
    return jsonify({"success": True, "message": f"已添加服务器 {server['name']}", "server": s2})


@app.route("/api/servers/<path:host>", methods=["DELETE"])
def api_server_remove(host):
    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    # 删除前先取消该服务器的白名单（恢复默认开放），取消成功才允许删除——
    # 否则远端的 SSH 限制规则会成为无人管理的"孤儿规则"，可能把人锁在门外。
    # 已禁用的服务器其白名单此前已被取消，直接删除，避免离线服务器永远删不掉。
    if srv.get("enabled", True):
        ssh_port = cfg["settings"].get("ssh_port", 22)
        script = generate_remove_script(ssh_port)
        ok, output = capture_run(srv, script, config=cfg)
        if not ok:
            return jsonify({
                "success": False,
                "message": "删除失败：远端取消白名单未成功，服务器未被删除，请检查连通性后重试",
                "output": output,
            }), 502

    cfg["servers"] = [s for s in cfg["servers"] if s["host"] != srv["host"]]
    save_config(cfg)
    return jsonify({"success": True, "message": f"已取消白名单并移除服务器 {srv.get('name', srv['host'])}"})


@app.route("/api/servers/<path:host>", methods=["PATCH"])
def api_server_update(host):
    """更新服务器密码或代理设置。"""
    data = request.json or {}
    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    if "password" in data:
        srv["password"] = data["password"]
    if "proxy" in data:
        srv["proxy"] = data["proxy"]
    if "key_file" in data:
        srv["key_file"] = data["key_file"]

    save_config(cfg)
    return jsonify({"success": True, "message": "服务器信息已更新"})


@app.route("/api/servers/<path:host>/toggle", methods=["POST"])
def api_server_toggle(host):
    """启用/禁用服务器。

    - 禁用：先远端取消白名单（恢复默认开放），取消成功才标记为禁用；远端失败则回滚，
      保持启用状态——避免"已标记禁用但远端规则仍在拦截"的不一致状态。
    - 启用：仅恢复状态标志，不自动重新下发（下发为敏感操作，含本机 IP 锁定检查，
      交由用户在下发区手动触发）。

    禁用后该服务器会在手动下发、审核下发、Guest 换 IP、后台自动下发中被跳过。
    """
    data = request.json or {}
    if "enabled" not in data:
        return jsonify({"success": False, "message": "缺少 enabled 字段"}), 400
    enabled = bool(data["enabled"])

    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    name = srv.get("name", srv["host"])

    if enabled:
        srv["enabled"] = True
        save_config(cfg)
        return jsonify({"success": True, "enabled": True,
                        "message": f"已启用 {name}（白名单未自动下发，如需生效请手动下发）"})

    # 禁用：先远端取消白名单，成功才标记禁用（失败回滚，保持启用）
    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_remove_script(ssh_port)
    ok, output = capture_run(srv, script, config=cfg)
    if not ok:
        return jsonify({
            "success": False,
            "enabled": True,
            "message": f"禁用失败：远端取消 {name} 的白名单未成功，已保持启用状态",
            "output": output,
        }), 502
    srv["enabled"] = False
    save_config(cfg)
    return jsonify({"success": True, "enabled": False,
                    "message": f"已禁用 {name} 并取消其白名单", "output": output})


# ─── API：服务器专属白名单 ─────────────────────────────────────────────────────

@app.route("/api/servers/<path:host>/whitelist", methods=["POST"])
def api_server_whitelist_add(host):
    data = request.json or {}
    ip = data.get("ip", "").strip()
    description = data.get("description", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "IP 不能为空"}), 400
    if not validate_ip_or_cidr(ip):
        return jsonify({"success": False, "message": f"无效的 IP 或 CIDR: {ip}"}), 400

    expire_at = None
    raw_expire = (data.get("expire_at") or "").strip()
    if raw_expire:
        try:
            expire_at = parse_expire(raw_expire)
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400

    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    wl = srv.setdefault("whitelist", [])
    if any(e["ip"] == ip for e in wl):
        return jsonify({"success": False, "message": f"{ip} 已在该服务器白名单中"}), 409

    added_by = session.get("username", "admin")
    entry = _make_ip_entry(ip, description, expire_at, added_by=added_by)
    wl.append(entry)
    save_config(cfg)
    return jsonify({"success": True, "message": f"已添加 {ip}", "entry": entry})


@app.route("/api/servers/<path:host>/whitelist/<path:ip>", methods=["DELETE"])
def api_server_whitelist_remove(host, ip):
    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    wl = srv.get("whitelist", [])
    entry = next((e for e in wl if e["ip"] == ip), None)
    if entry is None:
        return jsonify({"success": False, "message": f"{ip} 不在该服务器白名单中"}), 404
    if entry.get("locked"):
        return jsonify({"success": False, "message": f"{ip} 已锁定，请先解锁再删除"}), 403

    srv["whitelist"] = [e for e in wl if e["ip"] != ip]
    save_config(cfg)
    return jsonify({"success": True, "message": f"已移除 {ip}"})


@app.route("/api/servers/<path:host>/whitelist/<path:ip>", methods=["PATCH"])
def api_server_whitelist_update(host, ip):
    """更新服务器专属白名单条目（IP、备注、有效期）。"""
    data = request.json or {}
    cfg = load_config()

    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    wl = srv.get("whitelist", [])
    entry = next((e for e in wl if e["ip"] == ip), None)
    if not entry:
        return jsonify({"success": False, "message": f"{ip} 不在该服务器白名单中"}), 404
    if entry.get("locked"):
        return jsonify({"success": False, "message": f"{ip} 已锁定，请先解锁再编辑"}), 403

    if "ip" in data:
        new_ip = data["ip"].strip()
        if new_ip != ip:
            if not validate_ip_or_cidr(new_ip):
                return jsonify({"success": False, "message": f"无效的 IP 或 CIDR: {new_ip}"}), 400
            if any(e["ip"] == new_ip for e in wl):
                return jsonify({"success": False, "message": f"{new_ip} 已在该服务器白名单中"}), 409
            entry["ip"] = new_ip

    if "description" in data:
        entry["description"] = data["description"].strip()

    if "expire_at" in data:
        raw = (data["expire_at"] or "").strip()
        if raw:
            try:
                entry["expire_at"] = parse_expire(raw)
            except ValueError as e:
                return jsonify({"success": False, "message": str(e)}), 400
        else:
            entry.pop("expire_at", None)

    save_config(cfg)
    return jsonify({"success": True, "message": f"已更新", "entry": entry})


@app.route("/api/servers/<path:host>/whitelist/<path:ip>/lock", methods=["PATCH"])
def api_server_whitelist_lock(host, ip):
    """锁定/解锁服务器专属白名单条目。"""
    data = request.json or {}
    if "locked" not in data:
        return jsonify({"success": False, "message": "缺少 locked 字段"}), 400
    locked = bool(data["locked"])

    cfg = load_config()
    srv = _find_server(cfg, host)
    if not srv:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404

    entry = next((e for e in srv.get("whitelist", []) if e["ip"] == ip), None)
    if not entry:
        return jsonify({"success": False, "message": f"{ip} 不在该服务器白名单中"}), 404

    if locked:
        entry["locked"] = True
    else:
        entry.pop("locked", None)
    save_config(cfg)
    return jsonify({"success": True, "message": ("已锁定" if locked else "已解锁") + f" {ip}", "entry": entry})


# ─── API：设置 ────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["PATCH"])
def api_settings():
    data = request.json or {}
    cfg = load_config()

    if "ssh_port" in data:
        try:
            port = int(data["ssh_port"])
            if not (1 <= port <= 65535):
                raise ValueError
            cfg["settings"]["ssh_port"] = port
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "无效的端口号（1-65535）"}), 400

    if "persist_rules" in data:
        cfg["settings"]["persist_rules"] = bool(data["persist_rules"])

    save_config(cfg)
    return jsonify({"success": True, "settings": cfg["settings"]})


# ─── API：部署安全自检 ────────────────────────────────────────────────────────

def _http_client_ip() -> str:
    """提取 HTTP 请求的真实客户端 IP（X-Forwarded-For / remote_addr），不做服务器侧的出口探测。"""
    remote_addr = request.remote_addr or ""
    trusted_proxies = {"127.0.0.1", "::1", "localhost"}
    if remote_addr in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return forwarded or remote_addr
    return remote_addr


@public_route("/api/my-ip")
def api_my_ip():
    """返回 HTTP 请求方的客户端 IP（用于 Guest/申请页自动填充）。

    与 /api/check-my-ip 的关键区别：仅返回客户端连接源 IP，不做服务器自身出口探测。
    申请场景需要的是用户挂 VPN/代理后看到的真实公网 IP，而不是 Web 服务器自身的出口 IP——
    后者在反向代理未注入 X-Forwarded-For 时会误把网站服务器 IP 当成"用户 IP"。
    """
    client_ip = _http_client_ip()
    localhost_addrs = {"", "127.0.0.1", "::1", "localhost"}
    return jsonify({"client_ip": client_ip, "is_local": client_ip in localhost_addrs})


@public_route("/api/check-my-ip")
def api_check_my_ip():
    """检测本机出口 IP 是否在目标服务器白名单中。"""
    cfg = load_config(purge=False)
    server_filter = request.args.get("server") or None
    # 跳过已禁用的服务器：它们已恢复默认开放，本机 IP 必然可达，不应算作"被锁在门外"
    servers = [s for s in cfg["servers"] if s.get("enabled", True)]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    http_client_ip = _http_client_ip()

    # 若客户端是 localhost，说明 Web 界面本地访问，需探测真实出口 IP
    localhost_addrs = {"127.0.0.1", "::1", "localhost"}
    if http_client_ip in localhost_addrs:
        first_host = servers[0]["host"] if servers else None
        real_ip = get_outgoing_ip(first_host)
        client_ip = real_ip or http_client_ip
    else:
        client_ip = http_client_ip

    locked_out = []
    for s in servers:
        merged = get_merged_whitelist(s, cfg["whitelist"])
        if not ip_covered_by_whitelist(client_ip, merged):
            locked_out.append({"host": s["host"], "name": s.get("name", s["host"])})

    return jsonify({
        "client_ip": client_ip,
        "safe": len(locked_out) == 0,
        "locked_out_servers": locked_out,
    })


# ─── API：下发白名单 ───────────────────────────────────────────────────────────

@app.route("/api/deploy", methods=["POST"])
def api_deploy():
    data = request.json or {}
    cfg = load_config()

    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空，请先用 CLI 添加服务器"}), 400

    server_filter = data.get("server") or None
    audit = bool(data.get("audit", False))
    dry_run = bool(data.get("dry_run", False))

    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]
        if not servers:
            return jsonify({"success": False, "message": f"未找到服务器: {server_filter}"}), 404

    # 跳过已禁用的服务器（禁用 = 已取消白名单并排除下发）
    servers = [s for s in servers if s.get("enabled", True)]
    if not servers:
        return jsonify({"success": False, "message": "目标服务器均已禁用，未执行下发"}), 400

    # 预先计算每台服务器的合并白名单（全局 + 专属）
    global_whitelist = cfg["whitelist"]
    server_merged_map = {s["host"]: get_merged_whitelist(s, global_whitelist) for s in servers}

    if all(not m for m in server_merged_map.values()):
        return jsonify({"success": False, "message": "白名单为空，部署会阻断所有 SSH 连接，请先添加 IP"}), 400

    # 硬拦截：管理服务器（运行本 Web 应用的主机）的本地出口 IP 必须在全局白名单中。
    # 防止误删/误改导致管理机失去对目标服务器的 SSH 访问能力——此处只接受全局白名单，
    # 不接受专属白名单（强制管理机 IP 全局可达，避免单台服务器维护时把管理机摘掉）。
    # dry_run 仅生成脚本预览，不会真正下发，跳过此检查。
    if not dry_run:
        first_host = servers[0]["host"]
        local_ip = get_outgoing_ip(first_host)
        loopback_or_unknown = {None, "", "127.0.0.1", "::1"}
        if local_ip not in loopback_or_unknown and not ip_covered_by_whitelist(local_ip, global_whitelist):
            return jsonify({
                "success": False,
                "message": (
                    f"拦截：管理服务器本地 IP {local_ip} 不在全局白名单中。"
                    f"下发后管理机将无法 SSH 到目标服务器。"
                    f"请先将该 IP 加入全局白名单（建议同时锁定）。"
                ),
                "local_ip": local_ip,
            }), 403

    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)

    def _deploy_one(server):
        merged = server_merged_map[server["host"]]
        script = generate_apply_script(merged, ssh_port, persist, audit=audit)
        ok, output = capture_run(server, script, dry_run=dry_run, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers, _deploy_one)
    success_count = sum(1 for r in results if r["success"])

    return jsonify({
        "success": success_count > 0,
        "success_count": success_count,
        "total": len(servers),
        "results": results,
    })


# ─── API：取消白名单 ──────────────────────────────────────────────────────────

@app.route("/api/remove", methods=["POST"])
def api_remove():
    data = request.json or {}
    cfg = load_config()

    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空"}), 400

    server_filter = data.get("server") or None
    dry_run = bool(data.get("dry_run", False))

    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]
        if not servers:
            return jsonify({"success": False, "message": f"未找到服务器: {server_filter}"}), 404

    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_remove_script(ssh_port)

    def _remove_one(server):
        ok, output = capture_run(server, script, dry_run=dry_run, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers, _remove_one)
    success_count = sum(1 for r in results if r["success"])

    return jsonify({
        "success": success_count > 0,
        "success_count": success_count,
        "total": len(servers),
        "results": results,
    })


# ─── API：服务器状态 ───────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    cfg = load_config(purge=False)
    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空"}), 400

    server_filter = request.args.get("server")
    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_status_script(ssh_port)

    def _status_one(server):
        ok, output = capture_run(server, script, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers, _status_one)

    return jsonify({"success": True, "results": results})


# ─── API：审计日志 ─────────────────────────────────────────────────────────────

@app.route("/api/audit-log")
def api_audit_log():
    cfg = load_config(purge=False)
    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空"}), 400

    server_filter = request.args.get("server")
    lines = int(request.args.get("lines", 50))
    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_audit_log_script(ssh_port, lines)

    def _audit_one(server):
        ok, output = capture_run(server, script, config=cfg)
        return {
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        }

    results = _parallel_run(servers, _audit_one)

    return jsonify({"success": True, "results": results})


# ─── 入口 ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP 白名单管理 Web 界面")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=6969, help="监听端口（默认 6969）")
    parser.add_argument("--debug", action="store_true", help="开启 Flask 调试模式")
    args = parser.parse_args()

    _setup_app_secret()
    _init_scheduler_from_config()

    # 加固 session cookie 安全属性
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # SESSION_COOKIE_SECURE 需要 HTTPS，默认不开启。部署在反向代理后可启用。

    if args.host in ("0.0.0.0", "::"):
        print(f"[OK] 本机访问: http://127.0.0.1:{args.port}")
        print(f"[INFO] Flask 下面会列出所有可用网卡地址（局域网 / 虚拟网卡），任选其一可用")
    else:
        print(f"[OK] 启动 Web 界面: http://{args.host}:{args.port}")
    if args.debug:
        print("[WARN] debug 模式已开启，生产环境请关闭以禁用远程代码执行调试器")
    app.run(host=args.host, port=args.port, debug=args.debug)
