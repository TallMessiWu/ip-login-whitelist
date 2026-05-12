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
    is_entry_expired, CONFIG_FILE,
)

app = Flask(__name__)


# ─── 认证 ─────────────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split(":", 2)
        if len(parts) != 3 or parts[0] != "sha256":
            return False
        _, salt, _ = parts
        return _hash_password(password, salt) == stored
    except Exception:
        return False


def _get_auth_cfg() -> dict:
    """返回 config.json 中的 auth 配置（不存在则返回默认值）。"""
    try:
        if CONFIG_FILE.exists():
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
            print("[INFO] 已初始化默认账户: admin / admin  请登录后及时修改密码")
        save_config(cfg)
        app.secret_key = new_key
    except Exception:
        app.secret_key = secrets.token_hex(32)


def _ensure_csrf_token():
    """确保 session 中存在 CSRF token。"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.before_request
def _require_login():
    """拦截所有未登录请求，公开路径除外。同时校验 CSRF。"""
    public = {"/login", "/api/login", "/guest", "/api/guest/replace", "/apply", "/api/apply",
              "/api/check-my-ip", "/api/servers-public", "/api/csrf-token"}
    if request.path in public or request.path.startswith("/static/"):
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

@app.route("/login")
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/guest")
def guest_page():
    return render_template("guest.html")


@app.route("/apply")
def apply_page():
    return render_template("apply.html")


@app.route("/api/servers-public")
def api_servers_public():
    """公开的服务器列表（不含认证信息），供申请页面使用。"""
    cfg = load_config()
    servers = [{
        "host": s["host"],
        "name": s.get("name", s["host"]),
        "port": s.get("port", 22),
    } for s in cfg.get("servers", [])]
    return jsonify({"success": True, "servers": servers})


@app.route("/api/login", methods=["POST"])
def api_login():
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
    _ensure_csrf_token()
    return jsonify({"success": True, "message": "登录成功"})


@app.route("/api/csrf-token")
def api_csrf_token():
    _ensure_csrf_token()
    return jsonify({"success": True, "token": session["csrf_token"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/guest/replace", methods=["POST"])
def api_guest_replace():
    """Guest 自助替换 IP：提交替换申请，需管理员审核后执行。"""
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

    # 搜索旧 IP 所在位置，构建影响的服务器列表
    affected_servers = []
    found_global = False

    for entry in cfg.get("whitelist", []):
        if entry["ip"] == old_ip:
            found_global = True
            break

    for srv in cfg.get("servers", []):
        for entry in srv.get("whitelist", []):
            if entry["ip"] == old_ip:
                affected_servers.append(srv["host"])
                break

    if not found_global and not affected_servers:
        return jsonify({"success": False, "message": f"未在白名单中找到 IP: {old_ip}"}), 404

    if found_global:
        affected_servers = [s["host"] for s in cfg.get("servers", [])]

    now = datetime.datetime.now()
    app_id = now.strftime("%Y%m%d%H%M%S") + "_" + secrets.token_hex(4)
    application = {
        "id": app_id,
        "type": "replace",
        "ip": new_ip,
        "old_ip": old_ip,
        "name": "Guest",
        "employee_id": "",
        "purpose": f"自助替换: {old_ip} → {new_ip}",
        "duration": "",
        "expire_at": None,
        "servers": affected_servers,
        "status": "pending",
        "approved_servers": [],
        "deployed": False,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "reviewed_at": None,
        "reviewed_by": None,
    }
    cfg.setdefault("applications", []).append(application)
    save_config(cfg)
    return jsonify({
        "success": True,
        "message": "替换申请已提交，请等待管理员审核",
        "id": app_id,
    })


# ─── 自助申请白名单 ──────────────────────────────────────────────────────────

@app.route("/api/apply", methods=["POST"])
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
    all_hosts = {s["host"] for s in cfg.get("servers", [])}
    for h in servers:
        if h not in all_hosts:
            return jsonify({"success": False, "message": f"服务器不存在: {h}"}), 400

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
    cfg = load_config()
    apps = cfg.get("applications", [])
    return jsonify({"success": True, "applications": apps})


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

    valid_hosts = {s["host"] for s in cfg.get("servers", [])}
    final_servers = [h for h in approved_servers if h in app["servers"] and h in valid_hosts]
    if not final_servers:
        return jsonify({"success": False, "message": "所选服务器均不在原始申请中或服务器已不存在"}), 400

    is_replace = app.get("type") == "replace"

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

    # 构建备注：<姓名> <工号> <目的>
    description = f"{app.get('name', '')} {app.get('employee_id', '')} {app.get('purpose', '')}".strip()

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
                if not any(e["ip"] == app["ip"] for e in wl):
                    entry = _make_ip_entry(app["ip"], description, expire_at, added_by=reviewer)
                    wl.append(entry)
    else:
        # 普通模式：添加 IP 到各服务器专属白名单
        for srv in cfg["servers"]:
            if srv["host"] in final_servers:
                wl = srv.setdefault("whitelist", [])
                if not any(e["ip"] == app["ip"] for e in wl):
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

    servers_to_deploy = [s for s in cfg.get("servers", []) if s["host"] in affected_hosts]
    if not servers_to_deploy:
        return jsonify({"success": False, "message": "没有找到需要下发的服务器"}), 400

    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)
    global_whitelist = cfg["whitelist"]

    results = []
    success_count = 0
    for server in servers_to_deploy:
        merged = get_merged_whitelist(server, global_whitelist)
        if not merged:
            results.append({
                "server": server.get("name", server["host"]),
                "host": server["host"],
                "success": False,
                "output": "[SKIP] 白名单已全空，跳过自动下发",
            })
            continue

        buf = io.StringIO()
        try:
            script = generate_apply_script(merged, ssh_port, persist)
            with redirect_stdout(buf):
                ok = run_on_server(server, script, config=cfg, interactive=False)
        except Exception as exc:
            ok = False
            buf.write(f"[ERROR] {exc}\n")

        if ok:
            success_count += 1
        results.append({
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": buf.getvalue(),
        })

    # 部署成功后标记所有相关申请为已部署
    if success_count > 0:
        for a in pending_deploy:
            a["deployed"] = True
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
            with open(CONFIG_FILE, encoding="utf-8") as f:
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
            results = []

            for server in cfg["servers"]:
                if server["host"] not in affected_hosts:
                    continue
                merged = get_merged_whitelist(server, cfg["whitelist"])
                if not merged:
                    results.append({
                        "server": server.get("name", server["host"]),
                        "host": server["host"],
                        "success": False,
                        "output": "[SKIP] 白名单已全空，跳过自动下发（防止锁死服务器）",
                    })
                    continue

                buf = io.StringIO()
                try:
                    script = generate_apply_script(merged, ssh_port, persist)
                    with redirect_stdout(buf):
                        ok = run_on_server(server, script, config=cfg, interactive=False)
                except Exception as exc:
                    ok = False
                    buf.write(f"[ERROR] {exc}\n")

                results.append({
                    "server": server.get("name", server["host"]),
                    "host": server["host"],
                    "success": ok,
                    "output": buf.getvalue(),
                })

            _sched["last_results"] = results

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
        cfg = load_config()
        ad = cfg.get("settings", {}).get("auto_deploy", {})
        if ad.get("enabled"):
            _sched["interval_minutes"] = int(ad.get("interval_minutes", 5))
            _start_scheduler()
    except Exception:
        pass


# ─── API：调度器管理 ───────────────────────────────────────────────────────────

@app.route("/api/scheduler", methods=["GET"])
def api_scheduler_get():
    t = _sched.get("thread")
    return jsonify({
        "enabled": _sched["enabled"] and bool(t and t.is_alive()),
        "interval_minutes": _sched["interval_minutes"],
        "last_run_at": _sched["last_run_at"],
        "last_expired": _sched["last_expired"],
        "last_results": _sched["last_results"],
    })


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

def capture_run(server: dict, script: str, dry_run: bool = False, config: dict = None):
    """执行脚本并捕获输出，返回 (success: bool, output: str)"""
    buf = io.StringIO()
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
    cfg = load_config()
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

    # 全局已覆盖，清理各服务器专属白名单中的重复 IP
    cleaned = 0
    for srv in cfg.get("servers", []):
        wl = srv.get("whitelist", [])
        before = len(wl)
        srv["whitelist"] = [e for e in wl if e["ip"] != ip]
        cleaned += before - len(srv["whitelist"])

    save_config(cfg)
    msg = f"已添加 {ip}"
    if cleaned:
        msg += f"，已从 {cleaned} 台服务器专属白名单中移除（全局已覆盖）"
    return jsonify({"success": True, "message": msg, "entry": entry})


@app.route("/api/whitelist/<path:ip>", methods=["DELETE"])
def api_whitelist_remove(ip):
    cfg = load_config()
    before = len(cfg["whitelist"])
    cfg["whitelist"] = [e for e in cfg["whitelist"] if e["ip"] != ip]

    if len(cfg["whitelist"]) == before:
        return jsonify({"success": False, "message": f"{ip} 不在白名单中"}), 404

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

    if "ip" in data:
        new_ip = data["ip"].strip()
        if new_ip != ip:
            if not validate_ip_or_cidr(new_ip):
                return jsonify({"success": False, "message": f"无效的 IP 或 CIDR: {new_ip}"}), 400
            if any(e["ip"] == new_ip for e in cfg["whitelist"]):
                return jsonify({"success": False, "message": f"{new_ip} 已在白名单中"}), 409
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
    }
    cfg["servers"].append(server)
    save_config(cfg)
    s2 = dict(server)
    s2["has_password"] = bool(s2.pop("password", ""))
    return jsonify({"success": True, "message": f"已添加服务器 {server['name']}", "server": s2})


@app.route("/api/servers/<path:host>", methods=["DELETE"])
def api_server_remove(host):
    cfg = load_config()
    before = len(cfg["servers"])
    cfg["servers"] = [s for s in cfg["servers"] if s["host"] != host]
    if len(cfg["servers"]) == before:
        return jsonify({"success": False, "message": f"服务器 {host} 不存在"}), 404
    save_config(cfg)
    return jsonify({"success": True, "message": f"已移除服务器 {host}"})


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

    before = len(srv.get("whitelist", []))
    srv["whitelist"] = [e for e in srv.get("whitelist", []) if e["ip"] != ip]
    if len(srv["whitelist"]) == before:
        return jsonify({"success": False, "message": f"{ip} 不在该服务器白名单中"}), 404

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

@app.route("/api/check-my-ip")
def api_check_my_ip():
    """检测本机出口 IP 是否在目标服务器白名单中。"""
    cfg = load_config()
    server_filter = request.args.get("server") or None
    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    # 优先取 X-Forwarded-For（反代场景），否则取 remote_addr
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    http_client_ip = forwarded or request.remote_addr or ""

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

    # 预先计算每台服务器的合并白名单（全局 + 专属）
    global_whitelist = cfg["whitelist"]
    server_merged_map = {id(s): get_merged_whitelist(s, global_whitelist) for s in servers}

    if all(not m for m in server_merged_map.values()):
        return jsonify({"success": False, "message": "白名单为空，部署会阻断所有 SSH 连接，请先添加 IP"}), 400

    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)

    results = []
    success_count = 0
    for server in servers:
        merged = server_merged_map[id(server)]
        script = generate_apply_script(merged, ssh_port, persist, audit=audit)
        ok, output = capture_run(server, script, dry_run=dry_run, config=cfg)
        if ok:
            success_count += 1
        results.append({
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        })

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

    results = []
    success_count = 0
    for server in servers:
        ok, output = capture_run(server, script, dry_run=dry_run, config=cfg)
        if ok:
            success_count += 1
        results.append({
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        })

    return jsonify({
        "success": success_count > 0,
        "success_count": success_count,
        "total": len(servers),
        "results": results,
    })


# ─── API：服务器状态 ───────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    cfg = load_config()
    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空"}), 400

    server_filter = request.args.get("server")
    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_status_script(ssh_port)

    results = []
    for server in servers:
        ok, output = capture_run(server, script, config=cfg)
        results.append({
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        })

    return jsonify({"success": True, "results": results})


# ─── API：审计日志 ─────────────────────────────────────────────────────────────

@app.route("/api/audit-log")
def api_audit_log():
    cfg = load_config()
    if not cfg["servers"]:
        return jsonify({"success": False, "message": "服务器列表为空"}), 400

    server_filter = request.args.get("server")
    lines = int(request.args.get("lines", 50))
    servers = cfg["servers"]
    if server_filter:
        servers = [s for s in servers if s["host"] == server_filter or s.get("name") == server_filter]

    ssh_port = cfg["settings"].get("ssh_port", 22)
    script = generate_audit_log_script(ssh_port, lines)

    results = []
    for server in servers:
        ok, output = capture_run(server, script, config=cfg)
        results.append({
            "server": server.get("name", server["host"]),
            "host": server["host"],
            "success": ok,
            "output": output,
        })

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

    url = f"http://{args.host}:{args.port}"
    print(f"[OK] 启动 Web 界面: {url}")
    app.run(host=args.host, port=args.port, debug=args.debug)
