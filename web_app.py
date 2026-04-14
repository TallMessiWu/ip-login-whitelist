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
import time
import threading
import datetime
import getpass
import argparse
from contextlib import redirect_stdout
from pathlib import Path

try:
    from flask import Flask, jsonify, request, render_template
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

    entry = _make_ip_entry(ip, description, expire_at)
    cfg["whitelist"].append(entry)
    save_config(cfg)
    return jsonify({"success": True, "message": f"已添加 {ip}", "entry": entry})


@app.route("/api/whitelist/<path:ip>", methods=["DELETE"])
def api_whitelist_remove(ip):
    cfg = load_config()
    before = len(cfg["whitelist"])
    cfg["whitelist"] = [e for e in cfg["whitelist"] if e["ip"] != ip]

    if len(cfg["whitelist"]) == before:
        return jsonify({"success": False, "message": f"{ip} 不在白名单中"}), 404

    save_config(cfg)
    return jsonify({"success": True, "message": f"已移除 {ip}"})


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

    entry = _make_ip_entry(ip, description, expire_at)
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

    _init_scheduler_from_config()

    url = f"http://{args.host}:{args.port}"
    print(f"[OK] 启动 Web 界面: {url}")
    app.run(host=args.host, port=args.port, debug=args.debug)
