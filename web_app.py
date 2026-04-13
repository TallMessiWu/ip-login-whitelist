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
    run_on_server,
)

app = Flask(__name__)


# ─── 工具函数 ──────────────────────────────────────────────────────────────────

def capture_run(server: dict, script: str, dry_run: bool = False):
    """执行脚本并捕获输出，返回 (success: bool, output: str)"""
    if not dry_run and not server.get("key_file") and not server.get("password"):
        name = server.get("name", server["host"])
        return False, f"[ERROR] 服务器 {name} 未配置认证（需要 key_file 或 password）\n"

    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            result = run_on_server(server, script, dry_run=dry_run)
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

    cfg = load_config()
    if ip in [e["ip"] for e in cfg["whitelist"]]:
        return jsonify({"success": False, "message": f"{ip} 已在白名单中"}), 409

    entry = {
        "ip": ip,
        "description": description,
        "added_by": getpass.getuser(),
        "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
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


# ─── API：下发白名单 ───────────────────────────────────────────────────────────

@app.route("/api/deploy", methods=["POST"])
def api_deploy():
    data = request.json or {}
    cfg = load_config()

    if not cfg["whitelist"]:
        return jsonify({"success": False, "message": "白名单为空，部署会阻断所有 SSH 连接，请先添加 IP"}), 400
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

    ssh_port = cfg["settings"].get("ssh_port", 22)
    persist = cfg["settings"].get("persist_rules", True)
    script = generate_apply_script(cfg["whitelist"], ssh_port, persist, audit=audit)

    results = []
    success_count = 0
    for server in servers:
        ok, output = capture_run(server, script, dry_run=dry_run)
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
        ok, output = capture_run(server, script)
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
        ok, output = capture_run(server, script)
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
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8080, help="监听端口（默认 8080）")
    parser.add_argument("--debug", action="store_true", help="开启 Flask 调试模式")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(f"[OK] 启动 Web 界面: {url}")
    app.run(host=args.host, port=args.port, debug=args.debug)
