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

CONFIG_FILE = Path(__file__).parent / "config.json"

DEFAULT_CONFIG = {
    "whitelist": [],
    "servers": [],
    "settings": {
        "ssh_port": 22,
        "persist_rules": True
    }
}


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

def cmd_ip_add(args):
    config = load_config()
    ip = args.ip.strip()

    if not validate_ip_or_cidr(ip):
        print(f"[ERROR] 无效的 IP 或 CIDR 格式: {ip}")
        sys.exit(1)

    existing = [e["ip"] for e in config["whitelist"]]
    if ip in existing:
        print(f"[WARN] {ip} 已在白名单中，跳过")
        return

    entry = {
        "ip": ip,
        "description": args.desc or "",
        "added_by": getpass.getuser(),
        "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    config["whitelist"].append(entry)
    save_config(config)
    print(f"[OK] 已添加 {ip} 到白名单 (备注: {entry['description'] or '无'})")


def cmd_ip_remove(args):
    config = load_config()
    ip = args.ip.strip()
    before = len(config["whitelist"])
    config["whitelist"] = [e for e in config["whitelist"] if e["ip"] != ip]

    if len(config["whitelist"]) == before:
        print(f"[WARN] {ip} 不在白名单中")
        return

    save_config(config)
    print(f"[OK] 已从白名单移除 {ip}")


def cmd_ip_list(args):
    config = load_config()
    wl = config["whitelist"]
    if not wl:
        print("白名单为空")
        return

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
        "password": args.password or ""
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

    print(f"\n{'名称':<20} {'地址':<20} {'端口':<8} {'用户':<15} {'密钥文件'}")
    print("-" * 80)
    for s in servers:
        key_info = s.get('key_file') or ('(密码)' if s.get('password') else '(交互)')
        print(f"{s.get('name',''):<20} {s['host']:<20} {s.get('port',22):<8} {s.get('user','root'):<15} {key_info}")
    print(f"\n共 {len(servers)} 台服务器")


# ─── 生成远端执行脚本 ─────────────────────────────────────────────────────────

def generate_apply_script(whitelist: list, ssh_port: int, persist: bool) -> str:
    ip_list = " ".join(e["ip"] for e in whitelist)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    script = f"""#!/bin/bash
# IP 登录白名单部署脚本 - 由 whitelist_manager 自动生成
# 生成时间: {ts}

SSH_PORT={ssh_port}
WHITELIST_IPS="{ip_list}"
CHAIN="SSH_WHITELIST"
PERSIST={str(persist).lower()}

echo "=== 开始部署 SSH IP 白名单 ==="
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
    # 清理旧的白名单 rich-rule
    for old_rule in $(firewall-cmd --list-rich-rules 2>/dev/null | grep "SSH_WHITELIST\\|port port=\\"$SSH_PORT\\".*accept"); do
        firewall-cmd --permanent --remove-rich-rule="$old_rule" &>/dev/null || true
    done

    # 移除默认的 ssh service 开放（若存在），改为精确控制
    if firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
        firewall-cmd --permanent --remove-service=ssh
        echo "[INFO] 已移除默认 ssh service 开放"
    fi

    # 添加白名单 IP 的 rich-rule
    for ip in $WHITELIST_IPS; do
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=\\"$ip\\" port port=\\"$SSH_PORT\\" protocol=tcp accept"
        echo "[+] 允许 IP: $ip"
    done

    firewall-cmd --reload
    echo ""
    echo "[OK] firewalld 规则已应用"
    echo "当前 SSH 相关规则:"
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

# 拒绝其余 SSH 连接
iptables -A "$CHAIN" -j DROP

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

def run_on_server(server: dict, script: str, dry_run: bool = False) -> bool:
    host = server["host"]
    port = server.get("port", 22)
    user = server.get("user", "root")
    key_file = server.get("key_file", "")
    password = server.get("password", "")
    name = server.get("name", host)

    print(f"\n{'='*60}")
    print(f"目标服务器: {name} ({user}@{host}:{port})")

    if dry_run:
        print("[DRY-RUN] 将执行以下脚本:")
        print("-" * 40)
        print(script)
        print("-" * 40)
        return True

    try:
        import paramiko
        return _run_via_paramiko(host, port, user, key_file, password, script)
    except ImportError:
        return _run_via_subprocess(host, port, user, key_file, script)


def _run_via_paramiko(host, port, user, key_file, password, script) -> bool:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {"hostname": host, "port": port, "username": user, "timeout": 30}

    if key_file:
        key_path = os.path.expanduser(key_file)
        if os.path.exists(key_path):
            connect_kwargs["key_filename"] = key_path
        else:
            print(f"[WARN] 密钥文件不存在: {key_path}")

    if password:
        connect_kwargs["password"] = password
    elif not key_file:
        connect_kwargs["password"] = getpass.getpass(f"  请输入 {user}@{host} 的密码: ")

    try:
        client.connect(**connect_kwargs)
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
        print(f"[ERROR] 连接 {host} 失败: {e}")
        return False
    finally:
        client.close()


def _run_via_subprocess(host, port, user, key_file, script) -> bool:
    cmd = ["ssh", "-p", str(port),
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=30"]
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

    if not args.yes and not args.dry_run:
        confirm = input("\n确认部署？白名单外的 IP 将被拒绝 SSH 登录 [y/N]: ").strip().lower()
        if confirm != "y":
            print("已取消")
            return

    script = generate_apply_script(whitelist, ssh_port, persist)

    success_count = 0
    for server in servers:
        if run_on_server(server, script, dry_run=args.dry_run):
            success_count += 1

    if not args.dry_run:
        print(f"\n{'='*60}")
        print(f"部署完成: {success_count}/{len(servers)} 台成功")


def cmd_status(args):
    config = load_config()
    servers = get_target_servers(config, args.server)
    ssh_port = config["settings"].get("ssh_port", 22)
    script = generate_status_script(ssh_port)
    for server in servers:
        run_on_server(server, script)


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
        run_on_server(server, script)


def cmd_settings(args):
    config = load_config()
    if args.ssh_port:
        config["settings"]["ssh_port"] = args.ssh_port
        print(f"[OK] SSH 端口已设为 {args.ssh_port}")
    if args.persist is not None:
        config["settings"]["persist_rules"] = args.persist
        print(f"[OK] 规则持久化: {'开启' if args.persist else '关闭'}")
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
    ip_add.set_defaults(func=cmd_ip_add)

    ip_rm = ip_sub.add_parser("remove", help="从白名单移除 IP")
    ip_rm.add_argument("ip", help="要移除的 IP 或 CIDR")
    ip_rm.set_defaults(func=cmd_ip_remove)

    ip_ls = ip_sub.add_parser("list", help="查看白名单")
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

    # settings 命令
    settings = sub.add_parser("settings", help="全局设置")
    settings.add_argument("--ssh-port", type=int, help="设置全局 SSH 端口")
    settings.add_argument("--persist", type=lambda x: x.lower() == "true",
                          metavar="true/false", help="是否持久化规则（重启后生效）")
    settings.set_defaults(func=cmd_settings)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
