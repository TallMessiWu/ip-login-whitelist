# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目用途

通过 SSH 将 `iptables` 或 `firewalld` 规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。解决密码/免密泄露后无法撤权的问题。

## 运行方式

```bash
pip install paramiko          # 唯一外部依赖，用于 SSH 连接
python whitelist_manager.py --help
```

无 `paramiko` 时自动降级为系统 `ssh` 命令（`subprocess`）。

## 常用命令

```bash
# IP 白名单管理
python whitelist_manager.py ip add <IP或CIDR> --desc "备注"
python whitelist_manager.py ip remove <IP>
python whitelist_manager.py ip list

# 服务器管理
python whitelist_manager.py server add <host> --name <别名> --user root --key ~/.ssh/id_rsa
python whitelist_manager.py server remove <host>
python whitelist_manager.py server list

# 下发与运维
python whitelist_manager.py deploy [--server <host>] [--dry-run] [-y]
python whitelist_manager.py status [--server <host>]
python whitelist_manager.py remove [--server <host>] [-y]   # 撤销限制

# 全局设置
python whitelist_manager.py settings --ssh-port 2222 --persist true/false
```

## 代码架构

单文件 `whitelist_manager.py`，分为五层：

1. **配置层**（`load_config` / `save_config`）：读写 `config.json`，存储白名单 IP、服务器列表、全局设置。首次运行时从 `DEFAULT_CONFIG` 初始化。

2. **子命令处理层**（`cmd_ip_*` / `cmd_server_*` / `cmd_deploy` / `cmd_status` / `cmd_remove` / `cmd_settings`）：每个函数对应一个 CLI 子命令，通过 `argparse` 路由。

3. **脚本生成层**（`generate_apply_script` / `generate_status_script` / `generate_remove_script`）：返回在远端服务器执行的 bash 脚本字符串。脚本内含自适应逻辑，无需修改 Python 侧代码即可适配不同 OS。

4. **SSH 执行层**（`run_on_server` → `_run_via_paramiko` / `_run_via_subprocess`）：将生成的脚本通过 SSH 传输并执行，优先用 paramiko，无法导入时降级 subprocess。

5. **CLI 入口**（`build_parser` / `main`）：argparse 两级子命令树（`ip/server` 各自有三级子命令）。

## 远端脚本适配逻辑

`generate_apply_script` 生成的脚本在远端自动检测防火墙管理器：

- **firewalld 运行中**（openEuler / CentOS 8+ / RHEL 8+ 默认）→ 使用 `firewall-cmd --permanent --add-rich-rule` 模式，`--reload` 后生效，持久化天然由 `--permanent` 保证。
- **仅有 iptables**（Ubuntu / Debian / 关闭 firewalld 的 openEuler）→ 创建 `SSH_WHITELIST` 链并挂入 `INPUT`。持久化路径按 OS 自动选择：`/etc/iptables/rules.v4`（Debian 系）、`/etc/sysconfig/iptables` + `systemctl enable iptables`（RHEL/openEuler 系）、`rc.local`（兜底）。

## 配置文件结构

`config.json`（运行时自动创建，不要提交到版本库）：

```json
{
  "whitelist": [
    {"ip": "192.168.1.0/24", "description": "", "added_by": "", "added_at": ""}
  ],
  "servers": [
    {"host": "", "port": 22, "user": "root", "key_file": "", "name": "", "password": ""}
  ],
  "settings": {
    "ssh_port": 22,
    "persist_rules": true
  }
}
```

`password` 字段明文存储，生产环境应优先使用 `key_file`。

## 代码提交
代码提交时必须使用gitmoji_commit这个skill。
