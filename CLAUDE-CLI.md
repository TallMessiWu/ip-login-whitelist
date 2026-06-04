# CLI & 核心库参考

> 从 [CLAUDE.md](CLAUDE.md) 拆出。当需要定位 CLI 命令或核心函数的精确代码位置时按需读取。

## 一、CLI 参数树（`build_parser()` L1097）

```
whitelist_manager
├── ip
│   ├── add <ip> [--desc] [--expire] [--server]
│   ├── remove <ip> [--server]
│   └── list [--server]
├── server
│   ├── add <host> [--port] [--user] [--key] [--password] [--name] [--proxy]
│   ├── remove <host>
│   └── list
├── deploy [--server] [--port] [--dry-run] [--audit] [--yes]
├── status [--server]
├── remove [--server] [--yes]
├── audit-log [--server] [--lines]
└── settings [--ssh-port] [--persist] [--proxy]
```

## 二、CLI 子命令处理

### IP 白名单

| 功能 | 入口函数 | 行号 |
|---|---|---|
| 添加 IP（有效期/备注/服务器专属） | `cmd_ip_add()` | L190 |
| 移除 IP | `cmd_ip_remove()` | L242 |
| 查看白名单 | `cmd_ip_list()` | L268 |
| 格式校验 | `validate_ip_or_cidr()` | L74 |

### 服务器管理

| 功能 | 入口函数 | 行号 |
|---|---|---|
| 添加服务器 | `cmd_server_add()` | L303 |
| 移除服务器 | `cmd_server_remove()` | L327 |
| 查看列表 | `cmd_server_list()` | L341 |
| 按 host/名称查找 | `_find_server()` | L159 |

添加服务器时默认 `enabled: true`。`cmd_server_list()` 显示每台服务器的启用/禁用状态。

### 下发与运维

| 功能 | 入口函数 | 行号 |
|---|---|---|
| 下发白名单（审计/dry-run/自检） | `cmd_deploy()` | L959 |
| 查看规则状态 | `cmd_status()` | L1039 |
| 撤销白名单 | `cmd_remove()` | L1048 |
| 审计日志统计 | `cmd_audit_log()` | L1068 |
| 全局设置 | `cmd_settings()` | L1077 |

`cmd_deploy()` 自动跳过 `enabled=false` 的服务器并打印提示。

### 部署安全自检

| 函数 | 行号 | 说明 |
|---|---|---|
| `get_outgoing_ip()` | L911 | 探测本机出口 IP（socket UDP → ipify API 回退） |
| `ip_covered_by_whitelist()` | L931 | 检查 IP 是否被白名单 CIDR 覆盖 |

## 三、远端脚本生成

| 函数 | 行号 |
|---|---|
| `generate_apply_script()` | L359 |
| `generate_audit_log_script()` | L513 |
| `generate_status_script()` | L558 |
| `generate_remove_script()` | L588 |

`generate_apply_script` 额外处理 firewalld 已安装但未运行：先 `systemctl start/enable` + runtime 兜底放行 ssh，失败才回退 iptables。`generate_remove_script` 的 `firewall-cmd --reload` 失败时 exit 1，确保取消失败不被误判成功。

## 四、SSH 执行层

| 函数 | 行号 | 说明 |
|---|---|---|
| `run_on_server()` | L617 | 统一入口，自动选 paramiko/subprocess |
| `_run_via_paramiko()` | L705 | paramiko 通道（代理/密码缓存/认证重试/kbd-interactive 覆盖） |
| `_run_via_subprocess()` | L834 | subprocess 降级（SSH_ASKPASS 静默传密码/BatchMode） |
| `_make_proxy_sock()` | L645 | 代理 Socket（PySocks SOCKS / HTTP CONNECT） |
| `_proxy_to_nc_command()` | L688 | 代理 URL → nc ProxyCommand（subprocess 用） |
| `_resolve_proxy()` | L38 | 代理优先级：per-server > 全局 > 环境变量 |

密码处理要点：
- paramiko：覆盖 `client._interactive_handler` 防止弹终端密码框；认证失败清除缓存重试一次，成功后回写 config
- subprocess：密码通过 `SSH_ASKPASS` 环境变量 + 临时脚本静默传递；无密码时启用 `BatchMode=yes` 防止挂起

## 五、时效管理

| 函数 | 行号 |
|---|---|
| `parse_expire()` | L87 |
| `is_entry_expired()` | L124 |
| `purge_expired_entries()` | L135 |

支持：`7d`/`24h`/`30m`（相对）、`2025-12-31`/`2025-12-31 23:59:59`（绝对）、留空/`never`/`永久`（永久）。

## 六、全局 + 专属白名单

| 函数 | 行号 |
|---|---|
| `get_merged_whitelist()` | L179 |
| `_make_ip_entry()` | L167 |

合并逻辑：全局 + 专属去重，过期条目排除。`cmd_ip_add()` L227-233 添加全局 IP 时自动清除专属白名单重复项。

## 七、配置管理

| 函数 | 行号 |
|---|---|
| `load_config()` | L53 |
| `save_config()` | L68 |
| `DEFAULT_CONFIG` | L24 |

`load_config()` 每次调用时自动执行 `purge_expired_entries()`，有过期条目则静默写盘并打印 INFO。
