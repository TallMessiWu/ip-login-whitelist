# CLI & 核心库参考

> 从 [CLAUDE.md](CLAUDE.md) 拆出。当需要定位 CLI 命令或核心函数的精确代码位置时按需读取。

## 一、CLI 参数树（`build_parser()` L1097）

```
whitelist_manager
├── ip
│   ├── add <ip> [--desc] [--expire] [--server]
│   ├── remove <ip> [--server]
│   └── list [--server]
├── pubkey
│   ├── add --user <user> (--key <text> | --file <file>) [--desc] [--expire] [--server] [--lock]
│   ├── remove <id> [--server]
│   ├── list [--server]
│   ├── lock <id>
│   └── unlock <id>
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

### SSH 公钥白名单

| 功能 | 入口函数 |
|---|---|
| 解析、规范化、指纹和稳定 ID | `normalize_public_key()` / `_make_public_key_entry()` |
| 添加 / 列表 / 删除 | `cmd_pubkey_add()` / `cmd_pubkey_list()` / `cmd_pubkey_remove()` |
| 锁定 / 解锁 | `cmd_pubkey_lock()` / `cmd_pubkey_unlock()` |
| 合并全局与服务器专属公钥 | `get_merged_public_keys()` |
| 检查永久锁定恢复通道 | `has_locked_recovery_path()` |

公钥只保存规范化后的 `type base64`，按“Linux 用户 + 密钥 blob”去重。全局添加会清除服务器专属重复项并继承锁定状态；过期条目不会进入合并结果。

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

`generate_apply_script` 同时生成防火墙和 OpenSSH 策略：存在公钥时写入 `/etc/ssh/ip-login-whitelist/authorized_keys/%u` 和独立 drop-in，用 `Match Address` 实现 IP 命中保留原认证、非命中只允许托管公钥；仅有 IP 时使用纯防火墙模式；两类授权都为空时严格拒绝 SSH。主配置 Include、drop-in 和托管目录均按事务方式备份/替换，经 `sshd -t`、`sshd -T -C` 验证并 reload 成功后才调整防火墙，失败自动回滚。审计模式不改动公钥认证策略。

`generate_apply_script` 仍处理 firewalld 已安装但未运行：先 `systemctl start/enable` + runtime 兜底放行 ssh，失败才回退 iptables。`generate_remove_script` 会先移除工具 sshd 策略、恢复原认证，再开放防火墙；托管公钥文件保留但不再生效。

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

超时：SSH 连接超时 30s（paramiko `timeout` / subprocess `ConnectTimeout` / 代理 socket）；脚本执行+读输出超时由模块常量 `EXEC_TIMEOUT=120` 统一控制（paramiko `stdout.channel.settimeout` 与 subprocess `subprocess.run(timeout=...)` 共用），给慢服务器留足余量。

失败原因呈现：所有失败分支统一打印 `[FAIL] <host> …：<原因>`（连接/认证/执行超时/退出码非 0），原因可读且会进入 `capture_run` 捕获的输出供 Web 展示。`_friendly_ssh_error()` 把底层 socket/paramiko 异常翻译成中文（连接被拒绝/超时/网络不可达/主机名无法解析/认证失败，附原始信息）；退出码非 0 时用远端 stderr（无则 `_tail_lines()` 取输出末尾几行）作为原因；执行超时明确标注「执行超时（>EXEC_TIMEOUT）」并提示用「查看状态」确认规则是否已生效（区别于连接超时）。

## 五、时效管理

| 函数 | 行号 |
|---|---|
| `parse_expire()` | L87 |
| `is_entry_expired()` | L124 |
| `purge_expired_entries()` | L135 |

支持：`7d`/`24h`/`30m`（相对）、`2025-12-31`/`2025-12-31 23:59:59`（绝对）、留空/`never`/`永久`（永久）。IP 与公钥使用同一过期语义；调度器清理最后一条授权后也会下发全空拒绝策略。

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
