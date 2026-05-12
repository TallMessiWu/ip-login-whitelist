# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目用途

通过 SSH 将 `iptables` 或 `firewalld` 规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。解决密码/免密泄露后无法撤权的问题。

同时提供 Web 管理界面（Flask），支持浏览器端管理白名单、服务器、下发规则、审计日志、自助申请与审批。

## 运行方式

```bash
uv pip install paramiko flask        # 依赖安装（用 uv 管理）
python whitelist_manager.py --help    # CLI 模式
python web_app.py [--host 0.0.0.0] [--port 6969]  # Web 模式
```

## 文件说明

| 文件 | 用途 |
|---|---|
| `whitelist_manager.py` | CLI 全部功能 + Web 后端依赖的核心函数库，单文件 ~1220 行 |
| `web_app.py` | Flask Web 应用，REST API + 页面路由 + 后台调度器 |
| `templates/index.html` | Web 管理主界面（白名单、服务器、下发、设置、审核、调度器） |
| `templates/login.html` | Web 登录页 |
| `templates/guest.html` | Guest 自助换 IP 页面（无需登录） |
| `templates/apply.html` | 自助申请白名单页面（无需登录） |
| `requirements.txt` | 仅 `flask>=3.0.0`（paramiko 可选依赖） |
| `config.json` | 运行时自动创建，存储白名单、服务器、认证等（已 .gitignore） |

## 环境管理

代码的运行和环境与依赖的维护都必须使用 uv 工具。

## 代码提交

代码提交时必须使用 gitmoji-commit 这个 skill。

---

## 功能清单与代码路径

### 一、CLI 命令（`whitelist_manager.py`）

#### IP 白名单管理

| 功能 | CLI 命令 | 入口函数 | 行号 |
|---|---|---|---|
| 添加 IP（含有效期、备注） | `ip add` | `cmd_ip_add()` | L190 |
| 移除 IP | `ip remove` | `cmd_ip_remove()` | L242 |
| 查看白名单 | `ip list` | `cmd_ip_list()` | L268 |
| IP/CIDR 格式校验 | — | `validate_ip_or_cidr()` | L74 |

#### 服务器管理

| 功能 | CLI 命令 | 入口函数 | 行号 |
|---|---|---|---|
| 添加服务器（host/key/password/proxy） | `server add` | `cmd_server_add()` | L303 |
| 移除服务器 | `server remove` | `cmd_server_remove()` | L327 |
| 查看服务器列表 | `server list` | `cmd_server_list()` | L341 |
| 按 host 或名称查找服务器 | — | `_find_server()` | L159 |

#### 下发与运维

| 功能 | CLI 命令 | 入口函数 | 行号 |
|---|---|---|---|
| 下发白名单（含审计模式、dry-run） | `deploy` | `cmd_deploy()` | L959 |
| 查看服务器规则状态 | `status` | `cmd_status()` | L1039 |
| 撤销白名单限制 | `remove` | `cmd_remove()` | L1048 |
| 查看审计日志统计 | `audit-log` | `cmd_audit_log()` | L1068 |
| 全局设置（端口/持久化/代理） | `settings` | `cmd_settings()` | L1077 |

#### 部署前安全自检

- `get_outgoing_ip()`（L911）：探测本机出口 IP（先 socket UDP trick，回退 ipify API）
- `ip_covered_by_whitelist()`（L931）：检查 IP 是否被白名单 CIDR 覆盖
- `cmd_deploy()` 中部署前自动检测本机 IP 是否在白名单中，不在则警告并确认

### 二、远端脚本生成（`whitelist_manager.py`）

| 功能 | 函数 | 行号 |
|---|---|---|
| 生成部署脚本（iptables + firewalld 自适应） | `generate_apply_script()` | L359 |
| 生成审计日志查看脚本 | `generate_audit_log_script()` | L513 |
| 生成状态检查脚本 | `generate_status_script()` | L558 |
| 生成撤销白名单脚本 | `generate_remove_script()` | L588 |

脚本在远端自动检测防火墙管理器：
- **firewalld 运行中**（openEuler / CentOS 8+ / RHEL 8+）→ `firewall-cmd --permanent --add-rich-rule`
- **仅有 iptables**（Ubuntu / Debian / 关闭 firewalld 的系统）→ 创建 `SSH_WHITELIST` 链挂入 `INPUT`

### 三、SSH 执行层（`whitelist_manager.py`）

| 功能 | 函数 | 行号 |
|---|---|---|
| 统一入口（自动选择 paramiko 或 subprocess） | `run_on_server()` | L617 |
| paramiko 通道（含代理、密码缓存、认证重试） | `_run_via_paramiko()` | L705 |
| subprocess 降级通道（SSH_ASKPASS 静默传密码） | `_run_via_subprocess()` | L834 |
| 代理 Socket 创建（socks/http） | `_make_proxy_sock()` | L645 |
| 代理 URL → nc ProxyCommand | `_proxy_to_nc_command()` | L688 |
| 代理优先级解析（per-server > 全局 > 环境变量） | `_resolve_proxy()` | L38 |

### 四、时效管理（`whitelist_manager.py`）

| 功能 | 函数 | 行号 |
|---|---|---|
| 解析过期时间（相对/绝对/永久） | `parse_expire()` | L87 |
| 判断条目是否过期 | `is_entry_expired()` | L124 |
| 加载配置时自动清除过期条目 | `purge_expired_entries()` | L135 |

支持格式：`7d` / `24h` / `30m`（相对）、`2025-12-31` / `2025-12-31 23:59:59`（绝对）、留空/`never`/`永久`（永久）。

### 五、全局白名单 + 服务器专属白名单（`whitelist_manager.py`）

| 功能 | 函数 | 行号 |
|---|---|---|
| 合并全局白名单与服务器专属白名单（去重+过滤过期） | `get_merged_whitelist()` | L179 |
| 添加全局白名单时自动清除专属白名单重复 IP | — | `cmd_ip_add()` L227-233 |
| 创建带元数据的白名单条目 | `_make_ip_entry()` | L167 |

合并逻辑：全局 + 专属去重，且已过期条目不进入合并结果。`deploy` 和 Web 下发均基于合并结果。

### 六、配置文件管理（`whitelist_manager.py`）

| 功能 | 函数 | 行号 |
|---|---|---|
| 加载配置（含自动清除过期条目） | `load_config()` | L53 |
| 保存配置 | `save_config()` | L68 |
| 默认配置结构 | `DEFAULT_CONFIG` | L24 |

### 七、Web 后端（`web_app.py`）

#### 认证系统（L42-114）

| 功能 | 路由/函数 | 行号 |
|---|---|---|
| 密码哈希（SHA-256 + salt） | `_hash_password()` | L47 |
| 密码验证 | `_verify_password()` | L54 |
| 首次启动自动创建 admin/admin 默认账户 | `_setup_app_secret()` | L77 |
| 登录拦截中间件（公开路径白名单） | `_require_login()` | L104 |
| 登录页 | `/login` → `login_page()` | L119 |
| 登录 API | `/api/login` → `api_login()` | L148 |
| 登出 API | `/api/logout` → `api_logout()` | L166 |
| 修改密码 API | `/api/auth/password` → `api_change_password()` | L516 |

公开路径（无需登录）：`/login`、`/guest`、`/apply` 及其 API。

#### Guest 自助换 IP（L172-270）

| 功能 | 路由 | 行号 |
|---|---|---|
| Guest 页面 | `/guest` → `guest_page()` | L126 |
| 替换 IP 并自动下发 | `/api/guest/replace` → `api_guest_replace()` | L172 |

#### 自助申请白名单（L274-513）

| 功能 | 路由 | 行号 |
|---|---|---|
| 申请页面 | `/apply` → `apply_page()` | L131 |
| 提交申请 | `/api/apply` → `api_apply()` | L274 |
| 查看申请列表（管理员） | `/api/applications` → `api_applications_list()` | L340 |
| 审核申请（批准/拒绝，可部分服务器批准） | `/api/applications/<id>/review` → `api_applications_review()` | L348 |
| 下发已批准申请 | `/api/applications/deploy` → `api_applications_deploy()` | L437 |
| 公开服务器列表（供申请页用） | `/api/servers-public` → `api_servers_public()` | L136 |

审核流程：用户提交申请 → 管理员审核 → 批准后写入服务器专属白名单 → 手动或通过调度器下发到远端。

#### 白名单管理 API（L772-862）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加全局 IP | `POST /api/whitelist` | L774 |
| 删除全局 IP | `DELETE /api/whitelist/<ip>` | L815 |
| 编辑全局 IP（IP/备注/有效期） | `PATCH /api/whitelist/<ip>` | L828 |

添加全局 IP 时自动清除各服务器专属白名单中的重复项。

#### 服务器管理 API（L864-922）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加服务器 | `POST /api/servers` | L866 |
| 删除服务器 | `DELETE /api/servers/<host>` | L894 |
| 更新服务器（密码/代理/密钥） | `PATCH /api/servers/<host>` | L905 |

#### 服务器专属白名单 API（L925-1015）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加专属 IP | `POST /api/servers/<host>/whitelist` | L927 |
| 删除专属 IP | `DELETE /api/servers/<host>/whitelist/<ip>` | L961 |
| 编辑专属 IP | `PATCH /api/servers/<host>/whitelist/<ip>` | L977 |

#### 部署与运维 API（L1040-1231）

| 功能 | 路由 | 行号 |
|---|---|---|
| 部署前 IP 安全自检 | `/api/check-my-ip` → `api_check_my_ip()` | L1043 |
| 下发白名单（含审计模式、dry-run） | `/api/deploy` → `api_deploy()` | L1080 |
| 撤销白名单 | `/api/remove` → `api_remove()` | L1133 |
| 查看服务器状态 | `/api/status` → `api_status()` | L1176 |
| 查看审计日志 | `/api/audit-log` → `api_audit_log()` | L1205 |
| 全局设置 | `/api/settings` → `api_settings()` | L1020 |
| 读取完整配置（隐藏密码） | `/api/config` → `api_config()` | L759 |

`/api/check-my-ip` 会检测 X-Forwarded-For / remote_addr，如果是 localhost 则探测真实出口 IP。

#### 后台调度器（L537-733）

| 功能 | 函数/路由 | 行号 |
|---|---|---|
| 调度器状态（线程 + 计数 + 锁） | `_sched` dict | L540 |
| 单次执行：扫描过期 → 清除 → 重下发受影响服务器 | `_scheduler_run_once()` | L568 |
| 后台线程主循环 | `_scheduler_loop()` | L647 |
| 启动/停止调度器 | `_start_scheduler()` / `_stop_scheduler()` | L660/L671 |
| 启动时从 config 恢复调度器状态 | `_init_scheduler_from_config()` | L677 |
| 查询调度器状态 API | `GET /api/scheduler` | L691 |
| 启停/修改调度器 API | `PATCH /api/scheduler` | L703 |

调度器逻辑：
1. 读原始 config 文件（不触发 `load_config` 的写盘）
2. 扫描全局 + 各服务器专属白名单中的过期条目
3. 有过期 → `load_config()` 触发清除 + 写盘 → 对受影响服务器重新下发
4. 间隔可配置（默认 5 分钟）

#### Web 入口

| 功能 | 行号 |
|---|---|
| 主页面（需要登录） | `/` → `index()` L752 |
| 启动参数解析 | `__main__` L1235 |
| 端口配置（默认 6969） | L1238 |

### 八、前端模板（`templates/`）

| 文件 | 功能 |
|---|---|
| `templates/index.html` | 管理主界面：白名单编辑、服务器管理、下发面板、设置、审核中心、调度器控制 |
| `templates/login.html` | 登录页面 |
| `templates/guest.html` | Guest 自助换 IP 界面（输入旧 IP + 新 IP，自动替换并下发） |
| `templates/apply.html` | 自助申请白名单表单（IP、姓名、工号、目的、时长、目标服务器） |

### 九、CLI 参数树（`build_parser()` L1097）

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

---

## 远端脚本适配逻辑

`generate_apply_script` 生成的脚本在远端自动检测防火墙管理器：

- **firewalld 运行中**（openEuler / CentOS 8+ / RHEL 8+ 默认）→ 使用 `firewall-cmd --permanent --add-rich-rule` 模式，`--reload` 后生效，持久化天然由 `--permanent` 保证。审计模式下保留 ssh service 开放 + 添加日志规则。
- **仅有 iptables**（Ubuntu / Debian / 关闭 firewalld 的 openEuler）→ 创建 `SSH_WHITELIST` 链并挂入 `INPUT`。持久化路径按 OS 自动选择：`/etc/iptables/rules.v4`（Debian 系）、`/etc/sysconfig/iptables` + `systemctl enable iptables`（RHEL/openEuler 系）、`rc.local`（兜底）。

审计模式（`--audit`）：firewalld 下保留 ssh service + 添加日志 rich-rule；iptables 下链末规则为 LOG + ACCEPT（不 DROP）。`audit-log` 命令汇总 journald + syslog 中的审计日志并输出统计摘要。

---

## 配置文件结构

`config.json`（运行时自动创建，不要提交到版本库）：

```json
{
  "whitelist": [
    {"ip": "192.168.1.0/24", "description": "", "added_by": "", "added_at": "", "expire_at": null}
  ],
  "servers": [
    {"host": "", "port": 22, "user": "root", "key_file": "", "name": "", "password": "", "proxy": "", "whitelist": []}
  ],
  "settings": {
    "ssh_port": 22,
    "persist_rules": true,
    "proxy": "",
    "auto_deploy": {"enabled": false, "interval_minutes": 5},
    "secret_key": "",
    "auth": {"username": "admin", "password_hash": "sha256:..."}
  },
  "applications": [
    {"id": "", "ip": "", "name": "", "employee_id": "", "purpose": "", "duration": "", "expire_at": null, "servers": [], "status": "pending", "approved_servers": [], "deployed": false, "created_at": "", "reviewed_at": null, "reviewed_by": null}
  ]
}
```

`password` 字段明文存储，生产环境应优先使用 `key_file`。
