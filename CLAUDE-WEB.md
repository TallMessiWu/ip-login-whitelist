# Web 后端参考

> 从 [CLAUDE.md](CLAUDE.md) 拆出。当需要定位 Web API 路由、认证、调度器或前端模板的精确代码位置时按需读取。

## 一、认证系统（L42-114）

| 功能 | 函数/路由 | 行号 |
|---|---|---|
| 密码哈希（SHA-256 + salt） | `_hash_password()` | L47 |
| 密码验证 | `_verify_password()` | L54 |
| 首次启动创建 admin/admin 默认账户 | `_setup_app_secret()` | L77 |
| 登录拦截中间件 | `_require_login()` | L104 |
| 登录页 | `/login` → `login_page()` | L119 |
| 登录 API | `POST /api/login` → `api_login()` | L148 |
| 登出 API | `POST /api/logout` → `api_logout()` | L166 |
| 修改密码 API | `PATCH /api/auth/password` → `api_change_password()` | L516 |

公开路径（无需登录）：`/login`、`/guest`、`/apply` 及对应的 `/api/*` 路由 + `/api/servers-public`、`/api/check-my-ip`、`/api/my-ip`。

## 二、Guest 自助换 IP（L187-380）

| 功能 | 路由 | 行号 |
|---|---|---|
| Guest 页面 | `/guest` → `guest_page()` | L188 |
| 替换 IP 并立即下发（无需审核） | `POST /api/guest/replace` → `api_guest_replace()` | L253 |
| 自助记录列表（管理员） | `GET /api/self-service-log` → `api_self_service_log()` | L470 |

逻辑：原地更新（保留 description/expire_at 等元数据，仅刷新 added_at/added_by="guest-self-service"），同步全局白名单与所有服务器专属白名单中匹配的旧 IP，立即下发到受影响的**启用中**服务器，返回 `deploy_result` 给前端实时显示。无需管理员审核；隐式凭证 = 旧 IP 必须已在白名单中。

**存储分离**：自助替换记录写入独立的 `cfg["self_service_log"]`（不进 `applications`），避免被审核/批量下发流程误处理。记录字段：`id / old_ip / new_ip / description / expire_at / servers / deploy_results / success_count / total / all_success / created_at`。审核页通过"自助换 IP"筛选标签独立展示。

## 三、自助申请白名单（L274-513）

| 功能 | 路由 | 行号 |
|---|---|---|
| 申请页面 | `/apply` → `apply_page()` | L131 |
| 提交申请 | `POST /api/apply` → `api_apply()` | L274 |
| 查看申请列表 | `GET /api/applications` → `api_applications_list()` | L340 |
| 审核（批准/拒绝，可部分服务器） | `POST /api/applications/<id>/review` → `api_applications_review()` | L348 |
| 下发已批准申请 | `POST /api/applications/deploy` → `api_applications_deploy()` | L437 |
| 公开服务器列表 | `GET /api/servers-public` → `api_servers_public()` | L136 |

审核流程：提交申请(含 IP/姓名/工号/目的/时长/目标服务器) → 管理员审核 → 批准后写入服务器专属白名单 → 手动 deploy 或等调度器下发。公开服务器列表和申请提交仅接受启用的服务器（禁用的不展示不上报），审核批准的 `valid_hosts` 也排除禁用服务器。

**申请时长上限**：`/apply` 时长下拉仅 1d/3d/7d/14d（最长 2 周，已移除 30d/90d/自定义日期）。`api_apply()` 后端硬拦截：用 `parse_expire(duration)` 算出绝对到期时间，超过 `now + 14 天`（含 1 分钟容差）或为永久(`None`)的申请返回 400——防止绕过前端直接提交超长时长。相对时长（`Nd/Nh/Nm`）仍不预存 `expire_at`，审批时从审批时刻起算；绝对日期直接存入。更长时效由审核员批准后在管理端手动延长。

**超期未审批自动拒绝**：`_auto_reject_stale_applications(cfg)` 把 `created_at` 早于 `now - PENDING_AUTO_REJECT_DAYS`（默认 7 天）且仍为 `pending` 的申请置为 `rejected`，打 `auto_rejected=True` + `reviewed_by="system"`（与管理员手动拒绝区分；`created_at` 无法解析的跳过）。读时惰性触发：`api_applications_list()` 每次拉取先执行、有变更才回写；`_scheduler_run_once()` 也在开头独立执行一次（不依赖是否有过期白名单）。前端「已拒绝」卡片对 `auto_rejected` 显示灰色「超时自动拒绝」标签（i18n key `review_auto_rejected`），且不展示 `system` 这个哨兵审核人。

## 四、白名单管理 API（L772-862）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加全局 IP | `POST /api/whitelist` | L774 |
| 删除全局 IP | `DELETE /api/whitelist/<ip>` | L815 |
| 编辑全局 IP（IP/备注/有效期） | `PATCH /api/whitelist/<ip>` | L828 |
| 锁定/解锁全局 IP | `PATCH /api/whitelist/<ip>/lock` body=`{locked: bool}` | — |

添加全局 IP 时自动清除各服务器专属白名单重复项，并**继承锁定状态**：任一被清除的专属条目处于 `locked=true` 时，新建的全局条目也自动加锁（防"提升到全局"绕过锁定）。锁定的条目无法被删除/编辑/Guest 替换，需先解锁。

## 五、服务器管理 API（L864-922）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加服务器 | `POST /api/servers` | L866 |
| 删除服务器 | `DELETE /api/servers/<host>` | L894 |
| 更新服务器（密码/代理/密钥） | `PATCH /api/servers/<host>` | L905 |
| 启用/禁用服务器 | `POST /api/servers/<host>/toggle` body=`{enabled: bool}` | — |

添加服务器时默认 `enabled: true`。`DELETE /api/servers/<host>` 删除启用中的服务器前先远端取消白名单（取消成功才删除，失败 502），已禁用的跳过远端直接删除。`POST …/toggle` 禁用：先远端取消白名单，成功才标记禁用，失败回滚保持启用（502）；启用：仅恢复 flag 标记，不自动下发。

## 六、服务器专属白名单 API（L925-1015）

| 功能 | 路由 | 行号 |
|---|---|---|
| 添加专属 IP | `POST /api/servers/<host>/whitelist` | L927 |
| 删除专属 IP | `DELETE /api/servers/<host>/whitelist/<ip>` | L961 |
| 编辑专属 IP | `PATCH /api/servers/<host>/whitelist/<ip>` | L977 |
| 锁定/解锁专属 IP | `PATCH /api/servers/<host>/whitelist/<ip>/lock` body=`{locked: bool}` | — |

## 七、部署与运维 API（L1040-1231）

| 功能 | 路由 | 行号 |
|---|---|---|
| 部署前 IP 安全自检 | `GET /api/check-my-ip` → `api_check_my_ip()` | L1043 |
| 仅返回 HTTP 客户端 IP（申请页用） | `GET /api/my-ip` → `api_my_ip()` | — |
| 下发白名单（审计/dry-run） | `POST /api/deploy` → `api_deploy()` | L1080 |
| 撤销白名单 | `POST /api/remove` → `api_remove()` | L1133 |
| 查看服务器状态 | `GET /api/status` → `api_status()` | L1176 |
| 查看审计日志 | `GET /api/audit-log` → `api_audit_log()` | L1205 |
| 全局设置 | `PATCH /api/settings` → `api_settings()` | L1020 |
| 读取完整配置（隐藏密码） | `GET /api/config` → `api_config()` | L759 |

`/api/check-my-ip`：检测 X-Forwarded-For / remote_addr，localhost 时探测真实出口 IP（用于部署侧自检）。

`/api/my-ip`：仅返回 HTTP 客户端 IP（X-Forwarded-For / remote_addr），**永不**触发出口探测——避免反向代理未注入 X-Forwarded-For 时把网站服务器自身 IP 当作用户 IP 返回给申请页面。返回 `{client_ip, is_local}`。

`POST /api/deploy` 硬拦截（非 dry_run）：调用 `get_outgoing_ip` 探测管理机本地出口 IP；若不在 `cfg["whitelist"]`（**全局**白名单）中则返回 403 且不触发 `capture_run`，防止误下发使管理机失去对目标服务器的 SSH 访问能力。口径比前端 `/api/check-my-ip` 的合并白名单更严：只接受全局，强制管理机 IP 全局可达。**跳过已禁用服务器**——目标全禁用时返回 400 不下发。

**并发执行**：`/api/deploy`、`/api/remove`、`/api/status`、`/api/audit-log`、Guest 自助换 IP、`/api/applications/deploy`、调度器，对多台服务器的 `capture_run` 均通过 `_parallel_run(servers, work_fn)` 用线程池并发，最大并行度 `DEPLOY_MAX_CONCURRENCY=10`，`ex.map` 保证结果与入参同序；单台或空列表走串行分支。每个路由把原 per-server 循环体抽成 `work_fn(server)` 闭包返回结果 dict，循环外 `success_count = sum(...)`。`/api/deploy` 的管理机本地 IP 硬拦截在并发前串行执行；过滤（禁用/不受影响）也在并发前完成。`capture_run` 用 `_ThreadLocalStdout`（模块加载时 `_install_threadlocal_stdout()` 幂等安装）给每线程独立 buffer 捕获 `run_on_server` 的 print 输出，避免并发串台；未安装代理时回退全局 `redirect_stdout`。

## 八、后台调度器（L537-733）

| 功能 | 位置 | 行号 |
|---|---|---|
| 调度器状态 | `_sched` dict | L540 |
| 单次执行 | `_scheduler_run_once()` | L568 |
| 后台线程主循环 | `_scheduler_loop()` | L647 |
| 启动/停止 | `_start_scheduler()` / `_stop_scheduler()` | L660/L671 |
| 启动时恢复 | `_init_scheduler_from_config()` | L677 |
| 查询状态 API | `GET /api/scheduler` | L691 |
| 启停/修改 API | `PATCH /api/scheduler` | L703 |

执行逻辑：
0. 先独立执行 `_auto_reject_stale_applications()`（兜底：超期未审批 pending 申请自动拒绝，不依赖是否有过期白名单），有变更则回写
1. 读原始 config（不触发 load_config 写盘），扫描过期条目
2. 有过期 → `load_config()` 触发清除+写盘 → 对受影响的**启用中**服务器重下发
3. 间隔可配置（默认 5 分钟）；跳过已禁用服务器

## 九、前端模板

| 文件 | 功能 |
|---|---|
| `templates/index.html` | 管理主界面：白名单编辑、服务器管理、下发面板、设置、审核中心、调度器控制 |
| `templates/login.html` | 登录页面 |
| `templates/guest.html` | Guest 自助换 IP 界面（旧 IP → 新 IP，自动替换并下发） |
| `templates/apply.html` | 自助申请表单（IP、姓名、工号、目的、时长、目标服务器） |

**执行输出展示**：下发/取消/状态/审计/审核下发拿到后端 `results: [{server, host, success, output}]` 后统一走 `renderRunResults(results, {target, mode})`（`templates/index.html`）渲染——顶部「失败汇总条」(`#${target}-summary`) 红色列出失败服务器为可点击 chip（`scrollToRunLog(target, host)` 跳转到对应日志段并触发 `.log-flash` 高亮），绿色显示成功台数；下方 `#${target}-log` 每台一个带 `${target}-block-${host}` 锚点的分段日志块，失败块加红色左边框。`target` 区分主输出区（`output-*`）与审核输出区（`review-output-*`）；`mode='audit'` 无成功/失败语义，仅按服务器列日志。无 `results` 的纯文本提示（连接中/错误/无日志）仍走 `showOutput()`。摘要文案复用翻译 key `deploy_summary_failed` / `deploy_summary_success` / `deploy_server_success` / `deploy_server_fail`。

## 十、国际化（i18n）

| 功能 | 位置 | 行号 |
|---|---|---|
| 翻译字典模块 | `translations.py` | 全文 |
| 语言检测（Accept-Language） | `detect_language()` | translations.py 末 |
| 语言注入模板（context processor） | `inject_i18n()` | web_app.py L152 |
| 语言切换 API | `GET/PATCH /api/lang` → `api_lang()` | web_app.py L186 |
| session 中存储语言 | `before_request` → `session["lang"]` | web_app.py L108 |

逻辑：首次访问从 `Accept-Language` 检测（zh → ru → en → 默认 zh），存入 session。`/api/lang` PATCH 可手动切换。模板上下文处理器注入 `lang`（语言代码）和 `T`（当前语言完整翻译字典）。前端 `window.__I18N` + `t(key, params)` 查找翻译，`data-i18n` 属性自动翻译静态文本。

## 十一、Web 入口

| 功能 | 行号 |
|---|---|
| 主页面 | `/` → `index()` L752 |
| 启动参数 | `__main__` L1235（`--host`/`--port`/`--debug`，默认端口 6969） |
