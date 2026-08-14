# AGENTS.md

通过 SSH 将 `iptables` 或 `firewalld` 规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。同时提供 Flask Web 管理界面。

## 文件地图

| 文件 | 用途 |
|---|---|
| `whitelist_manager.py` | CLI 全部功能 + Web 依赖的核心库 |
| `web_app.py` | Flask Web 应用，REST API + 页面路由 + 后台调度器 |
| `templates/index.html` | 管理主界面（白名单/服务器/下发/设置/审核/调度器） |
| `templates/login.html` | Web 登录页 |
| `templates/guest.html` | Guest 自助换 IP（无需登录） |
| `templates/apply.html` | 自助申请白名单（无需登录） |
| `translations.py` | 三语翻译字典（zh/ru/en），含 Accept-Language 语言检测函数 |
| `tests/test_whitelist.py` | pytest 测试套件，覆盖 CLI + Web、权限矩阵与数据隔离 |
| `pyproject.toml` / `uv.lock` | uv 项目配置，Python ≥3.11，flask ≥3.1.3 |
| `requirements.txt` | `flask>=3.0.0`（paramiko 可选；兼容 pip 安装） |
| `config.json` | 运行时生成，存储白名单/服务器/认证等（已 gitignore） |

详细功能→代码位置映射见 CLI 与 Web 细分指导文档：
- CLI 命令、核心库函数（脚本生成、SSH 执行、时效管理、白名单合并）
- Web 后端 API、认证、调度器、前端模板

## 代码架构

`whitelist_manager.py` 五层结构：

1. **配置层** `load_config`/`save_config` — 读写 `config.json`，加载时自动清除过期条目
2. **子命令处理层** `cmd_ip_*`/`cmd_server_*`/`cmd_deploy`/`cmd_status`/`cmd_remove`/`cmd_settings`/`cmd_audit_log`
3. **脚本生成层** `generate_apply_script`/`generate_status_script`/`generate_remove_script`/`generate_audit_log_script` — 返回 bash 脚本字符串，远端自动检测 firewalld/iptables，并事务管理 OpenSSH 公钥策略
4. **SSH 执行层** `run_on_server` → `_run_via_paramiko`/`_run_via_subprocess` — 优先 paramiko，降级 subprocess
5. **CLI 入口** `build_parser`/`main` — argparse 两级子命令树

## 远端适配逻辑

`generate_apply_script` 脚本在远端自动检测：
- **firewalld 运行中** → `firewall-cmd --permanent --add-rich-rule`，`--reload` 生效，`--permanent` 保证持久化
- **仅有 iptables** → 创建 `SSH_WHITELIST` 链挂入 `INPUT`，持久化路径按 OS 选择：`/etc/iptables/rules.v4`（Debian）、`/etc/sysconfig/iptables`（RHEL/openEuler）、`rc.local`（兜底）

审计模式（`--audit`）：firewalld 下保留 ssh service + 日志 rich-rule；iptables 下链末 LOG + ACCEPT。

## 关键设计点

- **双层白名单**：全局白名单 + 每台服务器可配专属白名单，下发时合并去重，过期条目不进入合并；添加全局 IP 时若各服务器专属白名单中存在同 IP，自动清除重复并继承其锁定状态（防"提升到全局"绕过锁定）
- **IP 或 SSH 公钥放行**：来源 IP 命中有效 IP 白名单时保留服务器原认证方式；否则仅允许与 Linux 用户匹配的有效托管公钥。公钥同样采用全局 + 服务器专属合并，按“用户 + 密钥”去重
- **独立公钥存储**：托管公钥写入 `/etc/ssh/ip-login-whitelist/authorized_keys/%u`，只由工具生成的 sshd `Match Address` 策略引用，绝不读写用户原有 `~/.ssh/authorized_keys`
- **混合模式事务下发**：先校验 Linux 用户、恢复通道、`sshd -t` 和 `sshd -T -C`，原子替换并 reload sshd 成功后才开放防火墙；任何失败恢复工具原策略。最后一条授权过期时会严格下发拒绝所有 SSH
- **时效管理**：`parse_expire()` 支持 `7d`/`24h`/`30m`（相对）、`2025-12-31`（绝对）、留空（永久）；`load_config()` 加载时自动清除过期条目
- **条目锁定**：白名单条目可设 `locked: true`，锁定后无法被 Web 编辑/删除、Guest 自助换 IP 替换、或 `type=replace` 申请的审批删除；防止误把关键 IP（如管理服务器自身 IP）改掉导致回连失败
- **服务器启用/禁用开关**：每台服务器 `enabled` 字段（缺省 true，兼容旧配置）。禁用 → 先远端取消白名单，成功才标记禁用，失败回滚保持启用（502）；启用 → 仅恢复 flag，不自动下发。禁用的服务器在手动下发、审核下发、审核批准、Guest 换 IP、自动调度下发、安全自检、申请页公开列表、申请提交中均被跳过。删除服务器时自动先取消白名单（已禁用的跳过远端直接删除），取消失败则拒绝删除（502）
- **强制覆盖**：禁用/删除时远端取消失败的 502 响应带 `can_force: true`（区别于 404 等不可强制的失败）。用于「管理员自行关闭白名单并改了密码，网站再也连不上」的死锁场景——前端弹确认窗（展示远端失败原因 + 风险提示）让用户选择强制：删除走 `DELETE ...?force=1`、禁用走 toggle body `force: true`，后端 force 为真时**跳过远端**直接改本地状态（删除条目 / 标记禁用），成功响应带 `forced: true`。强制只改网站状态，远端可能残留白名单规则需用户自行清理
- **审批不覆盖既有条目**：审批申请时若目标服务器专属白名单已存在同 IP，跳过添加但保留原条目的 description/expire_at/added_by，响应中提示被跳过的服务器列表，避免新审批静默改写其他人申请的元数据
- **多管理员与服务器范围授权**：旧 `settings.auth` 自动无损迁移为 `settings.auth.accounts`，旧账号成为唯一 `superadmin`；新账号均为 `scoped_admin`，与服务器是多对多关系。账号创建要求至少一台有效服务器和不少于 6 位的密码，创建或重置时设置的密码直接生效，不强制首次改密。服务器范围按请求实时读取，范围调整立即生效；改密、重置密码、禁用或删除通过 `session_version` 立即使旧会话失效。删除服务器同步清理所有账号中的授权，空范围账号保持启用
- **受限管理员数据隔离**：受限管理员只能管理分配服务器的普通专属 IP/公钥、逐服务器申请审核、普通下发、受限状态和审计；locked 条目只读。全局 IP/公钥、服务器连接配置、设置、调度器、账号管理、审计模式和撤销远端限制均由后端拒绝。`/api/config` 不返回全局数组、数量、secret/auth/encryption key 或 SSH 端口/用户/密码/密钥/代理；Dry Run、下发、自助下发、状态和审计输出隐藏全局地址、公钥、指纹与合并数量
- **逐服务器审批**：申请用 `server_reviews[host]` 分别记录 `pending/approved/rejected`、审核人/时间、最终备注/有效期和下发状态；第一个审核结果生效，重复审核返回 409。任一待审则聚合 `pending`，全部拒绝为 `rejected`，无待审且至少一台批准为 `approved`，所有批准服务器成功下发后聚合 `deployed=true`。旧申请惰性迁移，超时自动拒绝也逐服务器处理；受限管理员只看到和处理自己范围内的部分，历史 `type=replace` 仅超级管理员可处理
- **并发下发**：Web 端各下发/查询路径（手动下发、取消、状态、审计、自助换 IP、审核批量下发、调度器）通过 `_parallel_run` 用线程池并发执行，最大并行度 `DEPLOY_MAX_CONCURRENCY=10`，结果按入参顺序收集；超过上限的服务器排队。`capture_run` 用 `_ThreadLocalStdout` 线程隔离 stdout，避免并发时多台输出串台（替代全局 `redirect_stdout`，后者非线程安全）
- **超时**：SSH 连接超时 30s；远端脚本执行/读输出超时由 `EXEC_TIMEOUT=120`（秒）统一控制（paramiko `settimeout` 与 subprocess `timeout` 共用）。「慢」由并发下发 + 连接超时解决，执行超时给足余量避免规则已落盘却因读输出超时被误判失败
- **代理链**：优先级 per-server `--proxy` > 全局 `settings --proxy` > 环境变量 `ALL_PROXY`，支持 socks5/socks4/http
- **安全自检**：`/api/check-my-ip` 部署侧自检（含服务器自身出口探测，跳过禁用服务器）；`/api/my-ip` 仅返回 HTTP 真实客户端 IP（供 Guest/申请页填充，不做服务器出口探测）；`POST /api/deploy` 硬拦截：管理机本地出口 IP 必须存在于**全局**白名单中，否则 403 不下发
- **远端防火墙自启**：下发脚本检测到 firewalld 已安装但未运行时，先 `systemctl start/enable firewalld` + runtime 兜底放行 ssh，启动失败才回退 iptables；移除脚本的 `firewall-cmd --reload` 失败时 exit 1，防止取消失败被误判为成功
- **认证**：Web 端 PBKDF2-HMAC-SHA256 密码哈希（200k 迭代，兼容旧 SHA-256 哈希），session 鉴权，登录速率限制（每 IP 60 秒 ≤10 次），公开路径白名单（`/login`、`/guest`、`/apply`）
- **CSRF 防护**：所有状态变更请求（POST/PUT/PATCH/DELETE）必须携带 `X-CSRF-Token` 头，前端通过包装 `window.fetch` 自动注入；session cookie 设置 HttpOnly + SameSite=Lax
- **国际化**：首次访问根据 `Accept-Language` 自动检测语言（中文 → 俄语 → 英文，无法检测默认中文），session 存储偏好；每页右上角语言切换按钮；`translations.py` 三语字典，模板上下文注入 `lang`/`T`，前端 `t(key)` + `data-i18n` 属性翻译
- **后台调度器**：可选启用的定时扫描 → 过期清除 → 自动重下发，间隔可配（默认 5 分钟）；跳过已禁用服务器

## 配置文件结构

```json
{
  "whitelist": [{"ip": "", "description": "", "added_by": "", "added_at": "", "expire_at": null, "locked": false}],
  "public_key_whitelist": [{"id": "", "public_key": "", "fingerprint": "", "linux_user": "", "description": "", "added_by": "", "added_at": "", "expire_at": null, "locked": false}],
  "servers": [{"host": "", "port": 22, "user": "root", "key_file": "", "name": "", "password": "", "proxy": "", "enabled": true, "whitelist": [], "public_key_whitelist": []}],
  "settings": {"ssh_port": 22, "persist_rules": true, "proxy": "", "auto_deploy": {"enabled": false, "interval_minutes": 5}, "secret_key": "", "auth": {"accounts": [{"username": "admin", "password_hash": "pbkdf2:...", "role": "superadmin", "enabled": true, "server_hosts": [], "password_changed": true, "session_version": 1, "created_at": "", "created_by": "system"}]}},
  "applications": [{"id": "", "ip": "", "name": "", "employee_id": "", "purpose": "", "duration": "", "servers": ["host"], "server_reviews": {"host": {"status": "pending", "reviewed_by": null, "reviewed_at": null, "description": null, "expire_at": null, "deployed": false}}, "status": "pending", "approved_servers": [], "deployed": false, ...}]
}
```

## 环境管理

依赖的安装和环境维护都必须使用 uv 工具：

```bash
uv sync                      # 按 pyproject.toml / uv.lock 安装依赖
uv run python web_app.py     # 在受管环境中启动 Web
uv run pytest                # 运行测试
```

## 测试

`tests/test_whitelist.py` 用 pytest + `unittest.mock`，无真实 SSH / 网络依赖：

- 顶层用 `mock.patch.dict(sys.modules, {"paramiko": ..., "socks": ...})` 屏蔽可选依赖
- `tmp_config_file` fixture 把 `CONFIG_FILE` 重定向到 `tmp_path`，每个测试独立隔离
- `_CSRFClient` 自动处理 CSRF token，模拟前端 fetch 包装器行为
- 覆盖范围：配置读写 / IP 与公钥校验 / 时效解析 / 双层合并 / 纯 IP、混合、公钥-only、全空拒绝脚本 / sshd 校验与回滚 / SSH 执行（mock）/ CLI 子命令 / Web REST API / 多账号迁移与生命周期 / 会话失效 / 权限矩阵 / 全局数据脱敏 / 逐服务器审批与下发 / 调度器

运行：`uv run pytest -v` 或 `uv run pytest tests/test_whitelist.py::TestParseExpire -v`。

## 代码提交

**文档更新时机**：AGENTS.md、README.md 以及相关细分指导文档 **只在提交前**才更新，平时迭代过程中不要修改这些文档——避免污染上下文缓存命中率。

**自动提交规则**：一旦本次工作改动了 AGENTS.md 或相关细分指导文档中的任何一个，必须**紧接着** `git add` + `git commit` + `git push`，不可只改文档不提交；同一次工作里的其他代码改动也一并打包进同一次提交。

**提交信息不需用户确认**：使用 gitmoji-commit skill 自行生成并执行提交，无需向用户确认提交信息。功能变更、文件增删、架构调整、API 增减都属于触发文档更新的条件。
