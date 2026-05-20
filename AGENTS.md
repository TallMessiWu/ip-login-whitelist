# AGENTS.md

通过 SSH 将 `iptables` 或 `firewalld` 规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。同时提供 Flask Web 管理界面。

## 文件地图

| 文件 | 用途 |
|---|---|
| `whitelist_manager.py` | CLI 全部功能 + Web 依赖的核心库，单文件 ~1300 行 |
| `web_app.py` | Flask Web 应用，REST API + 页面路由 + 后台调度器 |
| `templates/index.html` | 管理主界面（白名单/服务器/下发/设置/审核/调度器） |
| `templates/login.html` | Web 登录页 |
| `templates/guest.html` | Guest 自助换 IP（无需登录） |
| `templates/apply.html` | 自助申请白名单（无需登录） |
| `translations.py` | 三语翻译字典（zh/ru/en），含 Accept-Language 语言检测函数 |
| `tests/test_whitelist.py` | pytest 测试套件，覆盖 CLI + Web 双侧，~1600 行 / 60+ 测试类 |
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
3. **脚本生成层** `generate_apply_script`/`generate_status_script`/`generate_remove_script`/`generate_audit_log_script` — 返回 bash 脚本字符串，远端自动检测 firewalld/iptables
4. **SSH 执行层** `run_on_server` → `_run_via_paramiko`/`_run_via_subprocess` — 优先 paramiko，降级 subprocess
5. **CLI 入口** `build_parser`/`main` — argparse 两级子命令树

## 远端适配逻辑

`generate_apply_script` 脚本在远端自动检测：
- **firewalld 运行中** → `firewall-cmd --permanent --add-rich-rule`，`--reload` 生效，`--permanent` 保证持久化
- **仅有 iptables** → 创建 `SSH_WHITELIST` 链挂入 `INPUT`，持久化路径按 OS 选择：`/etc/iptables/rules.v4`（Debian）、`/etc/sysconfig/iptables`（RHEL/openEuler）、`rc.local`（兜底）

审计模式（`--audit`）：firewalld 下保留 ssh service + 日志 rich-rule；iptables 下链末 LOG + ACCEPT。

## 关键设计点

- **双层白名单**：全局白名单 + 每台服务器可配专属白名单，下发时合并去重，过期条目不进入合并；添加全局 IP 时若各服务器专属白名单中存在同 IP，自动清除重复并继承其锁定状态（防"提升到全局"绕过锁定）
- **时效管理**：`parse_expire()` 支持 `7d`/`24h`/`30m`（相对）、`2025-12-31`（绝对）、留空（永久）；`load_config()` 加载时自动清除过期条目
- **条目锁定**：白名单条目可设 `locked: true`，锁定后无法被 Web 编辑/删除、Guest 自助换 IP 替换、或 `type=replace` 申请的审批删除；防止误把关键 IP（如管理服务器自身 IP）改掉导致回连失败
- **审批不覆盖既有条目**：审批申请时若目标服务器专属白名单已存在同 IP，跳过添加但保留原条目的 description/expire_at/added_by，响应中提示被跳过的服务器列表，避免新审批静默改写其他人申请的元数据
- **代理链**：优先级 per-server `--proxy` > 全局 `settings --proxy` > 环境变量 `ALL_PROXY`，支持 socks5/socks4/http
- **安全自检**：`/api/check-my-ip` 部署侧自检（含服务器自身出口探测）；`/api/my-ip` 仅返回 HTTP 真实客户端 IP（供 Guest/申请页填充，不做服务器出口探测）；`POST /api/deploy` 硬拦截：管理机本地出口 IP 必须存在于**全局**白名单中，否则 403 不下发
- **认证**：Web 端 PBKDF2-HMAC-SHA256 密码哈希（200k 迭代，兼容旧 SHA-256 哈希），session 鉴权，登录速率限制（每 IP 60 秒 ≤10 次），公开路径白名单（`/login`、`/guest`、`/apply`）
- **CSRF 防护**：所有状态变更请求（POST/PUT/PATCH/DELETE）必须携带 `X-CSRF-Token` 头，前端通过包装 `window.fetch` 自动注入；session cookie 设置 HttpOnly + SameSite=Lax
- **国际化**：首次访问根据 `Accept-Language` 自动检测语言（中文 → 俄语 → 英文，无法检测默认中文），session 存储偏好；每页右上角语言切换按钮；`translations.py` 236 键三语字典，模板上下文注入 `lang`/`T`，前端 `t(key)` + `data-i18n` 属性翻译
- **后台调度器**：可选启用的定时扫描 → 过期清除 → 自动重下发，间隔可配（默认 5 分钟）

## 配置文件结构

```json
{
  "whitelist": [{"ip": "", "description": "", "added_by": "", "added_at": "", "expire_at": null, "locked": false}],
  "servers": [{"host": "", "port": 22, "user": "root", "key_file": "", "name": "", "password": "", "proxy": "", "whitelist": []}],
  "settings": {"ssh_port": 22, "persist_rules": true, "proxy": "", "auto_deploy": {"enabled": false, "interval_minutes": 5}, "secret_key": "", "auth": {"username": "admin", "password_hash": "sha256:..."}},
  "applications": [{"id": "", "ip": "", "name": "", "employee_id": "", "purpose": "", "duration": "", "status": "pending", "approved_servers": [], "deployed": false, ...}]
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
- 覆盖范围：配置读写 / IP 校验 / 时效解析 / 脚本生成 / SSH 执行（mock）/ 代理解析 / CLI 子命令 / Web REST API / 认证 / 调度器 / 审核审批

运行：`uv run pytest -v` 或 `uv run pytest tests/test_whitelist.py::TestParseExpire -v`。

## 代码提交

**文档更新时机**：AGENTS.md、README.md 以及相关细分指导文档 **只在提交前**才更新，平时迭代过程中不要修改这些文档——避免污染上下文缓存命中率。

**自动提交规则**：一旦本次工作改动了 AGENTS.md 或相关细分指导文档中的任何一个，必须**紧接着** `git add` + `git commit` + `git push`，不可只改文档不提交；同一次工作里的其他代码改动也一并打包进同一次提交。

**提交信息不需用户确认**：使用 gitmoji-commit skill 自行生成并执行提交，无需向用户确认提交信息。功能变更、文件增删、架构调整、API 增减都属于触发文档更新的条件。
