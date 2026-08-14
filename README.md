# IP Login Whitelist Manager

通过 SSH 将防火墙规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。

**适用场景**：服务器密码已扩散给多人、存在未登记的免密 SSH 配置，改密码已无法阻止未授权访问时，通过网络层 IP 白名单彻底封堵。

---

## 安装

推荐使用 [uv](https://github.com/astral-sh/uv) 管理依赖：

```bash
git clone https://github.com/TallMessiWu/ip-login-whitelist.git
cd ip-login-whitelist
uv sync                            # 按 pyproject.toml / uv.lock 安装依赖
uv run python web_app.py           # 在受管环境中启动 Web
```

或使用传统 pip：

```bash
pip install -r requirements.txt    # flask>=3.0.0
```

`paramiko` 可选，无此包时自动降级为系统 `ssh` 命令；`flask` 仅 Web 界面需要。

**系统要求**：Python 3.11+（`pyproject.toml` 声明），远端服务器需有 `iptables` 或 `firewalld`（需 root 权限执行）。

---

## Web 界面

除 CLI 外，还提供浏览器管理界面：

```bash
python web_app.py                     # 默认监听 0.0.0.0:6969，本机用 http://127.0.0.1:6969
python web_app.py --port 9090         # 自定义端口
python web_app.py --host 127.0.0.1    # 仅本地访问（输出只剩一行 URL）
```

> 启动时若看到多行 `Running on http://...` 是 Flask 列出所有可用网卡（包括 Clash/V2Ray 等创建的 `198.18.x.x` 虚拟网卡），任选一个可用。要只看一行就 `--host 127.0.0.1`。

首次启动自动创建唯一超级管理员账户 `admin / admin`，登录后请及时主动修改密码。系统不再强制首次改密；超级管理员可在右上角「管理员账号」中创建受限管理员，并为每个账号分配一台或多台服务器。

打开浏览器访问即可使用以下功能：

- **Web 登录认证**：密码哈希 PBKDF2-HMAC-SHA256（200k 迭代，兼容旧 SHA-256），多账号 session 鉴权、会话版本失效、登录速率限制、CSRF 防护和主动改密
- **多管理员与服务器授权**：保留 `admin` 为唯一超级管理员；受限管理员可多对多分配服务器，只能管理对应服务器的专属 IP、公钥、申请审核和普通下发，无法查看全局 IP、公钥、连接凭据、设置或危险操作
- **IP 白名单**：在线添加 / 删除 / 编辑白名单 IP，支持有效期设置和**条目锁定**（锁定后无法被删除/编辑/Guest 替换，防误改关键 IP），实时生效到 `config.json`
- **SSH 公钥白名单**：按 Linux 用户维护全局或服务器专属公钥，支持有效期、编辑、锁定和删除；未命中 IP 白名单的来源只能使用匹配用户的有效托管公钥登录
- **服务器列表**：查看 / 添加 / 删除托管服务器，支持在线配置密钥、密码、代理
- **服务器专属白名单**：每台服务器可额外维护专属 IP 白名单，与全局白名单自动合并去重
- **下发白名单**：支持选择目标服务器、切换审计模式、Dry Run 预览，执行输出实时展示；多台批量下发时顶部以「失败汇总条」红色列出失败的服务器，点击即可跳转到对应日志段，无需在长日志里翻找
- **撤销白名单**：一键从服务器移除防火墙规则，恢复所有 IP 可登录
- **审计日志**：在线查看各服务器审计日志统计
- **设置**：在线修改全局 SSH 端口、规则持久化开关、全局代理
- **部署前安全自检**：自动检测浏览器客户端 IP 是否在白名单中，防止误锁定
- **自助换 IP（Guest）**：无需登录，输入旧 IP 和新 IP 即可自动替换并下发到所有服务器
- **自助申请白名单**：无需登录，在线提交申请（IP、姓名、工号、用途、时长、目标服务器），自动检测客户端真实 IP（支持挂 VPN 场景）
- **逐服务器审核**：每个目标服务器独立批准或拒绝并记录审核人、有效期和下发状态；同一服务器的第一个审核结果生效
- **过期自动下发调度器**：后台定时扫描过期条目并自动清除 + 重下发，间隔可配置
- **多语言支持**：中文 / 俄语 / English 三语界面，首次访问自动检测浏览器语言，右上角可手动切换

> 服务器认证（密钥/密码）也可通过 CLI `server add` 配置。

---

## 快速开始

### 第一步：添加你自己的 IP

> **重要**：部署前务必先把自己的 IP 加入白名单，否则部署后你也会被锁在外面。

```bash
# 添加单个 IP（永久有效）
python whitelist_manager.py ip add 203.0.113.10 --desc "我的办公室"

# 添加带有效期的 IP（7 天后自动过期）
python whitelist_manager.py ip add 203.0.113.10 --desc "临时访问" --expire 7d

# 添加整个网段（CIDR）
python whitelist_manager.py ip add 192.168.1.0/24 --desc "公司内网"

# 查看当前白名单
python whitelist_manager.py ip list
```

### 第二步：添加目标服务器

```bash
# 使用 SSH 密钥（推荐）
python whitelist_manager.py server add 10.0.1.1 \
    --name "生产服务器1" \
    --user root \
    --key ~/.ssh/id_rsa

# 使用密码
python whitelist_manager.py server add 10.0.1.2 \
    --name "生产服务器2" \
    --user root \
    --password yourpassword

# 通过代理连接
python whitelist_manager.py server add 10.0.1.3 \
    --name "内网服务器" \
    --user root \
    --key ~/.ssh/id_rsa \
    --proxy socks5://127.0.0.1:1080

# 查看服务器列表
python whitelist_manager.py server list
```

### 第三步：先用审计模式验证（推荐）

正式拦截前，建议先用 `--audit` 模式测试——所有 SSH 连接仍正常放行，但非白名单 IP 的连接会被写入系统日志，确认识别效果符合预期后再切换为真实拦截。

```bash
# 部署审计模式（不拦截，只记录）
python whitelist_manager.py deploy --audit

# 等待一段时间，让各 IP 产生实际连接，然后查看日志
python whitelist_manager.py audit-log

# 确认无误后，取消 --audit，正式下发拦截规则
python whitelist_manager.py deploy
```

`audit-log` 输出示例：

```
─── 统计摘要 ───
被拦截（非白名单）IP 统计:
  15       次  SRC=1.2.3.4
  3        次  SRC=5.6.7.8

白名单 IP 连接统计:
  42       次  SRC=192.168.1.100
```

### 第四步：正式下发拦截规则

```bash
# 先预览将执行的脚本（不实际操作）
python whitelist_manager.py deploy --dry-run

# 确认无误后正式下发到所有服务器
python whitelist_manager.py deploy

# 只下发到指定服务器
python whitelist_manager.py deploy --server 10.0.1.1
```

---

## 完整命令参考

### IP 白名单管理

| 命令 | 说明 |
|------|------|
| `ip add <IP或CIDR> [--desc 备注] [--expire 有效期] [--server 服务器]` | 添加 IP 或网段到白名单（全局或指定服务器专属） |
| `ip remove <IP或CIDR> [--server 服务器]` | 从白名单移除 |
| `ip list [--server 服务器]` | 查看全部白名单（全局或指定服务器专属） |

支持标准 CIDR 格式，如 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。

**有效期格式**（`--expire` 参数）：

| 格式 | 示例 | 说明 |
|------|------|------|
| 相对时长 | `7d`、`24h`、`30m` | 相对于当前时刻 |
| 绝对日期 | `2025-12-31` | 当天 23:59:59 过期 |
| 绝对时间 | `2025-12-31 23:59:59` | 精确到秒 |
| 不填 / `never` / `永久` | — | 永久有效 |

### SSH 公钥白名单管理

```bash
# 添加永久锁定的全局恢复公钥；也可用 --key 直接粘贴普通 OpenSSH 公钥
python whitelist_manager.py pubkey add --user root --file ~/.ssh/id_ed25519.pub --desc "管理员笔记本" --lock

# 添加服务器专属临时公钥
python whitelist_manager.py pubkey add --user deploy --key "ssh-ed25519 AAAA..." --server 10.0.1.1 --expire 7d

python whitelist_manager.py pubkey list [--server <IP或别名>]
python whitelist_manager.py pubkey lock <ID>
python whitelist_manager.py pubkey unlock <ID>
python whitelist_manager.py pubkey remove <ID> [--server <IP或别名>]
```

只接受不带选项的普通 OpenSSH 公钥；注释会被丢弃，私钥、证书、`command=` 等 authorized_keys 选项和内部类型不一致的密钥都会被拒绝。

### 服务器管理

| 命令 | 说明 |
|------|------|
| `server add <host> [选项]` | 添加服务器 |
| `server remove <host>` | 移除服务器 |
| `server list` | 查看服务器列表 |

`server add` 可用选项：

```
--name, -n     服务器别名（用于下发时 --server 指定）
--port, -p     SSH 端口，默认 22
--user, -u     SSH 用户名，默认 root
--key,  -k     SSH 私钥文件路径（优先使用）
--password     SSH 密码（明文存储，不推荐）
--proxy        该服务器专用代理，如 socks5://127.0.0.1:1080
```

### 下发与运维

```bash
# 审计模式（只记录，不拦截）
python whitelist_manager.py deploy --audit [--server <IP或别名>]

# 查看审计日志（统计被拦截/放行的 IP）
python whitelist_manager.py audit-log [--server <IP或别名>] [--lines 100]

# 正式下发拦截规则
python whitelist_manager.py deploy [--server <IP或别名>] [--port <端口>] [--dry-run] [-y]

# 查看服务器上当前生效的规则
python whitelist_manager.py status [--server <IP或别名>]

# 撤销白名单限制（恢复所有 IP 可登录）
python whitelist_manager.py remove [--server <IP或别名>] [-y]
```

### 全局设置

```bash
# 修改全局 SSH 端口（非 22 时使用）
python whitelist_manager.py settings --ssh-port 2222

# 关闭重启后自动恢复规则
python whitelist_manager.py settings --persist false

# 设置全局代理（对所有服务器生效，单台服务器的 --proxy 优先级更高）
python whitelist_manager.py settings --proxy socks5://127.0.0.1:1080

# 清除全局代理
python whitelist_manager.py settings --proxy ""
```

也可通过环境变量设置兜底代理（优先级低于配置文件）：

```bash
export ALL_PROXY=socks5://127.0.0.1:1080
python whitelist_manager.py deploy
```

**代理优先级**：单台服务器 `--proxy` > 全局 `settings --proxy` > 环境变量 `ALL_PROXY` / `SOCKS_PROXY`

支持协议：`socks5://`、`socks4://`、`http://`。使用 SOCKS 代理需安装 PySocks：

```bash
pip install PySocks
```

---

## 功能详解

### 全局白名单 + 服务器专属白名单

每台服务器有**两层**白名单：

1. **全局白名单**：对所有服务器生效，通过 `ip add`（不加 `--server`）管理
2. **服务器专属白名单**：仅对指定服务器生效，通过 `ip add --server <host>` 管理

下发时自动合并两层白名单（去重、过滤已过期条目）。添加全局 IP 时自动清除各服务器专属白名单中的重复项。

### 多管理员与按服务器授权

- `admin` 是唯一超级管理员，保留全部现有权限；旧版 `settings.auth` 会在首次加载时无损迁移到多账号结构并保留原密码。
- 新建账号均为受限管理员，创建时至少选择一台服务器并设置不少于 6 位的密码；创建或重置时设置的密码直接生效，不强制首次改密。超级管理员可随时调整范围、重置密码、启用、禁用或删除账号。
- 服务器与管理员是多对多关系；权限范围在每次请求时由后端重新读取。调整范围立即生效，重置密码、禁用或删除会让旧会话立即失效。
- 受限管理员只能查看分配服务器的名称、地址、启用状态和服务器专属 IP/公钥；不返回 SSH 端口、用户、密码、密钥路径、代理、全局设置、全局 IP/公钥及其数量。
- 普通下发仍在后端合并全局与服务器专属规则，但受限账号的 Dry Run、执行输出、状态和审计日志会隐藏全局地址、公钥、指纹及合并数量。审计模式、撤销远端限制、服务器管理、调度器和账号管理仅限超级管理员。
- 服务器删除时会同步移除所有账号中的对应授权；账号范围因此变空时仍保持启用，但看不到任何服务器。

### IP + SSH 公钥择一放行

- 来源 IP 命中有效 IP 白名单时，不进入工具的 sshd `Match` 块，继续使用服务器原有密码、公钥等认证配置。
- 未命中 IP 白名单时，只允许 `/etc/ssh/ip-login-whitelist/authorized_keys/%u` 中与登录用户匹配的有效托管公钥；用户原有 `~/.ssh/authorized_keys` 不会被读取、修改或覆盖。
- 存在有效公钥时 SSH 端口对网络开放，由 sshd 执行认证隔离；仅有 IP 时继续使用纯防火墙白名单；IP 和公钥都为空时拒绝所有 SSH。
- 首次启用混合模式必须具有永久锁定的恢复通道。下发会检查用户与 OpenSSH 能力，用 `sshd -t`、`sshd -T -C` 验证两类来源，reload 失败时自动回滚。

### 白名单有效期与自动过期

每个白名单条目可设置过期时间。`load_config()` 每次加载配置时自动清除已过期条目。Web 后台调度器可定时扫描过期条目并自动重下发。

### Web 自助申请与审批流程

1. 用户访问 `/apply` 页面，填写 IP、姓名、工号、用途、时长、目标服务器，提交申请（时长仅可选 1 天 / 3 天 / 1 周 / 2 周，**最长 2 周**；如需更长须联系审核员批准后手动延长，后端硬性拦截超限申请）
2. 管理员在 Web 管理界面「审核中心」查看自己有权处理的服务器
3. 每台目标服务器独立批准或拒绝；同一服务器分配给多个管理员时，第一个成功审核的结果生效，重复审核返回冲突
4. 每台服务器可使用不同备注和有效期；批准后 IP 写入相应服务器的专属白名单，然后按服务器独立下发并记录结果

> 超过一周（默认 7 天）仍未审批的申请会被自动拒绝，「已拒绝」列表中标注灰色「超时自动拒绝」标签，与管理员手动拒绝区分。

### Guest 自助换 IP

适用于用户 IP 变更后无法登录服务器的场景：

1. 访问 `/guest` 页面
2. 输入旧 IP（当前已失效的 IP）和新 IP
3. 系统搜索全局白名单 + 所有服务器专属白名单，将旧 IP 全部替换为新 IP
4. 自动下发到所有服务器

### 过期自动下发调度器

Web 后台可选启用的定时任务：

- 按配置间隔（默认 5 分钟）扫描全局和各服务器专属白名单
- 发现过期条目 → 自动清除 → 对受影响服务器重新下发
- 通过 Web 界面或 CLI 配置开关和间隔

### 部署安全自检

`deploy` 命令和 Web 下发前会自动检测本机出口 IP 是否在白名单中：

- CLI：通过 socket UDP trick + ipify API 探测出口 IP
- Web：检测 X-Forwarded-For / remote_addr，本地访问时探测真实出口 IP
- 若不在白名单中则警告并需要手动确认

---

## 适配系统说明

工具在远端服务器上自动检测防火墙类型，无需手动配置：

| 系统 | 防火墙 | 处理方式 |
|------|--------|----------|
| openEuler / CentOS 8+ / RHEL 8+ | firewalld（默认运行） | `firewall-cmd --permanent --add-rich-rule`，`--reload` 后生效，持久化由 `--permanent` 保证 |
| Ubuntu / Debian | iptables | 创建 `SSH_WHITELIST` 链，规则保存到 `/etc/iptables/rules.v4` |
| CentOS 7 / openEuler（关闭 firewalld） | iptables | 规则保存到 `/etc/sysconfig/iptables`，`systemctl enable iptables` 开机自启 |
| 其他 Linux | iptables | 规则写入 `/etc/iptables.whitelist.rules`，通过 `rc.local` 恢复 |

---

## 注意事项

- `config.json` 含服务器地址和密码，已加入 `.gitignore`，**禁止提交到版本库**
- 每次 `deploy` 前会列出白名单和目标服务器，默认需手动确认；加 `-y` 可跳过
- 下发前建议先 `--dry-run` 预览脚本，确认逻辑无误再执行
- 部署前工具会自动检测本机 IP 是否在白名单中，不在则给出危险警告
- 如不小心锁定自己，可通过控制台/VNC 登录服务器执行 `remove` 命令撤销
- Web 首次启动默认超级管理员账户 `admin / admin`，请登录后立即主动修改密码；创建或重置受限管理员时设置的密码直接生效

---

## 文件说明

```
whitelist_manager.py        # CLI 全部功能 + Web 依赖的核心函数库
web_app.py                  # Web 管理界面后端（Flask），REST API + 多账号授权 + 后台调度器
translations.py             # 三语翻译字典（中文/俄语/英文），含语言检测函数
templates/index.html        # Web 管理主界面（白名单/服务器/下发/设置/审核/调度器）
templates/login.html        # Web 登录页面
templates/guest.html        # Guest 自助换 IP 页面（无需登录）
templates/apply.html        # 自助申请白名单页面（无需登录）
tests/test_whitelist.py     # pytest 测试套件，覆盖 CLI + Web、权限矩阵与数据隔离
pyproject.toml / uv.lock    # uv 项目配置（Python ≥3.11，flask ≥3.1.3）
requirements.txt            # pip 兼容依赖清单：flask>=3.0.0
config.json                 # 运行时自动生成，存储白名单、服务器、认证等（不提交）
```

---

## 运行测试

测试用 pytest + `unittest.mock`，不发起真实 SSH / 网络调用，配置文件落到 `tmp_path`：

```bash
uv run pytest                                          # 运行全部测试
uv run pytest -v                                       # 详细模式
uv run pytest tests/test_whitelist.py::TestParseExpire # 只跑某个测试类
```

覆盖范围：配置读写、IP/CIDR 与 OpenSSH 公钥校验、指纹和稳定 ID、时效解析、全局/专属合并、纯 IP/混合/公钥-only/全空拒绝脚本、sshd 校验与回滚、SSH 执行（mock paramiko + subprocess）、CLI 子命令、Web REST API、多账号迁移与生命周期、登录 / CSRF / 会话失效 / 速率限制、完整权限矩阵、全局数据多通道脱敏、逐服务器审批与下发、调度器。
