# IP Login Whitelist Manager

通过 SSH 将防火墙规则下发到远端 Linux 服务器，限制只有白名单 IP 才能登录。

**适用场景**：服务器密码已扩散给多人、存在未登记的免密 SSH 配置，改密码已无法阻止未授权访问时，通过网络层 IP 白名单彻底封堵。

---

## 安装

```bash
git clone https://github.com/TallMessiWu/ip-login-whitelist.git
cd ip-login-whitelist
pip install -r requirements.txt   # flask + paramiko
```

`paramiko` 可选，无此包时自动降级为系统 `ssh` 命令；`flask` 仅 Web 界面需要。

**系统要求**：Python 3.7+，远端服务器需有 `iptables` 或 `firewalld`（需 root 权限执行）。

---

## Web 界面

除 CLI 外，还提供浏览器管理界面：

```bash
python web_app.py              # 默认 http://127.0.0.1:8080
python web_app.py --port 9090  # 自定义端口
```

打开浏览器访问即可：

- **IP 白名单**：在线添加 / 删除白名单 IP，实时生效到 `config.json`
- **服务器列表**：查看所有托管服务器及认证方式，一键检查各服务器白名单状态
- **下发白名单**：支持选择目标服务器、切换审计模式、Dry Run 预览，执行输出实时展示
- **设置**：在线修改全局 SSH 端口和规则持久化开关

> 服务器认证（密钥/密码）仍通过 CLI `server add` 配置，Web 界面不暴露明文密码。

---

## 快速开始

### 第一步：添加你自己的 IP

> **重要**：部署前务必先把自己的 IP 加入白名单，否则部署后你也会被锁在外面。

```bash
# 添加单个 IP
python whitelist_manager.py ip add 203.0.113.10 --desc "我的办公室"

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
| `ip add <IP或CIDR> [--desc 备注]` | 添加 IP 或网段到白名单 |
| `ip remove <IP或CIDR>` | 从白名单移除 |
| `ip list` | 查看全部白名单 |

支持标准 CIDR 格式，如 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。

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
- 如不小心锁定自己，可通过控制台/VNC 登录服务器执行 `remove` 命令撤销

---

## 文件说明

```
whitelist_manager.py   # CLI 全部功能，单文件
web_app.py             # Web 管理界面后端（Flask）
templates/index.html   # Web 管理界面前端
requirements.txt       # 依赖：paramiko（可选）+ flask（Web 界面需要）
config.json            # 运行时自动生成，存储白名单和服务器列表（不提交）
```
