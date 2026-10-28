# ASSCOR 攻击面管理专项审计 — "所有攻击面收紧到内核端"

**日期**: 2026-08-15 | **版本**: v0.2.3 | **性质**: 审计 + 归档（不修复）
**范围**: 全系统外部可达/可配置/可执行面，评估"收紧到内核端"的现状、缺口与路径

---

## 一、执行摘要

| 维度 | 结论 |
|------|------|
| 网络监听面 | ⚠️ **Web UI (8087) 绑定所有接口且无认证** — 最大暴露；JSONRPC mTLS 默认启用 ✅；gRPC 默认关闭 ✅ |
| 命令执行面 | ⚠️ user_check `sh -c` 绕过白名单（配置驱动任意命令）；common 白名单 ✅；特权 agent 严格 ✅ |
| 配置面 | ✅ 本轮已收紧（config.ini/agent.ini 0640 root:asscor）+ 内核同步下发 |
| 扩展面 | ✅ 四档执行策略 + 白名单 + checksum + 超时 + 路径防护 |
| 数据面 | ✅ 密钥/证书 0600；CVE 缓存/持久化目录 asscor 可写（运行所需） |
| **总评** | **攻击面已大部分"内核端可管控"，但 Web UI 认证缺失与 user_check 无命令白名单是两个真实缺口** |

**"收紧到内核端"定义**：攻击面的配置/策略/白名单由内核端（config.ini + 内核进程）统一决定与下发，受管端（agent/服务）仅执行内核下发的策略，本地不可篡改（root 只读 + 同步下发）。

---

## 二、攻击面总览（全量盘点）

### 2.1 网络监听面

| # | 面 | 位置 | 监听 | 认证/加密 | 风险 | 收紧状态 |
|:--:|---|------|------|-----------|:---:|:---:|
| N1 | kernel JSONRPC | `internal/comms/server.go:36` | TCP `:50051` 全接口 | mTLS（`--no-mtls` 可禁用） | 中（mTLS 保护） | ⚠️ 需强制 mTLS 生产模式 |
| N2 | kernel gRPC | `internal/comms/grpc_server.go:37` | TCP `:50052`（默认 `Enabled:false`） | TLS 可选 | 低（默认关） | ✅ 已收紧 |
| N3 | **Web UI** | `internal/webui/module.go:117` | TCP `:8087` **全接口** | **无** | **高：安全数据无认证可读** | ❌ 需收紧 |
| N4 | CLI Unix socket | `internal/cli/socket.go:13` | `/opt/asscor/asscor-cli.sock` | 0660（asscor 组） | 中（本地） | ⚠️ 需评估收紧到 0600 |
| N5 | 特权 agent socket | `internal/agent/privileged.go` | `/run/asscor/agent-priv.sock` | SO_PEERCRED + AllowedPeerUID | 低 | ✅ 已收紧 |

### 2.2 命令执行面

| # | 面 | 位置 | 控制 | 风险 | 收紧状态 |
|:--:|---|------|------|:---:|:---:|
| C1 | 内置检查命令 | `internal/common/exec.go:14` | 25 命令白名单 + 15 精确 shell 命令 + 元字符拒绝 + 直接 exec | 低 | ✅ |
| C2 | **user_check 命令** | `internal/config/user_check_registry.go` | **`sh -c` 任意命令**（30s 超时）| **高：无白名单/无参数限制** | ❌ 需收紧 |
| C3 | 特权 agent 命令 | `internal/agent/privileged.go:140` | isolate_host/deisolate_host 白名单 | 低 | ✅ |
| C4 | 扩展执行 | `internal/extmgr/extension_executor.go` | 四档策略 + 白名单 + SHA-256 checksum + 30s 超时 + 路径/符号链接防护 | 低 | ✅ |
| C5 | adapter 脚本 | `internal/adapter/script.go` | validateScriptPath 四层校验 | 低 | ✅ |
| C6 | pluginsdk | `pluginsdk/sdk.go` | 独立进程 JSON-RPC stdin/stdout | 低 | ✅ |

### 2.3 配置/数据面

| # | 面 | 现状 | 收紧状态 |
|:--:|---|------|:---:|
| D1 | config.ini | 0640 root:asscor + /etc/asscor 0750（本轮修复） | ✅ |
| D2 | agent.ini | 0640 root:asscor（本轮修复） | ✅ |
| D3 | 配置主源 | config.ini → 心跳同步下发 agent（本轮实现，mTLS 通道） | ✅ |
| D4 | HMAC key / 证书 | certs/ 0600/0700 | ✅ |
| D5 | CVE 缓存 / 持久化 | /var/lib/asscor asscor 可写（kernel 运行用户，运行所需） | ✅ |

### 2.4 API/协议面

| # | 面 | 方法 | 控制 | 收紧状态 |
|:--:|---|------|------|:---:|
| A1 | gRPC KernelService | Register/Heartbeat | mTLS | ✅ |
| A2 | gRPC AgentService | GetSnapshot/ExecuteCommand/StreamLogs | ExecuteCommand 走 HMAC 签名（agent 端）+ mTLS | ✅ |
| A3 | JSONRPC | 全服务 | 拦截器链（限流/熔断/审计）+ mTLS | ✅ |
| A4 | Web UI API | /api/health/dashboard/hosts | **无认证** | ❌ |
| A5 | CLI 命令 | 15 运维命令 | PermRead/PermWrite/PermAdmin 分级 | ✅ |

---

## 三、关键发现（分级）

### 🔴 P0 — Web UI (8087) 无认证绑定全接口

- `internal/webui/module.go:117` `Addr: fmt.Sprintf(":%d", m.listenPort)` → 监听所有接口
- `/api/dashboard`、`/api/hosts/{id}` 返回主机安全评估详情（分数、检查结果、历史趋势、边缘因子）
- **任何能到达 8087 端口的网络实体可无认证读取全部受管主机安全态势**——若端口暴露公网/内网横向，等同于安全情报泄露
- **收紧到内核端路径**：
  1. 默认绑定 `127.0.0.1:8087`（内核端 config.ini `[webui] listen_addr` 控制）
  2. 加认证令牌（内核生成/配置，webui 校验 Bearer）
  3. 生产部署默认关闭或经反向代理

### 🔴 P0 — user_check `sh -c` 无命令白名单

- `internal/config/user_check_registry.go` `exec.CommandContext(ctx, "sh", "-c", cmd)`——任意 shell 命令
- 防护现状：仅依赖配置来源可信（root 权限 + 内核同步，均已落地）
- **但**：配置一旦被合法管理员误配或经扩展/漏洞写入恶意命令，即为 root 级任意命令执行（agent 侧以 asscor 用户、特权 agent 侧以 root）
- **收紧到内核端路径**：
  1. 内核同步已集中配置来源（单点管控）✅
  2. 补充：user_check 命令纳入受控执行（复用 common 白名单或显式 allow 前缀），或参数化限制
  3. 审计日志记录每条 user_check 命令执行

### 🟡 P1 — CLI socket 0660

- `/opt/asscor/asscor-cli.sock` 0660（asscor 组可读写）——CLI 有 PermWrite/PermAdmin 命令（可发指令/改状态）
- 本地同组用户（若 asscor 组被其他服务共享）可连接 CLI 执行管理操作
- **收紧路径**：0600 root:asscor 或连接时校验 peer UID（同特权 agent 模式）

### 🟡 P1 — `--no-mtls` 生产禁用未强制

- `cmd/kernel/main.go` `--no-mtls` 仅警告"DEVELOPMENT ONLY"，无生产环境强制（如配置校验拒绝）
- 若运维误用 --no-mtls 启动，JSONRPC 全接口无加密无认证
- **收紧路径**：config.ini 显式 `[comms] require_mtls=true` 时拒绝 --no-mtls 启动

### 🟢 P2 — 检查项命令白名单硬编码于 agent 侧

- `internal/common/exec.go` 的 25 命令白名单编译进 agent 二进制，**内核端无法调整**
- 收紧方向（长期）：白名单由内核 config.ini 下发（同 user_check 同步机制），agent 本地只读引导
- 风险低（白名单是精确命令集，当前合理），属"收紧到内核端"的收尾项

---

## 四、"收紧到内核端"现状矩阵

| 攻击面 | 配置主源 | 本地可篡改？ | 内核可管控？ | 状态 |
|--------|---------|:---:|:---:|:---:|
| agent.ini | 内核 config.ini 同步（本轮） | 否（0640 root:asscor） | ✅ | 已收紧 |
| user_check/check_deltas | 内核 config.ini 同步（本轮） | 否（同步覆盖） | ✅ | 已收紧 |
| HMAC key | 内核生成/持久化 | 否（0600） | ✅ | 已收紧 |
| 证书 | 内核签发 | 否（0600/0700） | ✅ | 已收紧 |
| 特权命令白名单 | 代码硬编码 | 否 | ⚠️ 代码级 | 合理（最小面） |
| 检查命令白名单 | agent 代码硬编码 | 否 | ❌ 不可调 | P2 待收尾 |
| Web UI 暴露 | kernel config | — | ❌ 未管控 | **P0** |
| user_check 命令范围 | 内核配置 | 否 | ⚠️ 无命令约束 | **P0** |
| CLI socket 权限 | 代码硬编码 | — | ⚠️ | P1 |
| mTLS 强制 | kernel config | — | ⚠️ | P1 |

---

## 五、建议（按优先级，不立即修复）

1. **P0-1 Web UI**：默认绑定 127.0.0.1；config.ini `[webui]` 增加 listen_addr 与 auth_token；生产默认经反向代理
2. **P0-2 user_check 命令管控**：复用 common 白名单机制或显式 allow 命令集；审计记录每次执行
3. **P1 CLI socket**：0600 + peer UID 校验（对齐特权 agent 模式）
4. **P1 mTLS 强制**：config.ini `require_mtls` 配置拒绝 --no-mtls 启动
5. **P2 白名单下发**：检查命令白名单纳入内核同步通道（长期）
6. **持续**：内核同步通道（CheckConfig）后续可扩展承载更多策略（命令白名单、webui 令牌、CLI 权限）

---

## 六、审计边界说明

- 本审计基于 v0.2.3 代码树（`42b0eea`）静态盘点，未做动态渗透
- "收紧到内核端"以本轮已完成的配置 root 化 + 同步下发为基础基线
- 全部发现仅归档，不立即修复

*审计完成于 2026-08-15。仅审计归档，不修复。*
