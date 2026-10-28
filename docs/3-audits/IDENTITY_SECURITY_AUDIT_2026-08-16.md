# ASSCOR 自身身份安全审计 — 机器身份 / 影子身份 / 身份孤岛

**日期**: 2026-08-16 | **版本**: v0.2.3 | **性质**: 审计 + 归档（不修复）
**前提**: ASSCOR 是安全评估工具且多主机部署（kernel 集中管理所有 agent），必然成为攻击者的高价值目标——拿下内核 = 控制全部受管主机的评估与响应。本审计聚焦三类现代身份威胁在 ASSCOR 自身架构中的表现。

---

## 一、执行摘要

| 维度 | 结论 |
|------|------|
| 机器身份（服务账户/密钥） | ✅ 分层合理（asscor+root）、密钥 0600、HMAC 90 天轮换；⚠️ 无证书吊销机制、adapter 凭证机制不统一 |
| 影子身份（未管理入口） | ⚠️ 扩展/插件/脚本受控执行（多重防护）✅；但连接器凭证持有是"高价值目标放大器" |
| 身份孤岛（多身份系统） | ❌ **三种连接身份各自独立、host_id 与证书无绑定、无身份事件统一审计** — 最薄弱 |
| **总评** | **身份分层与密钥卫生良好；身份一致性（证书↔host_id↔session 绑定）与身份可见性是主要缺口** |

---

## 二、A. 机器身份（服务账户、密钥、AI 智能体）

### A1. 服务账户分层 ✅ 基本合理

| 进程 | 用户 | 权限面 | 评估 |
|------|------|--------|:---:|
| kernel / agent 主进程 | `asscor`（systemd User=asscor） | 非 root | ✅ |
| privileged agent | `root`（systemd User=root） | 仅 socket 激活 + SO_PEERCRED + 白名单（isolate/deisolate） | ✅ 最小权限 |
| 扩展/插件执行 | asscor（kernel 进程派生） | 受控 | ✅ |

### A2. 密钥管理

| 密钥 | 存储 | 轮换/生命周期 | 评估 |
|------|------|------------|:---:|
| HMAC key | certs/ 0600 | 90 天自动轮换（双密钥窗口） | ✅ |
| mTLS 证书 | certs/ 0600/0700 | 过期校验；**无吊销机制** | ⚠️ |
| assessment key | certs/ 0600 | — | ✅ |
| SPC/CTI API keys | env 优先（`os.Getenv`）+ 配置 | — | ✅ 机制统一 |
| **adapter 连接器凭证** | config.ini `${NETBOX_TOKEN}` 等占位符 | **无 env 展开代码（无 ExpandEnv）、无轮换机制** | ⚠️ |

### A3. AI 智能体身份
- 当前无 AI 集成（v0.3.0 方向）；**一旦引入 AI 智能体（黑盒阵列/Research Core），其 API 密钥与执行身份将新增机器身份面**——需在立项时纳入治理

### A4. 关键缺口：无证书吊销（P1）

- agent 证书被攻破后**无法单独吊销**——只能删除 certs/ 全局重生（影响所有 agent）
- 证书与 host_id 无绑定（见 C1）——吊销/隔离粒度受限

---

## 三、B. 影子身份（未授权/未管理入口）

### B1. 扩展执行受控 ✅（多重防护）

| 载体 | 执行身份 | 防护 | 评估 |
|------|---------|------|:---:|
| extmgr 扩展（二进制/脚本） | asscor | SHA-256 checksum + 30s 超时 + 路径/符号链接防护 + 四档执行策略 | ✅ |
| extmgr 扩展检查命令 | asscor | `IsShellCommandAllowed` 整串白名单 | ✅ |
| pluginsdk 插件 | 独立进程 | JSON-RPC + 进程隔离 + panic 恢复 | ✅ |
| adapter 脚本 | kernel | validateScriptPath 四层校验 | ✅ |
| user_check 命令 | agent | 无 shell 直接 exec + 首词白名单（v0.2.3 已修复） | ✅ |

### B2. 高价值目标放大器：连接器凭证持有（P1）

- ASSCOR 持有外部系统凭证（netbox.api_token / wazuh_siem.password / snipe_it / jira / sourcemanager api_token）
- **攻击者拿下 kernel（asscor 用户可读 config.ini？—— config.ini 已 0640 root:asscor，asscor 可读）→ 可提取外部系统凭证 → 横向进入 NetBox/Wazuh/等**——ASSCOR 成为进入企业其他系统的跳板
- 缓解现状：占位符（非明文）✅ + config root 只读 ✅；但**凭证价值集中 + 无独立密钥管理/加密存储**

### B3. CLI/管理入口 ✅（v0.2.3 已收紧）
- CLI socket 0600 + SO_PEERCRED（root/asscor）✅

---

## 四、C. 身份孤岛（最薄弱 — P0）

### C1. 三种连接身份各自独立，无统一身份模型

```
agent → kernel    : mTLS 证书（agent.crt）+ host_id + HMAC session
CLI   → kernel    : Unix socket + peer UID（root/asscor）
privileged → agent: SO_PEERCRED + 白名单
```

**问题**：
- **host_id 与证书无绑定**：agent 注册（`Register`）只校验 host_id 格式 + mTLS 证书链有效；**持有合法 agent.crt 的进程可注册任意 host_id**（证书不携带/不校验 host_id）——一个被攻破的 agent 证书可冒充其他主机上报
- **三种身份无关联视图**：证书身份 / peer UID / HMAC session 各自验证，无"一个 agent = 证书+host_id+session"的统一实体概念
- **审计分散**：auditlog 拦截器（JSONRPC 层）+ 模块级日志，无身份事件聚合（谁用哪个证书在何时注册/心跳/执行命令）

### C2. 凭证生命周期不完整

| 凭证 | 轮换 | 吊销 | 绑定 |
|------|:---:|:---:|:---:|
| HMAC key | ✅ 90 天 | — | session |
| mTLS 证书 | ⚠️ 仅过期 | ❌ 无 CRL | ❌ 不绑定 host_id |
| adapter 凭证 | ❌ | ❌ | 外部系统 |

---

## 五、问题分级汇总

| 等级 | ID | 问题 |
|:---:|:---:|------|
| **P0** | I-01 | **host_id 与证书无绑定**：合法 agent.crt 可冒充任意 host_id 注册/上报（身份伪造面） |
| **P0** | I-02 | **无身份事件统一审计**：三种身份通道各自验证，无可追溯的"身份→动作"统一视图（孤岛） |
| **P1** | I-03 | **无证书吊销机制**：被攻破证书无法单独吊销（只能全局重生） |
| **P1** | I-04 | **adapter 连接器凭证集中持有**：kernel 被攻破 → 外部系统凭证泄露（高价值目标放大器）；无加密存储/轮换 |
| **P1** | I-05 | **adapter 凭证机制与 SPC/CTI 不统一**：SPC/CTI 用 env 优先，adapter 用配置占位符且无展开代码 |
| **P2** | I-06 | 扩展包是"外部代码以服务身份运行"载体（受控但集中）：安装来源需可审计/可撤销 |
| **P2** | I-07 | AI 智能体身份治理未规划（v0.3.0 引入时需定义） |

---

## 六、建议（按优先级，不立即修复）

1. **P0 I-01**：agent 证书携带/绑定 host_id（签发时嵌入或注册时校验 host_id ↔ 证书映射，heartbeat 维护该映射并拒绝不匹配）
2. **P0 I-02**：身份事件统一审计——注册/心跳/命令执行统一记录（身份类型 + 标识 + 动作 + 时间），可查询单一视图
3. **P1 I-03**：证书吊销列表（CRL）或按 host 撤销（维护 host_id → 证书序列号映射，吊销即拒绝）——**✅ 已实现（commit `35236cc`）并线上验证（见 8.3）**
4. **P1 I-04/05**：连接器凭证统一走环境变量/密钥文件（对齐 SPC/CTI 的 env 优先机制），移除配置占位符歧义；评估独立密钥存储——**✅ 已实现（commit `6114e83`、`7d59190`）并线上验证（见 8.4）**
5. **P2**：扩展安装来源审计 + AI 身份治理随 v0.3.0 立项

---

## 八、修复验证与后续发现（2026-08-16 晚，专项排查）

### 8.1 I-01 修复的线上验证（真机 10.0.0.1，Ubuntu 24.04）

I-01 已实施修复：mTLS 对端证书指纹绑定 host_id（`BindAgentCert`/`VerifyAgentCert`），
持久化到 `<data_dir>/heartbeat_identity.json`（0600，temp+rename）。线上验证结果：

| 场景 | 结果 |
|------|------|
| 真证书首次注册（`45869aa3...`） | ✅ accepted，绑定持久化 |
| 伪造证书注册（同 CA，CN "ASSCOR Agent evil"，`8936cf10...`） | ✅ 拒绝：`certificate identity conflict: host ... is bound to a different certificate`（audit ERR） |
| 真证书恢复后重注册（同指纹） | ✅ accepted，绑定不变 |

### 8.2 专项排查发现的严重缺陷（已修复）：剪除丢失身份锚定

**线上异常**：07:19:52 与 07:26:19 两次出现伪造证书注册被 accepted 并覆写
identity.json，即使 kernel 日志显示 07:19:14 / 07:24:07 已加载绑定（count=1）。

**根因**（`internal/heartbeat/heartbeat.go`）：持久化绑定在 kernel 重启后由
`loadIdentityLocked` 恢复到 `AgentRecord`，但该 record 的 `LastSeen` 为零值且
`Active=false`。监控循环（10s tick）的 `checkTimeouts` → `pruneDeadAgents`
（cutoff 1h，零值 LastSeen 必然早于）在 agent 重连前就把整个 record **连同
`CertFingerprint` 一并删除**。此后任意证书的 Register 都被当作"首次绑定"
接受并覆写持久化文件——身份锚定形同虚设。

**修复**（commit `f58a5a6`）：
- `pruneDeadAgents` 永不删除携带 `CertFingerprint` 的锚定 record（身份锚定
  与存活跟踪解耦，锚定在显式吊销前永久有效）；
- `checkTimeouts` 跳过 `LastSeen` 为零值的已恢复锚定（避免 kernel 启动即误报超时）。

**回归测试**：`internal/heartbeat/identity_prune_test.go`（5 个场景：reload→
monitor→prune 后锚定存活且伪造证书被拒、长期离线绑定主机锚定保留、无绑定死
记录仍可剪除、零值锚定不误报超时、超时事件后锚定仍存活）。

**修复后线上复验**（决定性场景）：停 agent → 重启 kernel（加载 45869aa3）→
agent 保持下线 15s 越过监控 tick → identity.json 不变、无 prune 记录 → 伪造
证书注册**被拒**、identity.json 未被覆写 → 恢复真证书重注册 accepted。全链路
通过，两服务 active。

### 8.3 证书吊销 I-03 已实现并线上验证（commit `35236cc`）

**实现**（`internal/heartbeat` + `internal/cli` + `internal/comms`）：
- 吊销按证书 SHA-256 指纹（与身份绑定同一粒度）：`RevokeCert`/`UnrevokeCert`/
  `IsCertRevoked`/`ListRevokedCerts`，持久化 `<data_dir>/revoked_certificates.json`
  （0600，temp+rename，重启后加载）；
- 吊销时自动解绑所有绑定该指纹的 host（可用新签发证书重新注册），指纹本身
  永久拒绝——任何证书都无法再冒充该身份；
- 强制点全覆盖：Register 显式拒绝（`certificate revoked`）、VerifyAgentCert
  对已吊销指纹恒 false（覆盖 Heartbeat）、BindAgentCert 深度防御；
- CLI `cert` 命令：`revoke <fp> [--reason]`（admin 权限）/ `unrevoke` /
  `revocations`，支持粘贴 openssl 冒号格式指纹。

**线上验证（10.0.0.1，真机）**：
| 场景 | 结果 |
|------|------|
| CLI 吊销伪造证书（`8936cf10...`，--reason=compromised-test） | ✅ 持久化到 revoked_certificates.json |
| 伪造证书注册 | ✅ 拒绝：`certificate revoked: fingerprint "8936cf10..."`（audit ERR） |
| 重启 kernel 后吊销列表 | ✅ 仍加载（`loaded revoked certificates count=1`） |
| 吊销真证书（`45869aa3...`） | ✅ 自动解绑：identity.json 清空 + 日志 `identity unbound` |
| 真证书 agent 重连 | ✅ 拒绝（certificate revoked） |
| 解除吊销后同证书重注册 | ✅ accepted，重新绑定并持久化（误吊销零损失恢复） |
| `cert revocations` 脚本化输出 | ✅ 干净可解析（修复 CLI 客户端显示竞态，commit `e8cf692`） |

**遗留（P2 I-06/07）**：扩展来源审计、AI 身份治理——见第九节。

### 8.4 连接器凭证统一 I-04/I-05 已实现并线上验证（commit `6114e83`、`7d59190`）

**根因**：配置模板与文档早已声明 `NETBOX_TOKEN`/`WAZUH_PASSWORD` 等环境
变量优先，但代码从未实现展开——`${NETBOX_TOKEN}` 占位符被**原样**传给 API
调用；adapter 连接器与 SPC/CTI 的凭证机制不统一（I-05），凭证集中在
config.ini 明文（I-04）。

**实现**（`internal/common/credentials.go` + `internal/config` + `internal/cti`）：
- `ExpandEnv`：`${VAR}` 占位符展开；未解析时保留原样并告警（可见的配置
  错误，而非静默空凭证），非标识符内容原样透传；
- `ResolveCredential`：统一优先级 **env > 密钥文件 > 配置值**——密钥文件支持
  `<ENV>_FILE` 环境变量或 `<key>_file` 配置项（docker secrets 风格），返回
  来源供审计日志；
- `IsSecretKey`/`SecretEnvName`：凭证键识别与 `<SECTION>_<KEY>` 约定命名；
- `resolveAdapterSecrets`：加载时对所有 adapter 值展开占位符；凭证键按文档
  短名表（`NETBOX_TOKEN`/`SNIPEIT_TOKEN`/`WAZUH_PASSWORD`/`JIRA_TOKEN`/
  `RUNDECK_TOKEN`/`FREEIPA_TOKEN`/`KEYCLOAK_TOKEN`）或约定名做 env/文件覆盖；
  来源写审计日志（只记来源与长度，**不记值**）；
- SPC NVD/MISP/CNNVD 与 CTI OTX/MISP 改用同一解析器（SPC 顺带获得 `_FILE`
  支持）；adapter 连接器代码零改动（中心化解析）。

**线上验证（10.0.0.1，真机，systemd 注入 env + 临时 [netbox] 段）**：
| 场景 | 结果 |
|------|------|
| `NETBOX_TOKEN` env 已设置 | ✅ `adapter credential loaded from environment variable` key=netbox.api_token |
| `api_token_file` 指向可读文件（无 env） | ✅ `adapter credential loaded from secret file`（08:04:26） |
| 文件存在但权限拒绝（root 0600，asscor 运行） | ✅ `credential secret file unreadable, falling back` + 回退配置值 |
| 文件缺失 | ✅ 同上，回退 + 告警 |
| `${NETBOX_TOKEN}` 未设置 | ✅ 占位符保留原样 + `placeholder unresolved` 告警（恰好一次，commit `7d59190`） |

**测试**：`common/credentials_test.go` + `config/credentials_test.go` 共 14 个
场景（展开/优先级/文件回退/约定命名/env 覆盖/SPC 对齐/非密钥展开）；全量
测试通过。

**遗留（P2 I-06/07）**：扩展来源审计、AI 身份治理——见第九节。

---

## 九、审计边界

- 基于 v0.2.3 代码树（`ed86fd9`）静态盘点，未做动态渗透
- 已确认的良好基线：服务账户分层、HMAC 轮换、证书 0600、扩展多重防护、CLI peer 校验（v0.2.3 收紧）
- 全部发现仅归档，不立即修复

*审计完成于 2026-08-16。仅审计归档，不修复。*
