# ASSCOR Secure Mode 安全模式白皮书

> **版本：** v1.0 | **适用：** ASSCOR v0.2.3（ASSCOR-Research-Core 分支，build-tag `securemode`） | **日期：** 2026-08-28
> **配套文档：** [Secure Mode 模块设计（SDD）](superpowers/specs/2026-08-21-secure-mode-design.md)、工程实现白皮书（§11 微内核架构）、ASSCOR 使用手册（Secure Mode 章节）
> **模块实现：** `internal/securemode/`（23 文件），build-tag：`securemode`

---

## 1. 概述

Secure Mode（安全模式）为 ASSCOR 内核（`config.ini`）与 agent（`agent.ini`）提供**默认模式**与**运行模式**双模式，目标是保护配置文件的**静态安全**（at-rest security）：

- **默认模式（default）**：配置文件明文存放，可直接修改，行为与现状完全一致。
- **运行模式（run）**：配置源文件加密为 `.enc`（明文删除），配置内容载入内存；CLI 修改配置、退出运行模式均需密码；从默认模式进入运行模式**免密**。

模式是**持久化状态**（标记文件），跨重启保持：若上次处于运行模式，重启后需输入密码解锁启动。安全边界是**"运行模式中的配置明文只在进程内存中出现"**——磁盘上永不落明文配置，破解者必须攻破进程内存才能获得配置内容。

**内核与 agent 的能力差异**：

- **内核**：完整模式管理能力（CLI 模式切换、配置修改、密码轮换）。
- **agent**：不提供良好的运行时配置能力；agent 启动时自生成临时密码，通过 mTLS 连接内核后上报密码，**自动进入运行模式**；agent 的模式切换**只允许由内核 CLI 发起**，agent 本地 CLI 不提供模式切换命令（内核托管模式）。

> 本模块为 ASSCOR-Research-Core 分支独有实验模块；默认构建（无 `securemode` tag）编译行为与旧版一致，main 分支不编译 securemode。

---

## 2. 架构

### 2.1 模块布局

独立 `internal/securemode/` 包，不侵入内核/agent 核心代码：

```
internal/securemode/
├── crypt.go        # AES-256-GCM 信封加密 + argon2id 密码派生
├── state.go        # 模式状态机（default ↔ run）+ 标记文件持久化 + 启动/崩溃恢复
├── vault.go        # 配置载入内存、明文↔密文转换、目标文件管理、内存完整性
├── controller.go   # 模式控制器：进入/退出/轮换/解锁/启动恢复/残留检测
├── cli.go          # CLI 命令注册（mode/config-set 命令族）
├── memguard.go     # 内存守卫：SHA-256 基线 + 只读快照（runtime hardening）
├── password.go     # 密码校验文件（argon2id 哈希，离线校验）
├── persist.go      # 登记表加密持久化（P0-1）
├── registry.go     # 证书指纹 → agent_id → 密码 登记表
├── securemode.go   # 常量与格式定义（魔数 "ASCM"、格式版本 1）
└── *_test.go       # 各组件单测（含 e2e 组合测试）
```

### 2.2 build-tag 开关

采用 **build-tag on/off** 挂载模式（沿用现有 `assessor_on/off.go` 模式）：

- `cmd/kernel/main.go` 与 `cmd/agent/main.go`：build-tag 文件 `securemode_on.go` / `securemode_off.go`。
- **默认 off**：无 tag 编译不引入 securemode，内核/agent 行为与旧版一致（零膨胀最小内核不受影响）。
- **on**：`go build -tags securemode` 编译完整 Secure Mode 能力（CLI `mode`/`config-set` 命令族、agent 托管、登记表）。

### 2.3 挂载点

- CLI：`internal/cli` 注册 `mode` 命令族与 `config-set` 子命令。
- agent 侧：`cmd/agent/main.go` 挂载 securemode 的 agent 托管逻辑（自生成密码、上报、自动进入运行模式）；agent 本地 CLI 仅暴露 `mode status`（只读）。

### 2.4 责任边界

| 组件 | 职责 | 不负责 |
|---|---|---|
| **kernel** | 完整模式管理（CLI 切换/改配置/密码轮换）；维护密码登记表（持久化）；指令 agent 切换；内核自身配置加密 | agent 进程内的加密执行；agent 本地 CLI |
| **agent** | 自生成临时密码；加密/解密自身 agent.ini；上报/请求密码；执行内核下发的模式指令；`mode status` 只读 | 不提供本地模式切换/配置修改；不做任何身份认证 |
| **securemode 包** | 加密原语；状态机与标记文件；三段式原子转换；内存校验与 hardening 原语；CLI 命令注册 | 不实现身份认证（复用 mTLS）；不做 agent 与 kernel 之间的策略仲裁 |

> **身份认证边界**：securemode **不重新实现任何身份认证**。连接身份、agent_id 与证书的绑定、吊销校验全部复用现有 mTLS 身份体系（`BindAgentCert`/`VerifyAgentCert`/`PeerCertFingerprintFromContext`）。securemode 只在此之上维护密码登记——**密码是解锁材料，不是认证凭据**。

---

## 3. 加密设计

### 3.1 信封加密（AES-256-GCM + argon2id）

```
配置明文 ──AES-256-GCM──→ 密文 .enc   （随机数据密钥 DEK 加密）
密码 ──argon2id──→ 派生密钥 KEK
DEK ──AES-GCM(KEK)──→ 信封（DEK 密文，随 .enc 头存储）
校验：argon2id 哈希（密码错 → 解密失败即拒绝）
```

- **DEK**（Data Encryption Key）：每次加密随机生成 32 字节，直接以 AES-256-GCM 加密配置明文（nonce 前置）。
- **KEK**（Key Encryption Key）：由口令经 **argon2id** 派生（默认参数：time=1、memory=64 MiB、threads=4、keyLen=32），用于加密 DEK——即使 KEK 被攻破也只暴露 DEK 信封，不解密出明文。
- **零化**：KEK/DEK 缓冲区使用后立即清零（zeroize），缩短密钥在内存中的存活时间。

### 3.2 `.enc` 文件格式

文件头 + 密文负载：

| 字段 | 说明 |
|---|---|
| 魔数 `ASCM`（4 字节） | 识别 Secure Mode 加密文件 |
| 版本（1 字节） | 当前格式版本 1 |
| Salt（16 字节） | argon2id 盐 |
| ArgonN / ArgonR / ArgonP / KeyLen（各 4 字节，big-endian） | argon2id 参数 |
| Envelope | KEK（AES-GCM）加密的 DEK 密文 |
| Nonce | 信封 GCM nonce |
| 负载 | DEK（AES-GCM）加密的配置明文，GCM nonce 前置 |

agent.ini 的 `[bootstrap]` 明文引导段（kernel 地址、mTLS 证书路径等连接必需项）在加密时**保留为明文**，其余段落加密——agent 重启后无需密码即可读取连接信息，再经内核下发密码解锁受保护段。

### 3.3 KDF 参数精确校验（防恶意文件）

`Decrypt`/`Verify` 对 `.enc` 头与校验文件执行**严格校验**：

- **版本必须 == 1**；魔数不符、截断、字段越界 → 拒绝。
- **KDF 四参数必须精确等于 `DefaultKDFParams()`**（N=1、R=64MiB、P=4、KeyLen=32）——v1 文件仅由 `Encrypt` 写出，恒记录默认参数；任何其他值都是攻击者可控的头输入，可能在 argon2（线程数 uint8 收窄后 <1 导致 panic）或 OOM/CPU DoS（无界内存/时间成本）上被利用，因此在任何派生之前拒绝。
- 文件大小上限 `MaxConfigSize`（10 MiB）校验。

> **目的**：防止恶意构造的 `.enc`/校验文件触发 panic、OOM 或 CPU 耗尽（DoS），是 fail-closed 语义在文件解析层的落地。

---

## 4. 崩溃安全

### 4.1 三段式原子转换

明文 → 密文的转换采用**三段式原子转换**，任何一步崩溃都不会丢配置：

```
1. 加密写入：明文 → .enc.tmp（临时文件）→ fsync 落盘
2. 验证：用内存中的密钥解密 .enc.tmp，与内存配置逐字节比对（完整性校验）
3. 提交：rename .enc.tmp → config.ini.enc（原子替换）→ 此时才删除明文
```

- 加密前先对明文做一次 **fsync**，防止文件系统缓存丢失。
- **OOM 保护**：加密在流式管道中完成（bufio 分块，不一次性读全文件）；加密中途 OOM 崩溃时明文安然无恙（未进入第 3 步）。

### 4.2 崩溃残留检测

启动时检测明文 + `.enc` 共存等残留状态：

| 残留状态 | 判定 | 处理 |
|---|---|---|
| 明文 + 孤儿 `.enc.tmp`（第 1/2 步崩溃） | 明文为权威，tmp 为惰性垃圾 | 忽略 `.enc.tmp`，明文模式正常启动 |
| 明文 + `.enc`（第 3 步崩溃窗口） | **残留（residue）** | **fail-closed**：拒绝自动处置，人工校验 `.enc` 有效性后恢复（有效则删明文，无效则回滚用明文） |
| 仅 `.enc`（无明文） | 运行模式（锁定） | 需密码解锁载入 |

> `.enc` 是权威副本：解密出的内容与内存配置逐字节比对通过即视为有效。

### 4.3 fail-closed 语义

- 磁盘写失败（fsync/rename 失败）：中止转换，保持当前状态不变，明文不删除。
- 残留状态无法自动裁决 → 拒绝启动/拒绝静默降级，提示人工处置。
- 模式标记损坏（见 §6）→ 拒绝静默降级为明文模式。

---

## 5. 内存硬化

> **定位**：本节措施是 **runtime hardening**（运行时加固），**不是防篡改保证**——它们提高攻击门槛、延迟内存取证、增加被检测概率，但不承诺能对抗拥有内核级权限（root/内核模块/物理内存访问）的攻击者。安全模型以"运行模式中的配置只在进程内存中出现明文"为边界，以下措施使**读取/改写该明文更困难、更可检测**，而非不可行。

1. **SHA-256 基线校验和**：载入内存时计算配置明文的 SHA-256 基线；运行模式期间，每次 `config` 读取 / `mode exit` 前，重新计算当前内存内容哈希并与基线比对——检测到篡改（注入/调试器改写）→ 拒绝操作并告警。
2. **只读快照**：运行模式中配置以不可变视图暴露（`config set` 通过受控通道重建新快照而非原地改写）。
3. **访问限制（hardening）**：运行模式中的明文内存区域使用 `mprotect(PROT_READ)` 只读页（Linux 下）；复用现有 `integrity.IsDebugged()` 反调试能力检测调试器附加——两者均为降低攻击便利性的加固手段，不构成完整性保证。

---

## 6. 模式状态机

### 6.1 内核状态机

```
         mode enter (免密)
  default ─────────────────────→ run
     ↑                              │
     │      mode exit (需密码)       │
     └──────────────────────────────┘
        （解密 .enc → 恢复明文 → 删 .enc）
```

| 转换 | 前置条件 | 说明 |
|---|---|---|
| `mode enter` | 默认模式 | **免密**；加密源文件（三段式原子转换），配置载入内存 |
| `mode exit` | 运行模式 | **需密码**；解密恢复明文，删除 `.enc`，回到默认模式 |
| `mode set-password` | 运行模式 | **需旧密码**；两段式轮换（先验证旧密码 → 写新校验 → 从内存重加密所有 vault，明文不落盘） |
| `mode unlock` | 重启后 run 标记 | **需密码**；解锁并载入受保护配置到内存守卫（Ruling 3） |

### 6.2 标记文件（跨重启持久化）

- 路径：`data_dir/.asscor-mode`（含版本 + 模式 + 自校验哈希，tmp+rename 原子写入）。
- **启动恢复**：
  - 标记 = default → 正常明文启动
  - 标记 = run → 提示输入密码 → 解密 `.enc` 载入内存 → 保持运行模式
  - 无标记 → 默认模式（首次使用）

### 6.3 corrupt ≠ missing（fail-closed）

| 状态 | 含义 | 行为 |
|---|---|---|
| **缺失（missing）** | 首次使用/从未进入过运行模式 | 默认模式启动（无历史状态可恢复，安全） |
| **损坏（corrupt）** | 存在但无法解析/校验失败（含哈希篡改检测） | **fail-closed**：拒绝静默降级为默认模式（否则攻击者可破坏标记文件把系统"打回"明文模式）。行为：拒绝启动或强制进入密码解锁流程，并告警"模式标记损坏，疑似篡改" |

标记文件含文件级校验和（SHA-256），任何校验失败即视为 corrupt，走 fail-closed 分支。

### 6.4 启动半态检查（M1 fail-closed 完备）

启动时对"标记文件 × vault 状态 × 校验文件"的组合做完整一致性检查，任何半态（interrupted transition）均 fail-closed：

- `default 标记 + 仅 .enc + 有校验文件` → 中断的 EnterRun（明文已删但标记未写回）→ 人工恢复。
- `default 标记 + 仅 .enc + 无校验文件` → 中断的 EnterRun（明文删除早于校验文件写入）→ 人工恢复。
- `run 标记 + 无校验文件` → 中断的 EnterRun 或篡改 → fail-closed（运行模式没有密码校验材料 = 无法解锁，拒绝启动）。

---

## 7. CLI 用法

### 7.1 内核 CLI 命令表（完整能力）

| 命令 | 说明 | 密码 |
|---|---|---|
| `mode status` | 查看当前模式、受保护文件、校验状态、已登记 agent | — |
| `mode enter --password <pw>` | 默认→运行：加密源文件，配置载入内存 | 免密（需已设置运行密码） |
| `mode exit --password <pw>` | 运行→默认：解密恢复明文 | **需密码** |
| `mode unlock --password <pw>` | kernel 重启后（run 标记）解锁并载入配置 | **需密码** |
| `mode set-password --old <pw> --new <pw>` | 设置/轮换运行密码（config.ini 与登记表同步重加密） | 需旧密码 |
| `mode agent <id> status` | 查看 agent 当前模式/登记状态 | —（内核权限） |
| `mode agent <id> enter` | 指令 agent 加密进入运行模式（已自动进入时幂等） | —（内核权限） |
| `mode agent <id> exit` | 指令 agent 解密回默认模式 | —（内核权限） |
| `mode agent <id> rotate-password` | 指令 agent 轮换密码并重新加密 | —（内核权限） |
| `config-set <key> <value> --temp\|--persist [--password <pw>]` | 修改配置（见 7.3） | 运行模式需密码 |

### 7.2 agent 本地 CLI（受限）

| 命令 | 说明 |
|---|---|
| `mode status` | 只读查看当前模式（由内核托管，本地不可切换） |
| `--mode-status` | 一次性查询 flag（`cmd/agent/main.go`），非交互式环境查询模式状态 |

agent 本地 CLI **不提供** `mode enter/exit/set-password`、`config-set` 等修改能力——配置修改与模式切换一律经内核 CLI 下发。

### 7.3 `config-set` 两段式持久化

```
config-set <key> <value>
  ├── --temp    （默认）：修改内存 + 立即生效，不落盘；重启后还原为磁盘值
  └── --persist：修改内存 + 写盘（默认模式写明文 / 运行模式写加密），
                  不立即生效——需 config reload 手动重新载入
```

- 默认模式下无 securemode 持有的内存配置：`config-set` 需 `--persist` 编辑明文文件。
- 运行模式下修改后，内存快照经完整性校验通过才提交（篡改检测）。

> **I-1 运行时回灌**：运行模式下 `config-set`/`mode unlock` 修改内存配置后，通过 `ModeCLI.OnConfigChanged` 钩子回灌内核运行时（`config.Parse` → `SetConfigObj` + `assessor.ReloadConfig`），`--temp` 即时生效；config watcher 经 `SetConfigLoader` 在 run 模式下读取内存守卫，SIGHUP/轮询重载不绕过加密配置。

---

## 8. Agent 内核托管

### 8.1 生命周期

```
agent 启动（磁盘 agent.ini 为明文 .ini + [bootstrap] 引导段）
  │
  ├─ 读取明文引导段（kernel 地址、mTLS 证书路径等连接必需项）
  ├─ 连接内核（mTLS）
  ├─ 自生成随机临时密码（每次重启重新生成，不落盘，仅内存）
  ├─ 加密 agent.ini → agent.ini.enc（三段式原子转换），删除明文
  ├─ 通过 mTLS 心跳上报密码给内核（内核以请求证书指纹为主键登记
  │    agent_id → 密码；指纹不一致的伪造登记在传输层被拒）
  └─ 自动进入运行模式（配置驻留内存，只读快照 + SHA-256 基线）
```

- **密码生命周期**：agent 密码是**临时解锁秘密**（ephemeral unlock secret），不是长期秘密——只用于解锁本次运行会话的 `.enc`，生命周期与单次进程运行绑定，随重启自然轮换。agent 磁盘上**不落任何密码材料**。
- **agent 重启解锁**：重启时读明文引导段连接内核 → 内核下发该 agent 当前登记的密码 → 解密受保护段 → 进入运行模式（agent 自身无交互式状态机，状态由内核驱动）。

### 8.2 指令通道

- **unlock 密码下发**：走**心跳响应通道**（`HeartbeatResponse.SecureModeNoSecret` 等信号）——锁定态 agent 无 `hmac_key` 无法校验 pending command，故解锁类指令不依赖命令通道。
- **exit / rotate-password**：走 **pending command** 通道（`securemode_exit` / `securemode_rotate`）下发；exit 后经 `reloadProtectedConfig` 恢复 `hmac_key`，重新具备命令校验能力。

### 8.3 自恢复（I-2）

agent 锁定态自恢复：**3 次心跳未解锁**或收到 `SecureModeNoSecret` 信号 → 自生成新密码 + `Vault.ReencryptOverwrite` 重加密 `.enc`（不读取旧 `.enc`）+ `reported=false` 重新上报；旧受保护内容按 spec §8.2 丢弃。等价于全新登记。

### 8.4 身份认证边界

- 登记/解锁/切换请求的证书指纹取自 `kernel.PeerCertFingerprintFromContext(ctx)`（与现有 Register/Heartbeat 的 identity 硬化同一机制）。
- 内核**先校验请求携带的证书指纹是否已登记**——若攻击者伪造 agent_id 上报密码，但其证书指纹与登记表不一致，内核在传输层直接拒绝该"非法登记"请求，不进入应用层逻辑。
- **一证书一身份**：一个证书只能登记一个 agent 身份，与现有 `BindAgentCert` 约束一致。

---

## 9. 登记表持久化（P0-1）

内核维护 **`证书指纹（SHA-256 hex）→ agent_id → 密码`** 三元组登记表：

- **键结构**：以 mTLS 客户端证书指纹为主键，agent_id 与密码挂在其下——而非仅 `agent_id → 密码`（防线从应用层压到传输层）。
- **持久化**：登记表以**加密形式落盘**（`data_dir/.asscor-secrets.enc`，用内核自身运行模式密钥信封加密）。
  - kernel 处于 **run 模式**：登记表加密持久化。
  - kernel 处于 **default 模式**：登记表不持久化（此时无 agent 处于 run 模式的预期）。
- **kernel 重启恢复**：
  1. kernel 启动 → 读自身模式标记：
     - kernel 为 **default**：登记表为空，agent 各自走"重启→自生成新密码→重新上报"流程。
     - kernel 为 **run**：用内核密码解锁 → 解密持久化登记表 → 恢复 `指纹→agent_id→密码` 三元组。
  2. kernel 恢复登记表后，处于 run 模式的 agent 重启时即可下发对应密码解锁；若 agent 已重新生成密码（其自身先重启且内核登记仍有效），则以内核登记的最新版本为准（agent 上报时覆盖旧登记，以请求指纹+时间戳排序）。
  3. **死锁防护**：kernel 重启后若登记表持久化失败/解密失败（fail-closed）→ kernel **拒绝启动 run 模式**，且已持久化的登记表**不删除**——人工处置路径（用内核密码恢复）。
- **agent 单方重启（kernel 未重启）**：agent 重启后自生成**新**密码上报 → 内核更新该指纹下的登记（新密码覆盖旧密码）→ 与旧密码相关的解锁请求立即失效。
- **密码轮换联动**：kernel `mode set-password` 轮换时，登记表（`.asscor-secrets.enc`）以新运行密钥同步重加密；退出运行模式时移除登记表文件。

---

## 10. 构建与部署

### 10.1 构建命令

默认构建（无 tag）不含 securemode，行为与旧版一致：

```bash
go build ./cmd/kernel ./cmd/agent
```

启用 Secure Mode 完整能力：

```bash
go build -tags securemode ./cmd/kernel ./cmd/agent
```

与全部产品模块 tag 联合使用（完整功能内核）：

```bash
go build -tags "securemode,heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" -o ASSCOR-kernel ./cmd/kernel/
```

### 10.2 部署要点

- **受保护文件**：内核 `config.ini`（`-config` 参数路径）；agent `agent.ini`（`-config` 参数路径，仅受保护段加密，`[bootstrap]` 明文引导段保留）。
- **运行模式磁盘布局**（data_dir 下）：
  - `.asscor-mode` — 模式标记（跨重启）
  - `.asscor-pw` — 密码校验文件（argon2id 哈希 + KDF 参数）
  - `.asscor-secrets.enc` — agent 登记表（加密持久化，仅 run 模式）
  - `<config>.enc` — 加密的配置文件（明文已删除）
- **重启解锁**：run 标记下 kernel 启动后执行 `mode unlock --password <pw>` 解锁载入配置后，服务才继续（Ruling 3）。
- **升级/降级**：退出运行模式（`mode exit`）恢复明文后，可正常进行版本升级；升级后如需保持加密，重新 `mode enter`。
- **人工处置路径**：崩溃残留 / 登记表损坏 / 标记损坏等 fail-closed 场景均保留现场文件（明文备份或 `.enc`），按 §4/§6/§9 指引人工校验恢复，不自动删除任何可能承载配置的文件。

---

## 11. 安全模型总结

| 威胁面 | 防护 | 定位 |
|---|---|---|
| 配置文件静态窃取（磁盘读取/备份窃取） | AES-256-GCM 信封加密 + argon2id | **保证**（安全边界：明文只在进程内存） |
| 密码暴力破解 | argon2id 内存硬 KDF（64 MiB）+ 密码错误拒绝 | 提高成本 |
| 恶意 `.enc`/校验文件（panic/OOM/CPU DoS） | KDF 四参数 + 版本精确校验、大小上限 | fail-closed 拒绝 |
| 崩溃导致配置丢失 | 三段式原子转换 + fsync + 残留检测 | 任何一步崩溃不丢配置 |
| 标记文件篡改降级 | corrupt ≠ missing，fail-closed 拒绝降级明文 | 检测并阻断 |
| 进程内存读取明文 | mprotect 只读页 + 反调试 + SHA-256 基线 | **runtime hardening，非防篡改保证** |
| 伪造 agent 登记 | 证书指纹主键 + 传输层校验 | 防线压到传输层 |

> **非目标（YAGNI）**：不做 TPM/系统 keyring 集成；不做多用户密码体系（单密码即解锁唯一途径）；不做 agent 与 kernel 之间的加密配置同步（agent 配置独立保护）；不重新实现身份认证（复用 mTLS）；不承诺内存防篡改保证；agent 密码不作长期凭据。

---

## 12. 参考

- [Secure Mode 模块设计（SDD，2026-08-21）](superpowers/specs/2026-08-21-secure-mode-design.md)
- README.md 「Secure Mode（实验性，build-tag：securemode）」章节
- 工程实现白皮书 §11 微内核架构（§11.3 插件表 securemode 行）
- ASSCOR 使用手册「Secure Mode 安全模式」章节（操作手册视角）
