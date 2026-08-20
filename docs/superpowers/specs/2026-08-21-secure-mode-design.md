# Secure Mode 模块设计（ASSCOR-Research-Core）

- 日期：2026-08-21
- 分支：ASSCOR-Research-Core
- 状态：已获用户批准（2026-08-21）

## 1. 目标

为 ASSCOR 内核与 agent 提供**默认模式**与**运行模式**双模式：

- **默认模式**：config.ini / agent.ini 明文存放，可直接修改，行为与现状一致。
- **运行模式**：配置文件源文件加密为 `.enc`（明文删除），配置内容载入内存；CLI 修改配置、退出运行模式均需密码；从默认模式进入运行模式**免密**。
- 模式为持久化状态（标记文件），跨重启保持；若上次处于运行模式，重启后需输入密码解锁启动。
- CLI 提供一定程度的配置修改能力（`config set`），支持"临时不落盘立即生效"与"落盘但不立即生效需手动重载"两种持久化选项。
- **内核与 agent 的能力差异（2026-08-21 补充）**：
  - **内核**：完整模式管理能力（CLI 模式切换、配置修改、密码轮换）。
  - **agent**：不提供良好的运行时配置能力；agent 启动时自生成密码，通过 mTLS 连接内核后上报密码，**自动进入运行模式**；agent 的模式切换**只允许由内核 CLI 发起**，agent 本地 CLI 不提供模式切换命令。

## 2. 方案选型（已确认）

- **方案 A**：独立 `internal/securemode` 包 + CLI 命令接入（用户批准）。
- 加密：**AES-256-GCM** 信封加密 + **argon2id** 密码派生（用户批准）。
- 密码校验材料：哈希（argon2id）校验 + 信封加密（用户批准）。
- 作用范围：内核 `config.ini` + agent `agent.ini`（用户批准）。
- CLI 能力：完整 `config` 子命令集 `view/set/encrypt/decrypt/rotate`（用户批准）。
- 模式生命周期：持久化标记，跨重启保持（用户批准）。

## 3. 模块布局

```
internal/securemode/
├── crypt.go        # AES-256-GCM 信封加密 + argon2id 密码派生
├── state.go        # 模式状态机（default ↔ run）+ 标记文件持久化 + 启动/崩溃恢复
├── vault.go        # 配置载入内存、明文↔密文转换、目标文件管理、内存完整性
├── cli.go          # CLI 命令注册（mode/config 子命令）
└── *_test.go       # 各组件单测
```

挂载点：

- `cmd/kernel/main.go` 与 `cmd/agent/main.go`：build-tag 文件 `securemode_on.go` / `securemode_off.go`（沿用现有 `assessor_on/off.go` 模式）。
- CLI：`internal/cli` 注册 `mode` 命令族与 `config set/encrypt/decrypt/rotate` 子命令。
- **agent 侧**：`cmd/agent/main.go` 挂载 securemode 的 agent 托管逻辑（自生成密码、上报、自动进入运行模式）；agent 本地 CLI 仅暴露 `mode status`（只读），**不暴露** `mode enter/exit/set-password` 与 `config encrypt/decrypt`。

## 3.1 agent 侧架构（内核托管模式）

agent 不提供良好运行时配置能力，其模式生命周期由内核托管：

```
agent 启动（磁盘 agent.ini 为明文 .ini + 引导段）
  │
  ├─ 读取明文引导段（kernel 地址、mTLS 证书路径等连接必需项）
  ├─ 连接内核（mTLS）
  ├─ 自生成随机密码（每次重启重新生成，不落盘，仅内存）
  ├─ 加密 agent.ini → agent.ini.enc（三段式原子转换），删除明文
  ├─ 通过 mTLS 上报密码给内核（内核以**请求证书指纹**为主键登记
  │    agent_id → 密码；指纹不一致的伪造登记在传输层被拒）
  └─ 自动进入运行模式（配置驻留内存，只读快照 + 校验和基线）
```

- **密码生命周期**：每次重启重新生成；agent 崩溃/重启后旧密码失效，内核侧自动更新登记。agent 磁盘上**不落任何密码材料**。
- **agent 重启解锁**：agent.ini 拆为两层——极小**明文引导段**（kernel 地址、mTLS 证书路径等连接必需项）+ **受保护段**（.enc）；重启时读明文引导段连接内核 → 内核下发该 agent 当前登记的密码 → 解密受保护段 → 进入运行模式。
- **模式切换**：只允许内核 CLI 发起（`mode agent <id> enter|exit` 或经 agent 命令通道下发指令）；agent 本地 CLI 无切换能力。
- **agent.ini 明文引导段**位于文件头部固定格式段（如 `[bootstrap]`），加密时保留为明文，其余段落加密。

## 4. 核心概念

| 模式 | 磁盘文件 | 内存 | 修改配置 | 切换 |
|---|---|---|---|---|
| **默认 (default)** | config.ini/agent.ini 明文 | 正常加载 | 直接改明文，立即生效 | `mode enter`（免密） |
| **运行 (run)** | `.enc` 密文（源文件加密后删除） | 明文配置驻留内存（只读快照） | 需密码；可选临时/落盘 | `mode exit`（需密码）→ 解密回明文 |

## 5. 加密设计（信封加密）

```
配置明文 ──AES-256-GCM──→ 密文 .enc   （随机数据密钥 DEK 加密）
密码 ──argon2id──→ 派生密钥 KEK
DEK ──AES-GCM(KEK)──→ 信封（DEK 密文，随 .enc 头存储）
校验：argon2id 哈希（密码错 → 解密失败即拒绝）
```

`.enc` 文件头包含：魔数、版本、argon2id 参数（salt、N、r、p）、DEK 密文信封、GCM nonce/tag。校验材料（argon2id 哈希 + salt）存于模式标记文件（或独立校验文件）。

## 6. 崩溃安全（加密后删除的原子性）

采用**三段式原子转换**，任何一步崩溃都不会丢配置：

```
1. 加密写入：明文 → .enc.tmp（临时文件）→ fsync 落盘
2. 验证：用内存中的密钥解密 .enc.tmp，与内存配置逐字节比对（完整性校验）
3. 提交：rename .enc.tmp → config.ini.enc（原子替换）→ 此时才删除明文
```

- **崩溃恢复**：进程在任何点崩溃，明文仍保留（第 3 步前明文从未被删除）；重启后检测到 `.enc` + 明文共存 → 走恢复流程（校验 `.enc` 有效则删明文，无效则回滚用明文）。
- **OOM 保护**：加密在流式管道中完成（bufio 分块，不一次性读全文件）；10MB 上限配置文件的峰值内存可控；加密中途 OOM 崩溃时明文安然无恙（未进入第 3 步）。
- 加密前先对明文做一次 **fsync**，防止文件系统缓存丢失。

## 7. 内存防篡改（明文配置驻留内存）

1. **基线校验和**：载入内存时计算配置明文的 SHA-256 基线；运行模式期间，每次 `config` 读取 / `mode exit` 前，重新计算当前内存内容哈希并与基线比对——检测到篡改（注入/调试器改写）→ 拒绝操作并告警。
2. **只读快照**：运行模式中配置以不可变视图暴露（`config set` 通过受控通道重建新快照而非原地改写）。
3. **访问限制**：运行模式中的明文内存区域使用 `mprotect(PROT_READ)` 只读页（Linux 下）；复用现有 `integrity.IsDebugged()` 反调试能力检测调试器附加。

## 8. 状态机

### 8.1 内核状态机

```
         mode enter (免密)
  default ─────────────────────→ run
     ↑                              │
     │      mode exit (需密码)       │
     └──────────────────────────────┘
        （解密 .enc → 恢复明文 → 删 .enc）
```

- **启动恢复**：读取 `data_dir/.asscor-mode` 标记
  - 标记 = default → 正常明文启动
  - 标记 = run → 提示输入密码 → 解密 .enc 载入内存 → 保持运行模式
  - 无标记 → 默认模式（首次使用）
- **崩溃恢复**：启动时检测明文 + .enc 共存 → 进入恢复流程（校验 .enc，有效则删明文；无效则回滚明文并告警）。

### 8.2 agent 状态机（内核托管）

agent 自身无交互式状态机，状态由内核驱动：

- **启动**：读明文引导段 → 连内核 → 自生成密码 → 加密 agent.ini → 上报 → 运行模式（自动）。
- **重启**：读明文引导段 → 连内核 → 请求密码 → 内核下发登记密码 → 解密 → 运行模式。
- **内核 CLI 操作**：`mode agent <id> exit` → 内核向 agent 下发退出指令（经 mTLS 通道）→ agent 用登记密码解密恢复明文 → 回到默认模式并通知内核。
- **密码轮换**：内核 CLI `mode agent <id> rotate-password` → agent 生成新密码 → 上报内核更新登记 → 重新加密 agent.ini。

## 9. CLI 命令

### 9.1 内核 CLI（完整能力）

| 命令 | 说明 | 密码 |
|---|---|---|
| `mode status` | 查看当前模式、受保护文件、校验状态 | — |
| `mode enter` | 默认→运行：加密源文件，配置载入内存 | 免密 |
| `mode exit` | 运行→默认：解密恢复明文 | **需密码** |
| `mode set-password` | 设置/轮换密码（rotate） | 需旧密码 |
| `config set <key> <value>` | 修改内存配置 | 运行模式需密码 |
| `config encrypt` | 加密指定文件 | 需密码 |
| `config decrypt` | 解密指定文件 | 需密码 |
| `mode agent <id> status` | 查看 agent 当前模式/登记状态 | — |
| `mode agent <id> enter` | 指令 agent 加密进入运行模式（已自动进入时幂等） | —（内核权限） |
| `mode agent <id> exit` | 指令 agent 解密回默认模式 | —（内核权限） |
| `mode agent <id> rotate-password` | 指令 agent 轮换密码并重新加密 | —（内核权限） |

### 9.2 agent 本地 CLI（受限）

| 命令 | 说明 |
|---|---|
| `mode status` | 只读查看当前模式（由内核托管，本地不可切换） |

agent 本地 CLI **不提供** `mode enter/exit/set-password`、`config encrypt/decrypt/set` 等修改能力——配置修改与模式切换一律经内核 CLI 下发。

### config set 的两段式持久化

```
config set <key> <value>
  ├── --temp   （默认）：修改内存 + 立即生效，不落盘；重启后还原为磁盘值
  └── --persist：修改内存 + 写盘（默认模式写明文 / 运行模式写加密），
                  不立即生效——需 config reload 手动重新载入
```

## 10. 受保护文件清单

- 内核：`config.ini`（`-config` 参数路径）
- agent：`agent.ini`（`-config` 参数路径）——仅**受保护段**加密，`[bootstrap]` 明文引导段保留
- 运行模式中 `config set` 写盘时按当前模式选择明文/密文格式

## 10.1 内核侧密码登记（agent 托管）

内核维护 **`证书指纹 → agent_id → 密码`** 三元组登记表（运行内存 + 可选加密持久化）：

- **键结构**：以 mTLS 客户端证书指纹（SHA-256，hex）为主键，agent_id 与密码挂在其下——而非仅 `agent_id → 密码`。
- **来源**：agent 启动时经 mTLS 上报；agent 轮换时更新。
- **传输层校验（安全防线下压到传输层）**：登记/解锁/切换请求的证书指纹取自 `kernel.PeerCertFingerprintFromContext(ctx)`（与现有 Register/Heartbeat 的 identity 硬化 I-01/I-03 同一机制）。内核**先校验请求携带的证书指纹是否已登记**——若攻击者伪造 agent_id 上报密码，但其证书指纹与登记表不一致，内核在传输层直接拒绝该"非法登记"请求，不进入应用层逻辑。
- **使用**：agent 重启时下发解锁；`mode agent <id> exit` 时下发解密指令。
- **保护**：登记表仅内核进程内存持有；若需持久化（跨内核重启保留），用内核自身运行模式密钥加密落盘。

> 设计理由（用户 2026-08-21）：以证书指纹为主键把防线从应用层压到传输层。伪造的 agent_id 无法通过指纹校验，非法登记在底层即被拒绝；也保证一个证书只能登记一个 agent 身份，与现有 BindAgentCert 的"一证书一身份"约束一致。

## 11. 错误处理

- 密码错误（argon2id 校验失败 / GCM 解密失败）：拒绝操作，记录告警，不修改任何状态。
- 解密完整性校验失败：拒绝载入，提示配置可能被篡改或损坏；保留 `.enc` 与（如有）明文备份供人工处置。
- 模式标记文件损坏/缺失：降级为默认模式并告警。
- 磁盘写失败（fsync/rename 失败）：中止转换，保持当前状态不变，明文不删除。

## 12. 测试计划

- `crypt_test.go`：信封加密往返、错误密码解密失败、篡改密文检测（GCM tag 失败）、argon2id 参数边界、引导段保留加密。
- `state_test.go`：状态机转换、标记文件持久化、崩溃恢复场景（明文+.enc 共存各分支）、无标记默认。
- `vault_test.go`：流式加密 OOM 安全（大文件分块）、内存基线校验和、篡改检测、只读快照。
- `cli_test.go`：CLI 命令注册与解析、`config set --temp/--persist` 两段式持久化、密码提示流程（mock stdin）。
- `agent_test.go`：agent 自生成密码流程、mTLS 上报、重启后内核下发密码解锁、内核 CLI 指令 agent 切换（mock mTLS 通道）。
- `registry_test.go`：密码登记表——指纹为主键；伪造 agent_id（指纹未登记/不匹配）在传输层被拒；指纹已登记但 agent_id 不同被拒；一证书一身份约束；轮换更新；吊销证书后登记失效。
- 集成：build-tag `securemode` 开/关编译均通过；`go vet` 通过。

## 13. 非目标（YAGNI）

- 不做 TPM/系统 keyring 集成（用户选择哈希校验 + 信封加密）。
- 不做多用户密码体系；单密码即解锁唯一途径。
- 不对 agent 与 kernel 之间的加密配置同步做额外设计（agent 配置独立保护）。
- **agent 端不做运行时配置修改能力**：agent 本地 CLI 无模式切换/配置修改命令；配置变更一律经内核 CLI 下发（内核托管模式）。
