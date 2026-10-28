# 模块联动审计：声明的联动 vs 真实实现的联动（2026-10-29）

> 目的：回答"哪些模块**声称**互相支持/联动，哪些在代码里**真的**接上了"。
> 结论先行：**真联动主要通过 4 条通道**（DI、Bus、扩展点、`cmd/kernel` 直接构造），
> 但存在 **7 个无人解析的 DI 绑定、11 个死主题、1 个整包孤儿（adapterhub）、
> 以及 `internal/attck` 在 kernel 中从未启动** 的落差。

## 1. 判定口径

| 通道 | 证据形式 | 说明 |
|---|---|---|
| DI（Container） | `kc.Container().Bind/Resolve`（`internal/kernel/di.go`） | 接口级解耦 |
| 总线（Bus） | `Bus().Publish/Subscribe` + `Topic*` 常量 | 事件/数据流 |
| 扩展点 | `Extensions().Execute("point")` + `RegisterAllExtensionPoints` | 平台 89 个钩子 |
| 直接装配 | `cmd/kernel/main.go` / `comms_on.go` 构造器参数、包 import | 最硬耦合 |

"声明"包括：`Dependencies() []kernel.PluginDependency`、`Topic*` 常量、`Priority()` 隐含顺序、文档/配置。

## 2. 模块装配总表

| 模块 | 装配 | Priority（越大越晚启动） | Dependencies 声明 | 真实通道 | 判定 |
|---|---|---|---|---|---|
| config_watcher | plugin | 1 | — | Bus 发布 config.reloaded | 半接线（无订阅者） |
| workerpool | plugin | 2 | — | DI 被 CLI 解析 | **真** |
| persistence | plugin | 3 | — | Bus 订阅 agent.registered/timeout/assessor.result；直连 comms | **真** |
| heartbeat | plugin | 5 | — | Bus 发布 3 主题；`topology.RecordNetworkFacts`；直连 comms | **真** |
| cti | plugin | 10 | — | DI 被 assessor 解析；发布 cti.threat_detected | 真（主题无订阅者） |
| spc | plugin | 20 | — | DI 被 assessor/attck 解析；ResolveNamed persistence | **真** |
| attck（internal） | **kernel 不注册** | 21（无效） | — | 仅 `cmd/asscor` 独立二进制 + 可选包注入 assessor | **kernel 中未启动** |
| assessor | plugin | 40 | `config` | DI 解析 4 个 provider；Bus 发布 assessor.result；扩展点执行 15+ | **真（核心枢纽）** |
| engine（scoring） | plugin | — | — | 绑定 ScoringEngineProvider；直连 attck 注入目标 | **真** |
| adapter_integration | plugin | 45 | — | 绑定 AdapterIntegrationInterface | **真** |
| policy | plugin | 50 | — | 订阅 assessor.result；发布 policy.action | **真** |
| sourcemanager | plugin | 55 | `adapter_integration` | DI 解析 adapter_integration；gRPC 服务 | **真** |
| commander | plugin | 60 | — | 订阅 policy.action | **真** |
| collector | plugin | 70 | — | 绑定 LogCollectorInterface；直连 comms | 真 |
| cli | plugin | 90 | — | DI 解析 assessor/sourcemanager/workerpool | **真** |
| federation（扩展） | 扩展包自注册 | 95 | 无（但 Resolve assessor + 读 topology） | DI + `topology.ListNodes` | **真（声明缺失）** |
| srdwrapper | plugin | 110（srd manager） | — | 订阅 topology 事件；Bus 发布；扩展点 | **真** |
| integrity / resilience / securemode | 非 Plugin（库） | — | — | 被 kernel/assessor/adapter/comms/agent import | 真（库级） |
| adapterhub | **无任何 import** | — | — | 仅自身与测试 | **孤儿** |
| extmgr | kernel 内建 | — | — | 桥接扩展点到 89 个钩子 | **真** |
| comms | kernel 内建 | — | — | 构造器直连 9 个模块 | **真（手工装配点）** |

## 3. 真实联动矩阵（带证据）

### 3.1 DI：谁提供给谁

| Provider（Bind） | Consumer（Resolve） | 证据 |
|---|---|---|
| `ScoringEngineProvider`（cmd/kernel engine_on） | assessor | `internal/assessor/assessor.go:85` |
| `PrismEngineProvider`（cmd/kernel） | assessor | `assessor.go:96` |
| `SPCInterface`（spc） | assessor、attck | `assessor.go:566`、`attck_apt_enhanced.go:204` |
| `CTIInterface`（cti） | assessor（2 处） | `assessor.go:613,627` |
| `AssessorInterface`（assessor） | CLI、config_watcher、federation | `cli/module.go:71`、`config_watcher.go:105`、`extensions/federation/plugin.go:447` |
| `SourceManagerInterface`（sourcemanager） | CLI | `cli/module.go:395` |
| `AdapterIntegrationInterface`（kernel） | sourcemanager | `sourcemanager.go:427` |
| `WorkerPoolInterface`（kernel） | CLI | `cli/module.go:140` |
| `config`（BindNamed） | assessor、persistence、policy、spc | `assessor.go:76` 等 |

**无人解析的 Bind（7 个）**：`PersistenceInterface`、`PolicyInterface`、`CommanderInterface`、
`HeartbeatInterface`、`LogCollectorInterface`、`CLIInterface`、`ATTACKInterface`。
它们实际由 `comms_on.go` 构造器直连或 CLI KernelAccess 使用，DI 注册是冗余的
（容易让人误以为已解耦）。

### 3.2 Bus：真实数据流

| 主题 | 发布者 | 订阅者 | 判定 |
|---|---|---|---|
| `assessor.result` | assessor（`assessor.go:428,549`） | attck（`:312`，kernel 中未启动）、kernel lifecycle（`:194`）、persistence（`:193`）、policy（`:74`） | **真**（attck 除外） |
| `policy.action` | policy（`:169,:223`） | commander（`:221`） | **真** |
| `agent.registered` | heartbeat（`:300`） | persistence（`:194`） | **真** |
| `agent.timeout` | heartbeat（`:574`） | persistence（`:195`） | **真** |

### 3.3 Bus：声明了但没有消费者

| 主题 | 发布点 | 状态 |
|---|---|---|
| `agent.heartbeat` | `heartbeat.go:269` | **无订阅者** |
| `assessor.self_check` | `assessor.go:337` | **无订阅者** |
| `config.reloaded` | `config_watcher.go:286`、`securemode_on.go:107` | **无订阅者** |
| `cti.threat_detected` | `cti.go:390` | **无订阅者** |

### 3.4 Bus：常量存在但全仓零使用

`TopicSPCUpdated`、`TopicCTIUpdated`、`TopicCommandEnqueued`、`TopicCommandResult`、
`TopicConfigChanged`、`TopicAdapterFindings`、`TopicSourceManagerDeployed`
（定义在 `internal/kernel/plugin.go:89-98`），以及 srd 结果主题无常量。

**命名不一致**：`adapterhub` 发布的是字面量 `"adapterhub.findings"`
（`internal/adapterhub/manager.go:504`），而常量是 `"adapter.findings"`（`plugin.go:97`）——
即使将来加订阅者也会对不上。

### 3.5 直接装配（最硬的联动）

- `cmd/kernel/comms_on.go:45`：`comms.NewKernelServiceImpl(heartbeat, commander, cti, assessor, persistence, spc)`
- `cmd/kernel/comms_on.go:57`：`comms.NewAgentServiceImpl(assessor, commander, logCollector)`
- `cmd/kernel/comms_on.go:70`：`sourceManager` gRPC 服务注册
- `cmd/kernel/main.go:279-280`：`initATTACK(assessor)` → `optional/.../attck-ext-pack/register.go:18` → `assessor.SetATTACKProvider`
- `extensions/federation`：Extenion 自注册（唯一不依赖 `cmd/kernel` append 的模块）

### 3.6 包级 import（谁把谁编进来）

- `heartbeat` → `topology`（网络事实）
- `comms` → `topology`、`resilience`、`securemode`
- `assessor` → `checks`、`integrity`
- `sourcemanager` → `adapter`
- `adapter` → `resilience`、`checks`
- `srdwrapper` → `engine/srd`、`topology`（`srd_wrapper.go:71` 订阅拓扑事件）
- `federation` → `topology`、`assessor`（DI）
- `adapterhub` → **无人 import**

## 4. 重点发现

1. **`internal/attck` 在 kernel 中从未启动**：`cmd/kernel` 的插件列表不包含 attck；
   `attck_ext_on.go` 只做"可选包注入 assessor"。因此 attck 的 `Bus().Subscribe(assessor.result)`
   与 `Container().Bind(ATTACKInterface)` 在 kernel 中**永不执行**；kernel 的 ATT&CK 数据流是
   `optional pack → assessor.attackProvider → assessor.go:659`。`cmd/asscor` 独立二进制才用 attck 插件形态。
2. **`internal/adapterhub` 是整包孤儿**：除自身与测试外无引用；其发布主题还与平台常量不一致。
3. **11 个总线主题没有闭环**（4 个发布无订阅 + 7 个零使用），其中 `spc.updated`/`cti.updated`
   与"SPC/CTI 联动"的文档叙述容易让人误以为走事件，实际走 DI。
4. **依赖声明几乎为空**：全部插件里只有 assessor→`config`、sourcemanager→`adapter_integration`
   两条 `Dependencies()`；启动顺序实际靠 `Priority()` + `kernel_lifecycle.go` 的拓扑排序。
   federation 扩展解析 assessor、读取 topology，但 `Dependencies()` 返回 nil。
5. **7 个 DI 绑定无人解析**：模块实际被 `comms_on.go` 手工塞进服务构造器；DI 与真实装配脱节。
6. **`comms_on.go` 是最大手工装配点**：新增/替换任一模块都要改 `cmd/kernel`（federation 扩展除外）。

## 5. 修复建议

| 级别 | 动作 |
|---|---|
| P0 | 删除零使用主题常量，或补上订阅者；统一 `adapter.findings` 命名；决定 adapterhub 去留（接进 kernel 或删除） |
| P0 | 在文档/README 明确：kernel 的 ATT&CK 走 provider 注入，`internal/attck` 插件形态只用于 `cmd/asscor` |
| P1 | 为关键顺序补 `Dependencies()`（assessor→SPC/CTI/engine、policy→assessor、commander→policy、persistence→heartbeat、federation→assessor），让排序不依赖"Priority 数字约定" |
| P1 | 把 `comms_on.go` 的 9 个构造器参数改为按接口 DI Resolve，减少 `cmd/kernel` 改动面 |
| P2 | 扩展点执行清单化：确认 89 个点里哪些真的被 `Execute`（当前仅 assessor 15+、srd 1 个） |

## 6. 复现方式

- 静态矩阵：`grep` 上述 file:line；DI/Bus 解析用一次性脚本完成（未入库）。
- 动态佐证：相关包测试全部通过（kernel/heartbeat/persistence/policy/commander/spc/cti/
  sourcemanager/srdwrapper/cli 共 10 个包 + `extensions/federation`）。
- 注意：本轮审计在环境停机状态下完成，只有静态证据 + 单测；端到端联动证据见
  `docs/2-experiments/T4_FEDERATION_AUC_LARGE_2026-10-28.md` 与联邦验收日志。
