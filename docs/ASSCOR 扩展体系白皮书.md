# ASSCOR 扩展体系白皮书

**版本**：v1.1
**日期**：2026-07-17
**状态**：发布
**配套文档**：SSAM 2.0 白皮书（第一篇章）、工程实现白皮书（第三篇章）

> 本文整合了《ASSCOR 扩展接口报告》与《ASSCOR 可替换性评估报告》，系统阐述 ASSCOR 的扩展架构——包括插件生命周期、DI 容器、事件总线、扩展点系统、业务模块接口、检查器注册表，以及全部核心模块和检查器的可替换性设计。

---

## 摘要

ASSCOR 采用"微内核 + 插件"架构，通过标准化接口、依赖注入容器、事件总线和扩展点系统，实现了从底层检查器到顶层评分引擎的**全栈可替换性**。本文档系统记录 ASSCOR 的扩展接口体系、可替换性机制、以及扩展开发规范，为第三方开发者和社区贡献者提供完整的接入指南。

---

## 目录

1. [插件生命周期接口](#一插件生命周期接口)
2. [DI 容器与依赖注入](#二di-容器与依赖注入)
3. [事件总线](#三事件总线)
4. [扩展点系统](#四扩展点系统)
5. [业务模块接口](#五业务模块接口)
6. [检查器注册表与可替换性](#六检查器注册表与可替换性)
7. [核心模块可替换性](#七核心模块可替换性)
8. [外部适配器与检查委派](#八外部适配器与检查委派)
9. [扩展开发快速指南](#九扩展开发快速指南)
10. [替换复杂度与缺口分析](#十替换复杂度与缺口分析)

---

## 一、插件生命周期接口

### 1.1 Plugin（核心接口）

所有 ASSCOR 模块必须实现 `Plugin` 接口，核心定义位于 [plugin.go](file:///f:/Argus/internal/kernel/plugin.go#L102-L114)。

```go
type Plugin interface {
    Info() PluginInfo
    Dependencies() []PluginDependency
    Init(ctx context.Context, kc KernelContext) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    State() PluginState
}
```

**生命周期状态机**：

```
Unregistered → Registered → Initialized → Started → Stopping → Stopped
                                                    ↘ Failed
```

| 阶段 | 方法 | 约定 |
|------|------|------|
| Registered | `RegisterPlugin()` | 插件注册到 Kernel |
| Initialized | `Init()` | 仅做初始化（加载配置、注册扩展点、绑定 DI），不启动长运行任务 |
| Started | `Start()` | 启动 goroutine、订阅 Bus、启动定时器 |
| Stopping | `Stop()` | 清理 goroutine、关闭 channel、取消 context |

### 1.2 PriorityPlugin（优先级插件）

```go
type PriorityPlugin interface {
    Plugin
    Priority() int
}
```

实现此接口的插件按 `Priority()` 升序启动，降序停止。

**各模块优先级分配**：

| 优先级 | 插件 | 说明 |
|:------:|------|------|
| 1 | ConfigWatcherModule | 配置文件监听，最高优先级 |
| 2 | ConcurrencyModule | 并发控制基础设施 |
| 3 | PersistenceModule | 持久化层 |
| 5 | HeartbeatModule | Agent 心跳管理 |
| 10 | CTIModule | 网络威胁情报 |
| 20 | SPCModule | 安全态势计算 |
| 21 | ATTACKModule | ATT&CK 知识库与行为分析 |
| 35 | ScoringEngineModule | SSAM 评分引擎 |
| 40 | AssessorModule | 评估调度器 |
| 45 | AdapterIntegrationModule | 外部适配器集成 |
| 50 | PolicyModule | 策略引擎 |
| 55 | SourceManagerModule | 外部源管理 |
| 60 | CommanderModule | 命令下发 |
| 70 | LogCollectorModule | 日志收集 |

### 1.3 HealthCheckable（健康检查）

```go
type HealthCheckable interface {
    HealthCheck(ctx context.Context) error
}
```

实现者：SPCModule、ConcurrencyModule 等。Kernel 的 `HealthCheck()` 遍历所有实现此接口的插件并收集状态。

### 1.4 ConfigurablePlugin（热加载配置）

```go
type ConfigurablePlugin interface {
    Plugin
    Configure(config map[string]string) error
}
```

热加载时 Kernel 调用 `Configure(k.config)` 注入新配置。

### 1.5 辅助类型

```go
type PluginInfo struct {
    Name, Version, Description, Author string
}

type PluginDependency struct {
    Interface interface{}
    Name      string
}
```

---

## 二、DI 容器与依赖注入

DI 容器定义于 [di.go](file:///f:/Argus/internal/kernel/di.go)，提供类型安全的依赖注入。

### 2.1 容器接口

| 方法 | 签名 | 说明 |
|------|------|------|
| `Bind` | `(iface interface{}, impl interface{})` | 以接口的 reflect.Type 为 key 注册实现，**重复调用直接覆盖** |
| `BindNamed` | `(name string, iface interface{}, impl interface{})` | 命名绑定 |
| `Resolve` | `(iface interface{}) (interface{}, bool)` | 按类型查找实现 |
| `ResolveNamed` | `(name string) (interface{}, bool)` | 按名称查找实现 |
| `Inject` | `(target interface{}) error` | 通过 `inject:"true"` 或 `inject:"名称"` 标签自动注入 |
| `Remove` | `(iface interface{})` | 移除绑定 |
| `Count` | `() int` | 返回已绑定数量 |

### 2.2 完整 DI 绑定表

| 序号 | 绑定接口 | 绑定实例 | 文件位置 |
|:---:|------|------|------|
| 1 | `(*engine.AssessorEngine)(nil)` | `ssam.NewEngineAdapter(cfg)` | `main.go` (平台层注入) |
| 2 | `(*AssessorInterface)(nil)` | AssessorModule | [assessor.go:L99](file:///f:/Argus/internal/kernel/assessor.go#L99) |
| 3 | `(*PersistenceInterface)(nil)` | PersistenceModule | [persistence.go:L261](file:///f:/Argus/internal/kernel/persistence.go#L261) |
| 4 | `(*ConcurrencyInterface)(nil)` | ConcurrencyModule | [workerpool.go:L209](file:///f:/Argus/internal/kernel/workerpool.go#L209) |
| 5 | `(*WorkerPoolInterface)(nil)` | WorkerPool | [workerpool.go:L210](file:///f:/Argus/internal/kernel/workerpool.go#L210) |
| 6 | `(*SPCInterface)(nil)` | SPCModule | [spc.go:L447](file:///f:/Argus/internal/kernel/spc.go#L447) |
| 7 | `(*AdapterIntegrationInterface)(nil)` | AdapterIntegrationModule | [adapter_integration.go:L56](file:///f:/Argus/internal/kernel/adapter_integration.go#L56) |
| 8 | `(*CTIInterface)(nil)` | CTIModule | [cti.go:L47](file:///f:/Argus/internal/kernel/cti.go#L47) |
| 9 | `(*HeartbeatInterface)(nil)` | HeartbeatModule | [heartbeat.go:L55](file:///f:/Argus/internal/kernel/heartbeat.go#L55) |
| 10 | `(*ATTACKInterface)(nil)` | ATTACKModule | [attck.go:L292](file:///f:/Argus/internal/kernel/attck.go#L292) |
| 11 | `(*CommanderInterface)(nil)` | CommanderModule | [commander.go:L106](file:///f:/Argus/internal/kernel/commander.go#L106) |
| 12 | `(*PolicyInterface)(nil)` | PolicyModule | [policy.go:L86](file:///f:/Argus/internal/kernel/policy.go#L86) |
| 13 | `(*SourceManagerInterface)(nil)` | SourceManagerModule | [source_manager.go:L157](file:///f:/Argus/internal/kernel/source_manager.go#L157) |
| 14 | `(*LogCollectorInterface)(nil)` | LogCollectorModule | [collector.go:L74](file:///f:/Argus/internal/kernel/collector.go#L74) |
| 15 | `(*ScoringEngineProvider)(nil)` | ScoringEngineModule | [main.go:L131](file:///f:/Argus/cmd/kernel/main.go#L131) |

### 2.3 依赖解析时机

核心模块的依赖解析发生在**运行时**（非 Init 时固化），这使得热替换成为可能：

| 消费模块 | 依赖接口 | 解析时机 |
|------|------|------|
| Assessor | `SPCInterface` | 每次评估时 |
| Assessor | `CTIInterface` | 每次评估时 |
| Assessor | `ATTACKInterface` | 每次评估时 |
| Assessor | `ScoringEngineProvider` | Init 时 |

### 2.4 典型注入模式

```go
// 在模块 Init 中通过 KernelContext 获取依赖
var spc SPCInterface
if impl, ok := kc.Container().Resolve((*SPCInterface)(nil)); ok {
    spc = impl.(SPCInterface)
}
```

---

## 三、事件总线

### 3.1 话题常量

定义于 [plugin.go](file:///f:/Argus/internal/kernel/plugin.go#L83-L100)：

| 常量 | 值 | 说明 |
|------|-----|------|
| `TopicAssessorResult` | `"assessor.result"` | 评估完成后发布 |
| `TopicPolicyAction` | `"policy.action"` | 策略引擎触发动作时发布 |
| `TopicAgentRegistered` | `"agent.registered"` | Agent 注册时发布 |
| `TopicAgentTimeout` | `"agent.timeout"` | Agent 超时时发布 |
| `TopicConfigChanged` | `"config.changed"` | 配置变更时发布 |
| `TopicSPCUpdated` | `"spc.updated"` | SPC 数据更新时发布 |
| `TopicCTIUpdated` | `"cti.updated"` | CTI 情报更新时发布 |
| `TopicCommandEnqueued` | `"command.enqueued"` | 命令入队时发布 |
| `TopicCommandResult` | `"command.result"` | 命令执行结果返回时发布 |
| `TopicAgentHeartbeat` | `"agent.heartbeat"` | Agent 心跳时发布 |
| `TopicConfigReloaded` | `"config.reloaded"` | 配置重载完成时发布 |
| `TopicCTIThreatDetected` | `"cti.threat_detected"` | CTI 威胁检测到时发布 |
| `TopicAdapterFindings` | `"adapter.findings"` | Adapter 发现结果时发布 |
| `TopicSourceManagerDeployed` | `"source_manager.deployed"` | 外部源部署完成时发布 |

### 3.2 订阅关系表

| 订阅者 | 主题 | Handler |
|--------|------|---------|
| **PersistenceModule** | `TopicAssessorResult` | `m.onAssessmentResult` |
| **PersistenceModule** | `TopicAgentRegistered` | `m.onAgentRegistered` |
| **PersistenceModule** | `TopicAgentTimeout` | `m.onAgentTimeout` |
| **ATTACKModule** | `TopicAssessorResult` | `m.onAssessmentResult` |
| **CommanderModule** | `TopicPolicyAction` | `m.onPolicyAction` |
| **PolicyModule** | `TopicAssessorResult` | `m.onAssessmentResult` |

### 3.3 事件流图

```
Agent 上报 → HeartbeatModule
    ├─ TopicAgentRegistered ──→ PersistenceModule (持久化注册记录)
    └─ TopicAgentHeartbeat   ──→ (系统内部)

评估触发 → AssessorModule
    └─ TopicAssessorResult
        ├─→ PersistenceModule (写入评估历史)
        ├─→ ATTACKModule     (ATT&CK 覆盖率分析 / APT 归因)
        └─→ PolicyModule     (策略判定 → 可能触发动作)

策略判定 → PolicyModule
    └─ TopicPolicyAction ──→ CommanderModule (下发命令到 Agent)
```

---

## 四、扩展点系统

扩展点定义于 [extensions.go](file:///f:/Argus/internal/kernel/extensions.go)。

### 4.1 核心类型

```go
type ExtensionPoint struct {
    Name        string
    Description string
    Version     string
}

type ExtensionHandler func(ctx context.Context, data interface{}) error
```

### 4.2 ExtensionRegistry 方法

| 方法 | 说明 |
|------|------|
| `RegisterPoint(point ExtensionPoint)` | 注册扩展点 |
| `RegisterExtension(pointName string, id string, handler ExtensionHandler) error` | 注册扩展处理器 |
| `Execute(ctx, pointName string, data interface{}) []error` | 执行所有处理器 |
| `ExecuteUntilFirst(ctx, pointName string, data interface{}) (interface{}, error)` | 执行到第一个非 nil 结果 |
| `UnregisterPlugin(id string)` | 移除指定插件的所有扩展 |
| `ListPoints() []ExtensionPoint` | 列出所有已注册扩展点 |
| `ListExtensions(pointName string) []string` | 列出指定扩展点的处理器 ID |

### 4.3 内核级扩展点（6 个）

| 扩展点名称 | 触发时机 |
|-----------|---------|
| `kernel.pre_init` | 所有插件 Init 之前 |
| `kernel.post_init` | 所有插件 Init 之后 |
| `kernel.pre_start` | 所有插件 Start 之前 |
| `kernel.post_start` | 所有插件 Start 之后 |
| `kernel.pre_stop` | 关闭序列开始前 |
| `kernel.post_stop` | 所有插件 Stop 之后 |

### 4.4 业务模块扩展点（44 个，v0.2.1+）

**AssessorModule（4 个）**：`assessor.pre_evaluate`、`assessor.post_evaluate`、`assessor.report_generated`、`assessor.outbound`

**SPCModule（3 个）**：`spc.pre_calculate`、`spc.post_calculate`、`spc.cve_updated`

**ATTACKModule（13 个）**：

| 扩展点 | 触发时机 | 分类 |
|------|------|------|
| `attck.coverage.complete` | 覆盖率分析完成 | 覆盖率 |
| `attck.apt.matched` | APT 组织匹配检测 | APT 归因 |
| `attck.risk.predicted` | 预测性风险评估完成 | 风险评估 |
| `attck.detection.alert` | 检测告警触发 | 检测告警 |
| `attck.detection.anomaly` | 高分异常检测到 | 检测告警 |
| `attck.emulation.complete` | 对手仿真完成 | 仿真 |
| `attck.assessment.complete` | 差距分析评估完成 | 评估 |
| `attck.apt.chain_detected` | APT 攻击链重构完成 | APT 归因 |
| `attck.apt.attribution` | APT 归因执行 | APT 归因 |
| `attck.apt.hunt_confirmed` | 威胁狩猎假设确认 | 威胁狩猎 |
| `attck.apt.report_generated` | APT 分析报告生成 | 报告 |
| `attck.behavioral.alert` | 行为告警触发 | 行为分析 |
| `attck.behavioral.beacon` | C2 Beaconing 检测到 | 行为分析 |

**HeartbeatModule（3 个）**：`heartbeat.agent_timeout`、`heartbeat.agent_reconnected`、`heartbeat.agent_pruned`

**ConfigWatcherModule（3 个）**：`config.pre_reload`、`config.post_reload`、`config.load_error`

**CTIModule（3 个）**：`cti.pre_update`、`cti.post_update`、`cti.coefficient_changed`

**AdapterIntegrationModule（2 个）**：`adapter.pre_fetch`、`adapter.post_fetch`

**SIEM Pusher（3 个）**：`siem.pre_push`、`siem.post_push`、`siem.push_failure`

**CommanderModule（2 个）**：`commander.command_expired`、`commander.key_rotated`

**SourceManagerModule（4 个）**：`source.pre_deploy`、`source.post_deploy`、`source.pre_enable`、`source.pre_disable`

**Log Collector（2 个）**：`log.entry_received`、`agent.log_uploaded`

**PersistenceModule（3 个）**：`persistence.pre_append`、`persistence.post_append`、`persistence.dashboard_written`

**生命周期阶段映射**：

| 阶段 | 扩展点 | 覆盖模块 |
|------|--------|---------|
| **探测** | 23 | Assessor + SPC + ATT&CK + Heartbeat + Adapter + CTI |
| **响应** | 5 | Policy + ConfigWatcher |
| **报告** | 8 | Assessor + ATT&CK + SIEM + Log + Persistence |
| **修复** | 5 | Remediation + Commander |
| **验证** | 3 | Verify |
| **归档** | 6 | Archive + Persistence |

### 4.5 扩展点注册示例（v0.2.1 集中化架构）

扩展点由平台层 `RegisterAllExtensionPoints()` 集中定义在 `kernel/platform_extensions.go`。模块不可注册新扩展点（`ModuleExtensions` 接口不含 `RegisterPoint`），只能订阅已有扩展点：

```go
// 平台层: platform_extensions.go 集中注册
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
    r.RegisterPoint(ExtensionPoint{
        Name: "spc.pre_calculate", Description: "Called before SPC calculation", Version: "1.0",
    })
}

// 模块: 使用 RegisterExtension 订阅（不可 RegisterPoint）
kc.Extensions().RegisterExtension("my_plugin", "spc.pre_calculate",
    func(ctx context.Context, data interface{}) error { return nil }, 10,
)
```

---

## 五、业务模块接口

### 5.1 ScoringEngineProvider

[assessor.go:L20-L27](file:///f:/Argus/internal/kernel/assessor.go#L20-L27) — SSAM 评分引擎提供者

```go
type ScoringEngineProvider interface {
    Assess(hostID string, hostname string) *model.AssessmentResult
    AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
    SSAMEngine() *ssam.Engine
    ReloadWeights(cfg *config.Config)
    ValidateEdgeFactors(registeredChecks []model.CheckItem) []string
    PrintReport(result *model.AssessmentResult) string
}
```

### 5.2 AssessorInterface

[assessor.go:L515-L520](file:///f:/Argus/internal/kernel/assessor.go#L515-L520) — 评估调度器

```go
type AssessorInterface interface {
    Evaluate(hostID string) *model.AssessmentResult
    EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
    GetResult(hostID string) *model.AssessmentResult
    ReloadConfig(cfg *config.Config)
}
```

### 5.3 PolicyInterface

[policy.go:L182-L185](file:///f:/Argus/internal/kernel/policy.go#L182-L185) — 策略引擎

```go
type PolicyInterface interface {
    EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction)
    GetHostStatus(hostID string) HostStatus
}
```

### 5.4 SPCInterface

[spc.go:L1194-L1213](file:///f:/Argus/internal/kernel/spc.go#L1194-L1213) — 安全态势计算

```go
type SPCInterface interface {
    Calculate(hostID string, assetPackages []string) SPCCorrection
    AddCVE(score SPCCVEScore)
    AddCVEs(scores []SPCCVEScore)
    MergeCVEs(cves []SPCCVEScore) (added int, updated int)
    GetCVEs() []SPCCVEScore
    GetCVECount() int
    GetKEVCount() int
    ClearCache()
    UpsertAsset(asset LocalAsset)
    GetAsset(hostID string) *LocalAsset
    FetchFromAllSources() []SPCFetchResult
    FetchFromEPSS() SPCFetchResult
    FetchFromCISAKEV() SPCFetchResult
    ImportOSCAL(data []byte, format string) (int, error)
    ConfigureMISP(baseURL, apiKey string) error
    Enabled() bool
    SetEnabled(v bool)
    LastUpdate() time.Time
}
```

### 5.5 CTIInterface

[cti.go:L166-L170](file:///f:/Argus/internal/kernel/cti.go#L166-L170) — 网络威胁情报

```go
type CTIInterface interface {
    GetCoefficient() float64
    ReportThreat(severity string)
    ClearThreat()
}
```

### 5.6 其余模块接口

| 接口 | 文件位置 | 方法数 |
|------|------|:---:|
| `HeartbeatInterface` | [heartbeat.go:L223-L229](file:///f:/Argus/internal/kernel/heartbeat.go#L223-L229) | 5 |
| `CommanderInterface` | [commander.go:L324-L328](file:///f:/Argus/internal/kernel/commander.go#L324-L328) | 3 |
| `PersistenceInterface` | [persistence.go:L651-L661](file:///f:/Argus/internal/kernel/persistence.go#L651-L661) | 9 |
| `ConcurrencyInterface` | [workerpool.go:L304-L311](file:///f:/Argus/internal/kernel/workerpool.go#L304-L311) | 6 |
| `WorkerPoolInterface` | [workerpool.go:L313-L321](file:///f:/Argus/internal/kernel/workerpool.go#L313-L321) | 6 |
| `ATTACKInterface` | [attck.go:L1560-L1639](file:///f:/Argus/internal/kernel/attck.go#L1560-L1639) | 30+ |
| `AdapterIntegrationInterface` | [adapter_integration.go:L198-L201](file:///f:/Argus/internal/kernel/adapter_integration.go#L198-L201) | 2 |
| `LogCollectorInterface` | [collector.go:L177-L180](file:///f:/Argus/internal/kernel/collector.go#L177-L180) | 2 |
| `SourceManagerInterface` | [source_manager.go:L88-L103](file:///f:/Argus/internal/kernel/source_manager.go#L88-L103) | 14 |

---

## 六、检查器注册表与可替换性

### 6.1 注册表机制

检查器通过 [registry.go](file:///f:/Argus/internal/checks/registry.go) 中全局注册表管理：

```go
var (
    mu       sync.RWMutex
    registry []model.CheckItem
)

func Register(items ...model.CheckItem)     // 注册新检查项
func Unregister(checkIDs ...string)          // 按 ID 移除检查项
func GetAll() []model.CheckItem             // 获取全部注册项
func GetByID(checkID string) (model.CheckItem, bool)  // 按 ID 查找
func GetByDomain(domain model.ScoreDomain) []model.CheckItem  // 按域筛选
```

默认检查项在 [init.go](file:///f:/Argus/internal/checks/init.go) 中通过 `init()` 自动注册：

```go
func init() {
    Register(linux.All()...)
}
```

### 6.2 替换检查器

**方案 A：替换单个检查项**

```go
checks.Unregister("AS-001")
checks.Register(model.CheckItem{
    ID: "AS-001", Domain: model.DomainAttackSurface, Function: myCustomAS001Checker,
})
```

**方案 B：替换全部检查项**

```go
checks.Unregister(/* 获取所有现有 ID */...)
checks.Register(myCustomCheckSet...)
```

**方案 C：按合规要求裁剪**

```go
ids := checks.GetByComplianceLevel("等保三级")
// 过滤后重新注册
checks.Unregister(getIDs(all)...)
checks.Register(keep...)
```

### 6.3 替换注意事项

| 注意点 | 说明 |
|------|------|
| ⚠️ **边缘因子 TriggerCheck 依赖** | 替换检查项需同步更新 `TriggerCheck` 映射 |
| ⚠️ **ATT&CK 技术映射** | 需在 ATTACKModule 中同步更新 |
| ⚠️ **等保条款标注** | 替换后需标注正确的等保条款编号 |
| ✅ **运行时安全** | `sync.RWMutex` 保护，支持并发读写 |

---

## 七、核心模块可替换性

### 7.1 DI 容器替换原理

DI 容器（[di.go](file:///f:/Argus/internal/kernel/di.go#L23-L32)）的 `Bind` 采用**覆盖策略**——重复绑定同一接口会静默覆盖之前的实现：

```go
func (c *Container) Bind(iface interface{}, impl interface{}) {
    t := reflect.TypeOf(iface).Elem()
    c.bindings[t] = impl  // 直接覆盖，无检查
}
```

### 7.2 可替换性总览

| 组件 | 可替换性 | 替换机制 | 热替换 |
|------|:---:|------|:---:|
| 原生检查器 | ✅ | 注册表 API（Register/Unregister） | ✅ |
| SPC 安全态势计算 | ✅ | DI 容器 Bind 覆盖 SPCInterface | ✅ |
| CTI 网络威胁情报 | ✅ | DI 容器 Bind 覆盖 CTIInterface | ✅ |
| SSAM 评分引擎 | ✅ | DI 容器 Bind 覆盖 ScoringEngineProvider | ✅ |
| ATT&CK 知识库 | ✅ | DI 容器 Bind 覆盖 ATTACKInterface | ✅ |
| Assessor 评估调度 | ✅ | DI 容器 Bind 覆盖 AssessorInterface | ✅ |
| Policy 策略引擎 | ✅ | DI 容器 Bind 覆盖 PolicyInterface | ✅ |
| Commander 命令下发 | ✅ | DI 容器 Bind 覆盖 CommanderInterface | ✅ |
| Persistence 持久化 | ✅ | DI 容器 Bind 覆盖 PersistenceInterface | ✅ |
| 其余 6 个核心模块 | ✅ | DI 容器 Bind 覆盖对应接口 | ✅ |

### 7.3 替换依赖链

| 替换模块 | 影响的下游 |
|------|------|
| `SPCInterface` | Assessor → SSAM 公式（P_score 因子） |
| `CTIInterface` | Assessor → SSAM 公式（μ 威胁系数） |
| `ScoringEngineProvider` | Assessor → 整个评分管道 |
| `ATTACKInterface` | Assessor → 覆盖率/APT 归因 |
| `PolicyInterface` | 策略判定 → Commander 命令下发 |
| `ConcurrencyInterface` | 所有使用 WorkerPool 的模块 |

### 7.4 替换示例

```go
// 替换 SPC 为自定义实现
type MySPC struct{}
func (m *MySPC) Calculate(hostID string, assetPackages []string) SPCCorrection {
    return SPCCorrection{Score: 1.0, Weight: 1.0}
}
// 实现 SPCInterface 的所有方法...

// 在 main.go 中替换
k.Container().Bind((*kernel.SPCInterface)(nil), &MySPC{})
```

---

## 八、外部适配器与检查委派

### 8.1 外部适配器机制

[AdapterIntegrationModule](file:///f:/Argus/internal/kernel/adapter_integration.go) 提供外部安全工具的集成：

```
外部安全工具            AdapterIntegration          Assessor
───────────            ──────────────────          ────────
Wazuh / OpenSCAP / Lynis / Falco
    └─→   RunAdapters() → CollectFindings() → EvaluateFromResults()
                                                  │
                                         []model.CheckResult
```

### 8.2 外部结果注入点

Assessor 提供两个评估入口：

| 入口 | 签名 | 检查来源 |
|------|------|------|
| `Evaluate` | `(hostID string)` | 原生检查器注册表 |
| `EvaluateFromResults` | `(hostID, hostname string, checkResults []model.CheckResult)` | 外部传入的 CheckResult 切片 |

**完全替代原生检查器**：

```go
checks.Unregister(getAllIDs()...)           // 清空原生检查器
adapterResults := adapter.CollectFindings()  // 收集外部检查结果
result := assessor.EvaluateFromResults(hostID, hostname, adapterResults)
```

### 8.3 适配器检查项的模型结构

```go
type CheckResult struct {
    CheckID           string       // 检查项 ID
    Domain            ScoreDomain  // 归属域（AS/BC/OT/RS）
    Passed            bool         // 是否通过
    Score             float64      // 得分
    Detail            string       // 详情
    Description       string       // 描述
    ComplianceRef     string       // 合规引用
    ATTACKTechniqueID string       // ATT&CK 技术 ID
    EdgeFactors       []string     // 触发的边缘因子 ID
}
```

---

## 九、扩展开发快速指南

### 9.1 新增插件清单

1. 实现 `Plugin` 接口（`Info/Dependencies/Init/Start/Stop/State`）
2. 如需控制启动顺序，实现 `PriorityPlugin` 接口
3. 如需健康检查，实现 `HealthCheckable` 接口
4. 如需热加载配置，实现 `ConfigurablePlugin` 接口
5. 在 `Init` 中：通过 `kc.Container().Resolve()` 获取依赖、通过 `kc.Container().Bind()` 注册自身接口、通过 `kc.Extensions().RegisterExtension()` 订阅扩展点
6. 在 `Start` 中：通过 `kc.Bus().Subscribe()` 订阅事件、启动 goroutine
7. 在 `Stop` 中：关闭 goroutine、清理资源
8. 在 [main.go](file:///f:/Argus/cmd/kernel/main.go) 中实例化并注册

### 9.2 新增扩展点（平台层操作）

扩展点定义归属 ASSCOR 平台层（`kernel/platform_extensions.go`），不归属各模块。新增扩展点需在 `RegisterAllExtensionPoints()` 函数中添加：

```go
// platform_extensions.go: 集中注册
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
    r.RegisterPoint(ExtensionPoint{
        Name: "module.phase", Description: "触发说明", Version: "1.0",
    })
}
// 模块触发: 任意位置均可
errs := kc.Extensions().Execute(ctx, "module.phase", data)
```

### 9.3 新增事件主题

1. 在 [plugin.go](file:///f:/Argus/internal/kernel/plugin.go) 中添加 `Topic*` 常量
2. 发布方调用 `kc.Bus().Publish(ctx, TopicXxx, payload)`
3. 订阅方调用 `kc.Bus().Subscribe(TopicXxx, "my_id", handler)`
4. Handler 签名：`func(ctx context.Context, msg Message) error`

### 9.4 命名约定

- 扩展点名称：`模块名.阶段`（如 `spc.pre_calculate`）
- 事件主题：`模块名.事件名`（如 `assessor.result`）
- DI 绑定 key：`(*InterfaceName)(nil)` 的 reflect.Type

---

## 十、替换复杂度与缺口分析

### 10.1 替换难度

| 难度 | 组件 |
|:---:|------|
| ⭐ **低**（几行代码） | 检查器、CTI、Policy、Commander、LogCollector、Heartbeat |
| ⭐⭐ **中**（< 50 行） | SPC、Persistence、AdapterIntegration、SourceManager、Concurrency |
| ⭐⭐⭐ **高**（需验证） | SSAM 引擎、ATTACK、Assessor |

### 10.2 已知缺口

| 缺口 | 说明 | 影响 |
|------|------|:---:|
| 检查器与 DI 容器不统一 | 检查器用全局注册表，核心模块用 DI 容器 | 两套 API |
| `Evaluate` 入口不透明 | 内部调用 `checks.GetAll()`，无法覆盖检查器来源 | 适配器需手动调用 `EvaluateFromResults` |
| 适配器与原生检查器合并缺失 | 适配器结果需手动传入 `EvaluateFromResults`，无自动合并通道 | 需额外代码 |

### 10.3 统计汇总

| 类别 | 数量 |
|------|:---:|
| 核心插件接口 | 4（Plugin / PriorityPlugin / HealthCheckable / ConfigurablePlugin） |
| 已注册插件 | 15 |
| 业务模块接口 | 13 |
| DI 容器绑定 | 15 |
| 事件总线话题 | 13 |
| 总线订阅关系 | 6 |
| 扩展点总数 | 50（内核 6 + 业务模块 44） |
| 全部可替换 | ✅ |

---

## 11. 外部扩展模块与扩展包（v0.2.1+）

ASSCOR v0.2.1 引入了**外部扩展体系**——与内核集成的 ExtensionManager (extmgr) 互补的、独立编译的模块化扩展系统。核心设计原则：**外部扩展不修改内核代码，通过 Go import 和 Extension Point 系统挂载**。

### 11.1 目录结构

```
optional/                          # 外部扩展根目录（独立于内核）
├── README.md                      #   使用指南
├── SCHEMA.md                      #   package.json 格式规范
├── pkgmgr/                        #   扩展包管理工具 (asscor-pkg CLI)
│   ├── main.go                    #     6 条 CLI 命令
│   ├── manifest.go                #     package.json 解析 + 依赖求解
│   └── fetcher.go                 #     git 外部仓库克隆 + 兼容性校验
├── algorithms/                    #   按用途: 算法扩展
│   ├── modules/                   #     单模块扩展
│   │   └── multi-algo-orchestrator/ #   多算法编排器 (独立 Go module)
│   └── packages/                  #     多模块扩展包
│       └── example-pack/          #       示例扩展包
│           └── package.json       #         依赖声明 + 外部仓库引用
├── adapters/                      #   按用途: 适配器扩展
│   ├── modules/
│   └── packages/
├── checks/                        #   按用途: 检查项扩展
│   ├── modules/
│   └── packages/
└── platform/                      #   按用途: 平台层扩展
    ├── modules/
    └── packages/
```

### 11.2 单模块 vs 扩展包

ASSCOR 外部扩展提供两种形式：

| 形式 | 目录路径 | 接入方式 | 适用场景 |
|------|---------|---------|---------|
| **单模块** | `<category>/modules/<name>/` | 在 `cmd/kernel/main.go` 中 `import`，通过 `Register()` 挂载到 Extension Point | 单个独立功能（如多算法编排） |
| **扩展包** | `<category>/packages/<name>/` | 通过 `package.json` 声明模块集合、外部依赖和冲突；使用 `asscor-pkg install` 自动拉取外部仓库 | 多模块聚合、含第三方 git 仓库依赖的复杂扩展 |

单模块是不打包的独立模块。扩展包通过 `package.json` 声明所含模块、外部 git 仓库引用、依赖及冲突，支持 `asscor-pkg` 自动解析。

### 11.3 扩展包管理器 (asscor-pkg)

`asscor-pkg` 是专门管理 `optional/` 下扩展包的命令行工具。不会进入内核二进制，需独立构建：

```bash
cd optional/pkgmgr && go build -o asscor-pkg .
```

| 命令 | 功能 |
|------|------|
| `asscor-pkg resolve` | 递归扫描 `package.json`，解析依赖图、检测环、报告未解决项 |
| `asscor-pkg install` | 克隆 `external_sources` 中声明的外部 git 仓库 + 兼容性校验 |
| `asscor-pkg list` | 列出所有已发现的扩展包 |
| `asscor-pkg info <name>` | 查看扩展包详细信息（模块、依赖、外部源、兼容性） |
| `asscor-pkg graph` | 输出 DOT 格式依赖图（可管道到 `dot -Tpng`） |
| `asscor-pkg validate` | 校验所有 `package.json` 格式和字段合法性 |

#### 11.3.1 依赖求解器

- **版本约束**：支持 `>=` `<=` `>` `<` `^x.y.z` `~x.y.z` `1.0.0 - 2.0.0` `1.x` 精确匹配
- **环形依赖检测**：DFS 回溯算法，识别并报告循环依赖
- **冲突声明**：通过 `conflicts` 字段声明不兼容扩展包
- **可选依赖**：标记 `optional: true` 的依赖缺失不视为错误
- **兼容性校验**：检查 `asscor_version` / `go_version` / `ssam_version` / `platform` 约束

### 11.4 package.json 清单格式

每个扩展包根目录需包含 `package.json`。与内核 ExtensionManager 的 `extension.json` 互补——`extension.json` 面向运行时插件安装，`package.json` 面向编译时依赖管理。

```json
{
  "name": "example-security-pack",
  "version": "1.0.0",
  "description": "示例扩展包",
  "compatibility": { "asscor_version": ">=0.2.1", "go_version": ">=1.26", "platform": ["linux"] },
  "modules": [
    { "id": "multi-algo-orchestrator", "path": "../../modules/multi-algo-orchestrator" }
  ],
  "external_sources": [
    { "repo": "https://github.com/user/repo", "ref": "v1.0.0", "path": "subdir/", "target": "modules/custom-checks" }
  ],
  "dependencies": [
    { "package": "base-algorithms-pack", "version": ">=1.0.0" },
    { "package": "experimental-plugin", "version": ">=0.1.0", "optional": true }
  ],
  "conflicts": [
    { "package": "legacy-scoring-only", "versions": "<=0.5.0", "reason": "使用了弃用的评分引擎" }
  ]
}
```

完整规范见 `optional/SCHEMA.md`。

### 11.5 多算法编排器 (multi-algo-orchestrator)

位于 `optional/algorithms/modules/multi-algo-orchestrator/`，是外部扩展体系的首个单模块实现。解决单一评分算法的"木桶效应"——通过编排多个算法并行/串行/级联执行，取最低分消除单一算法偏差。

#### 11.5.1 接入方式

不修改内核代码，通过 Extension Point 系统挂载：

```go
import multialgo "github.com/asscor/asscor-optional-multi-algo"

cfg := multialgo.OrchestrationConfig{
    Mode:  multialgo.ModeCascade,
    Merge: multialgo.MergeWorstOf,
    Algorithms: []multialgo.AlgorithmProfile{
        {ID: "ssam_v2", Name: "SSAM 2.0", Role: multialgo.RolePrimary, ...},
        {ID: "baseline", Name: "基准算法", Role: multialgo.RoleSecondary, ...},
    },
}
orch := multialgo.NewOrchestrator(cfg)
orch.Register(k.PlatformExtensionRegistry())  // 订阅 assessor.pre_score 扩展点
```

#### 11.5.2 三种执行模式

| 模式 | 行为 | 适用 |
|------|------|------|
| `sequential` | 按序串行执行 | 调试验证 |
| `parallel` | goroutine 并发执行所有算法 | 高性能 |
| `cascade` | 主算法及格 (≥阈值) 则跳过辅算法 | 生产节省资源 |

#### 11.5.3 五种合并策略

| 策略 | 行为 | 消除木桶效应 |
|------|------|:---:|
| `best_of` | 取最高分 | ❌ |
| `worst_of` | **取最低分** | ✅ |
| `weighted_average` | 按算法置信度加权平均 | ⚠️ |
| `consensus` | 一致则平均，分歧取最低 | ✅ |
| `primary_only` | 仅使用主算法 | ❌ |

#### 11.5.4 检查项模式

| 模式 | 行为 |
|------|------|
| `merge` | 合并所有算法检查项，按 CheckID 去重 |
| `independent` | 各算法拥有独立检查项列表，互不干扰 |
| `tagged` | 检查项标注来源算法，评分引擎可见来源标签 |

#### 11.5.5 木桶效应度量

编排器输出中提供完整的算法间差异度量：
- `AlgoSpread`：最高分—最低分差异
- `AlgoVariance`：统计算法间方差
- `WorstAlgo` / `BestAlgo`：识别短板和长板算法
- `EliminatedByCascade`：级联模式下跳过的算法列表

---

## 结论

ASSCOR 的扩展体系提供了**四种互补的扩展机制**——进程内插件 (Plugin 接口)、运行时钩子 (Extension Point)、内核安装式扩展 (ExtensionManager + extension.json)、外部编译时扩展 (optional/ + pkgmgr + package.json)——覆盖了从底层检查逻辑到顶层评分引擎、从内核内嵌到独立编译模块的全部可扩展性需求。14 个核心模块接口全部通过 DI 容器注入，检查器通过注册表 API 管理。外部扩展通过 Extension Point 系统实现零代码侵入式挂载，扩展包通过 `asscor-pkg` 工具链管理依赖和外部仓库引用。这套体系为第三方开发者提供了从轻量级检查项到完整算法编排的全维度扩展能力。