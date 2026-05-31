# ASSCOR 扩展接口报告

**版本**：v1.0
**日期**：2026-06-01
**配套文档**：ASSCOR 工程实现白皮书、ASSCOR 使用手册

---

## 一、插件生命周期接口

所有 ASSCOR 模块必须实现 `Plugin` 接口，核心定义位于 [plugin.go](file:///f:/Argus/internal/kernel/plugin.go#L102-L114)。

### 1.1 Plugin（核心接口）

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
| 1 | ConfigWatcherModule | 配置文件监听，最高优先级，确保配置先加载 |
| 2 | ConcurrencyModule | 并发控制基础设施，其他模块依赖其 WorkerPool |
| 3 | PersistenceModule | 持久化层，为其他模块提供数据存储能力 |
| 5 | HeartbeatModule | Agent 心跳管理 |
| 10 | CTIModule | 网络威胁情报 |
| 20 | SPCModule | 安全态势计算（CVE/EPSS/KEV 数据源） |
| 21 | ATTACKModule | ATT&CK 知识库与行为分析 |
| 100 | ScoringEngineModule / AssessorModule / PolicyModule / CommanderModule / LogCollectorModule / AdapterIntegrationModule / SourceManagerModule / CLIModule | 业务层模块，在基础设施就绪后启动 |

### 1.3 HealthCheckable（健康检查）

```go
type HealthCheckable interface {
    HealthCheck(ctx context.Context) error
}
```

实现者：SPCModule、ConcurrencyModule 等。Kernel 的 `HealthCheck()` 方法遍历所有实现此接口的插件并收集状态：

```go
type PluginHealthStatus struct {
    Name    string `json:"name"`
    Healthy bool   `json:"healthy"`
    Error   string `json:"error,omitempty"`
}
```

### 1.4 ConfigurablePlugin（热加载配置）

```go
type ConfigurablePlugin interface {
    Plugin
    Configure(config map[string]string) error
}
```

热加载时 Kernel 调用 `Configure(k.config)` 注入新配置，插件自行处理配置变更逻辑。

### 1.5 辅助类型

```go
type PluginInfo struct {
    Name        string
    Version     string
    Description string
    Author      string
}

type PluginDependency struct {
    Interface interface{}
    Name      string
}
```

---

## 二、DI 容器接口与绑定表

DI 容器定义于 [di.go](file:///f:/Argus/internal/kernel/di.go)，提供类型安全的依赖注入。

### 2.1 容器接口

| 方法 | 签名 | 说明 |
|------|------|------|
| `Bind` | `(iface interface{}, impl interface{})` | 以接口的 reflect.Type 为 key 注册实现 |
| `BindNamed` | `(name string, iface interface{}, impl interface{})` | 命名绑定，同时写入别名映射 |
| `Resolve` | `(iface interface{}) (interface{}, bool)` | 按类型查找实现 |
| `ResolveNamed` | `(name string) (interface{}, bool)` | 按名称查找实现 |
| `Inject` | `(target interface{}) error` | 通过 `inject:"true"` 或 `inject:"名称"` 标签自动注入 |
| `Remove` | `(iface interface{})` | 移除绑定 |
| `Count` | `() int` | 返回已绑定数量 |

### 2.2 完整 DI 绑定表

| 序号 | 文件 | 行号 | 绑定接口 | 绑定实例 |
|:---:|------|:---:|------|------|
| 1 | [assessor.go](file:///f:/Argus/internal/kernel/assessor.go#L92) | L92 | `(*ssam.ScoringProvider)(nil)` | `m.engine.SSAMEngine()` |
| 2 | [assessor.go](file:///f:/Argus/internal/kernel/assessor.go#L99) | L99 | `(*AssessorInterface)(nil)` | `m` (AssessorModule) |
| 3 | [persistence.go](file:///f:/Argus/internal/kernel/persistence.go#L261) | L261 | `(*PersistenceInterface)(nil)` | `m` (PersistenceModule) |
| 4 | [workerpool.go](file:///f:/Argus/internal/kernel/workerpool.go#L209) | L209 | `(*ConcurrencyInterface)(nil)` | `m` (ConcurrencyModule) |
| 5 | [workerpool.go](file:///f:/Argus/internal/kernel/workerpool.go#L210) | L210 | `(*WorkerPoolInterface)(nil)` | `m.workerPool` |
| 6 | [spc.go](file:///f:/Argus/internal/kernel/spc.go#L447) | L447 | `(*SPCInterface)(nil)` | `m` (SPCModule) |
| 7 | [adapter_integration.go](file:///f:/Argus/internal/kernel/adapter_integration.go#L56) | L56 | `(*AdapterIntegrationInterface)(nil)` | `m` (AdapterIntegrationModule) |
| 8 | [cti.go](file:///f:/Argus/internal/kernel/cti.go#L47) | L47 | `(*CTIInterface)(nil)` | `m` (CTIModule) |
| 9 | [heartbeat.go](file:///f:/Argus/internal/kernel/heartbeat.go#L55) | L55 | `(*HeartbeatInterface)(nil)` | `m` (HeartbeatModule) |
| 10 | [attck.go](file:///f:/Argus/internal/kernel/attck.go#L292) | L292 | `(*ATTACKInterface)(nil)` | `m` (ATTACKModule) |
| 11 | [commander.go](file:///f:/Argus/internal/kernel/commander.go#L106) | L106 | `(*CommanderInterface)(nil)` | `m` (CommanderModule) |
| 12 | [policy.go](file:///f:/Argus/internal/kernel/policy.go#L86) | L86 | `(*PolicyInterface)(nil)` | `m` (PolicyModule) |
| 13 | [source_manager.go](file:///f:/Argus/internal/kernel/source_manager.go#L157) | L157 | `(*SourceManagerInterface)(nil)` | `m` (SourceManagerModule) |
| 14 | [collector.go](file:///f:/Argus/internal/kernel/collector.go#L74) | L74 | `(*LogCollectorInterface)(nil)` | `m` (LogCollectorModule) |

> **注**：`ScoringEngineProvider` 接口在 [main.go](file:///f:/Argus/cmd/kernel/main.go#L131) 中额外绑定，用于跨层注入。

### 2.3 典型注入模式

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
| `RegisterPoint(point ExtensionPoint)` | 注册扩展点，已存在则 panic |
| `RegisterExtension(pointName string, id string, handler ExtensionHandler) error` | 注册扩展处理器 |
| `Execute(ctx, pointName string, data interface{}) []error` | 执行所有处理器（全部执行，收集错误） |
| `ExecuteUntilFirst(ctx, pointName string, data interface{}) (interface{}, error)` | 执行到第一个非 nil 结果 |
| `UnregisterPlugin(id string)` | 移除指定插件的所有扩展 |
| `ListPoints() []ExtensionPoint` | 列出所有已注册扩展点 |
| `ListExtensions(pointName string) []string` | 列出指定扩展点的处理器 ID |

### 4.3 内核级扩展点（kernel.go）

共 6 个，在 `NewKernel()` 中注册：

| 扩展点名称 | 触发时机 | 版本 |
|-----------|---------|------|
| `kernel.pre_init` | 所有插件 Init 之前 | 1.0 |
| `kernel.post_init` | 所有插件 Init 之后 | 1.0 |
| `kernel.pre_start` | 所有插件 Start 之前 | 1.0 |
| `kernel.post_start` | 所有插件 Start 之后 | 1.0 |
| `kernel.pre_stop` | 关闭序列开始前 | 1.0 |
| `kernel.post_stop` | 所有插件 Stop 之后 | 1.0 |

### 4.4 业务模块扩展点

#### AssessorModule（2 个）

| 扩展点名称 | 触发时机 |
|-----------|---------|
| `assessor.pre_evaluate` | 每次主机评估之前 |
| `assessor.post_evaluate` | 每次主机评估完成之后 |

#### SPCModule（3 个）

| 扩展点名称 | 触发时机 |
|-----------|---------|
| `spc.pre_calculate` | SPC 计算之前 |
| `spc.post_calculate` | SPC 计算完成之后 |
| `spc.cve_updated` | CVE 缓存刷新时 |

#### ATTACKModule（13 个）

| 扩展点名称 | 触发时机 | 分类 |
|-----------|---------|------|
| `attck.coverage.complete` | 覆盖率分析完成 | 覆盖率 |
| `attck.apt.matched` | APT 组织匹配检测到 | APT 归因 |
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

> ATTACKModule 拥有最多的扩展点（13 个），覆盖 ATT&CK 分析生命周期的所有关键阶段，是系统中最可扩展的模块。

### 4.5 扩展点注册示例

```go
// 模块 Init 中注册扩展点
kc.Extensions().RegisterPoint(ExtensionPoint{
    Name:        "spc.pre_calculate",
    Description: "Called before SPC calculation",
    Version:     "1.0",
})

// 其他模块注册处理器
kc.Extensions().RegisterExtension("spc.pre_calculate", "my_plugin",
    func(ctx context.Context, data interface{}) error {
        // 在 SPC 计算前执行自定义逻辑
        return nil
    },
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

### 5.6 HeartbeatInterface

[heartbeat.go:L223-L229](file:///f:/Argus/internal/kernel/heartbeat.go#L223-L229) — Agent 心跳管理

```go
type HeartbeatInterface interface {
    RecordHeartbeat(hostID string)
    RegisterAgent(hostID, hostname, version string)
    GetAgent(hostID string) *AgentRecord
    ListAgents() []*AgentRecord
    IsAlive(hostID string) bool
}
```

### 5.7 CommanderInterface

[commander.go:L324-L328](file:///f:/Argus/internal/kernel/commander.go#L324-L328) — 命令下发

```go
type CommanderInterface interface {
    EnqueueCommand(hostID string, action string, params map[string]string) string
    DequeueCommands(hostID string) []*apiv1.Command
    AckCommand(hostID string, cmdID string, success bool, output string)
}
```

### 5.8 PersistenceInterface

[persistence.go:L651-L661](file:///f:/Argus/internal/kernel/persistence.go#L651-L661) — 数据持久化

```go
type PersistenceInterface interface {
    Append(dataset string, record interface{}) error
    AppendBatch(dataset string, records []interface{}) error
    WriteAudit(entry AuditEntry) error
    WriteCommand(record CommandRecord) error
    WriteAssessment(record AssessmentRecord) error
    WriteDashboardReport(report *DashboardReport) error
    WriteCVECache(record CVECacheRecord) error
    RotateAll()
    DataDir() string
}
```

### 5.9 ConcurrencyInterface / WorkerPoolInterface

[workerpool.go:L304-L321](file:///f:/Argus/internal/kernel/workerpool.go#L304-L321) — 并发控制

```go
type ConcurrencyInterface interface {
    Submit(task func() error)
    SubmitWithTimeout(task func() error, timeout time.Duration)
    Wait()
    Pool() *WorkerPool
    HealthCheck(ctx context.Context) *ConcurrencyStatus
    CheckAlerts() []string
}

type WorkerPoolInterface interface {
    Submit(task func() error)
    SubmitWithTimeout(task func() error, timeout time.Duration)
    Wait()
    ActiveWorkers() int
    AvailableSlots() int
    MaxConcurrency() int
    Metrics() WorkerPoolMetrics
}
```

### 5.10 ATTACKInterface

[attck.go:L1560-L1639](file:///f:/Argus/internal/kernel/attck.go#L1560-L1639) — ATT&CK 知识库与分析

```go
type ATTACKInterface interface {
    GetAllTactics() []ATTACKTactic
    GetTechniquesByTactic(tacticID string) []ATTACKTechnique
    CalculateCoverage(checkResults map[string]bool) []ATTACKCoverage
    GetCoverageSummary(checkResults map[string]bool) map[string]interface{}
    MatchAPTGroup(detectedTechniques []string) []APTMatchResult
    GetAPTGroup(groupID string) *APTGroupProfile
    ListAPTGroups() []string
    PredictRisk(hostID string, detectedTechniques []string, maxDepth int) PredictiveRisk
    AssessKillChain(hostID string, checkResults map[string]bool) KillChainAssessment
    GetTransitionMatrix() TransitionMatrix
    AddTechniqueToTactic(tacticID string, tech ATTACKTechnique)
    UpdateCheckMapping(techID string, AsscorChecks []string)
    UpsertAPTGroup(profile APTGroupProfile)
    Version() string
    // 检测、IOC、威胁情报、仿真、评估、行为分析、APT 归因、狩猎等完整方法
    // （完整共 80 行接口定义）
}
```

### 5.11 AdapterIntegrationInterface

[adapter_integration.go:L198-L201](file:///f:/Argus/internal/kernel/adapter_integration.go#L198-L201) — 外部适配器集成

```go
type AdapterIntegrationInterface interface {
    RunAdapters(ctx context.Context) []adapter.PipelineResult
    CollectFindings() []model.CheckResult
}
```

### 5.12 LogCollectorInterface

[collector.go:L177-L180](file:///f:/Argus/internal/kernel/collector.go#L177-L180) — 日志收集

```go
type LogCollectorInterface interface {
    Append(entry *apiv1.LogEntry) error
    AppendBatch(entries []*apiv1.LogEntry) error
}
```

### 5.13 SourceManagerInterface

[source_manager.go:L88-L103](file:///f:/Argus/internal/kernel/source_manager.go#L88-L103) — 外部源生命周期管理

```go
type SourceManagerInterface interface {
    DeploySource(ctx context.Context, spec SourceSpec, cfg SourceConfig) error
    UninstallSource(ctx context.Context, id string, force bool) error
    EnableSource(ctx context.Context, id string) error
    DisableSource(ctx context.Context, id string) error
    UpdateSource(ctx context.Context, id string, version string) error
    GetSourceStatus(id string) (*SourceStatus, bool)
    ListSources(category SourceCategory) []SourceStatus
    ListAllSources() []SourceStatus
    ConfigureSource(ctx context.Context, id string, cfg SourceConfig) error
    GetSourceConfig(id string) (*SourceConfig, bool)
    GetSourceSpec(id string) (*SourceSpec, bool)
    RunSourceNow(ctx context.Context, id string) error
    GetAuditLog(sourceID string, limit int) []AuditLogEntry
    HealthCheck(ctx context.Context) error
}
```

---

## 六、模块间依赖关系

```
                         ┌──────────────┐
                         │ ConfigWatcher│ (P=1)
                         └──────┬───────┘
                                │ 触发配置重载
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
   ┌──────────┐          ┌───────────┐          ┌──────────┐
   │ SPCM     │          │ Assessor  │          │ Policy   │
   │ (P=20)   │          │ (P=100)   │          │ (P=100)  │
   └────┬─────┘          └─────┬─────┘          └────┬─────┘
        │  P_score              │                     │
        │  ┌────────────────────┘                     │
        ▼  ▼ 评估结果(TopicAssessorResult)            │
   ┌──────────┐          ┌───────────┐          ┌────┴─────┐
   │ ATTACK   │          │Persistence│          │Commander │
   │ (P=21)   │          │ (P=3)     │          │ (P=100)  │
   └────┬─────┘          └───────────┘          └────┬─────┘
        │                                             │
        │ 覆盖率/APT 归因                               │ 策略动作
        │                                    (TopicPolicyAction)
        ▼                                             │
   ┌──────────┐                              ┌───────┴─────┐
   │ CTI      │                              │    Agent    │
   │ (P=10)   │                              │  (远程主机)  │
   └──────────┘                              └─────────────┘
```

**基础设施层（P=1~3）**：ConfigWatcher → Concurrency → Persistence
**数据层（P=5~21）**：Heartbeat → CTI → SPC → ATTACK
**业务层（P=100）**：ScoringEngine / Assessor / Policy / Commander / LogCollector / AdapterIntegration / SourceManager / CLI

---

## 七、插件注册与启动

所有插件在 [main.go:L130-L153](file:///f:/Argus/cmd/kernel/main.go#L130-L153) 中实例化并注册：

```go
// 特殊绑定：ScoringEngineProvider
scoringEngine := kernel.NewScoringEngineModule(cfg)
k.Container().Bind((*kernel.ScoringEngineProvider)(nil), scoringEngine)

// 标准模块实例化
assessor     := &kernel.AssessorModule{}
policy       := &kernel.PolicyModule{}
spc          := kernel.NewSPCModule()
cti          := &kernel.CTIModule{}
commander    := &kernel.CommanderModule{}
logCollector := &kernel.LogCollectorModule{}
heartbeat    := &kernel.HeartbeatModule{}
persistence  := kernel.NewPersistenceModule("data")
concurrency  := kernel.NewConcurrencyModule(10)
attck        := kernel.NewATTACKModule()
configWatcher := kernel.NewConfigWatcherModule(resolvedConfigPath)
adapterIntegration := kernel.NewAdapterIntegrationModule()
sourceManager := kernel.NewSourceManagerModule()
cliModule    := cli.NewCLIModule()

// 批量注册
for _, p := range []kernel.Plugin{
    heartbeat, spc, cti, scoringEngine, assessor,
    policy, commander, logCollector, persistence,
    concurrency, attck, configWatcher, adapterIntegration,
    sourceManager, cliModule,
} {
    if err := k.RegisterPlugin(p); err != nil {
        log.Error("register plugin failed", "error", err)
        os.Exit(1)
    }
}
```

---

## 八、扩展开发快速指南

### 8.1 新增插件清单

1. 实现 `Plugin` 接口（`Info/Dependencies/Init/Start/Stop/State`）
2. 如需控制启动顺序，实现 `PriorityPlugin` 接口
3. 如需健康检查，实现 `HealthCheckable` 接口
4. 如需热加载配置，实现 `ConfigurablePlugin` 接口
5. 在 `Init` 中：
   - 通过 `kc.Container().Resolve()` 获取依赖
   - 通过 `kc.Container().Bind()` 注册自身接口
   - 通过 `kc.Extensions().RegisterPoint()` 注册扩展点
6. 在 `Start` 中：
   - 通过 `kc.Bus().Subscribe()` 订阅事件
   - 启动 goroutine
7. 在 `Stop` 中：
   - 关闭 goroutine（通过 context 或 channel）
   - 清理资源
8. 在 [main.go](file:///f:/Argus/cmd/kernel/main.go) 中实例化并注册

### 8.2 新增扩展点清单

```go
// 1. 在模块 Init 中注册扩展点
kc.Extensions().RegisterPoint(ExtensionPoint{
    Name:        "module.phase",
    Description: "触发说明",
    Version:     "1.0",
})

// 2. 在关键逻辑点执行扩展
errs := kc.Extensions().Execute(ctx, "module.phase", data)

// 或获取第一个结果
result, err := kc.Extensions().ExecuteUntilFirst(ctx, "module.phase", data)
```

### 8.3 新增事件主题清单

1. 在 [plugin.go](file:///f:/Argus/internal/kernel/plugin.go) 中添加 `Topic*` 常量
2. 发布方在关键点调用 `kc.Bus().Publish(ctx, TopicXxx, payload)`
3. 订阅方在 `Start` 中调用 `kc.Bus().Subscribe(TopicXxx, "my_id", handler)`
4. Handler 签名：`func(ctx context.Context, msg Message) error`

### 8.4 命名约定

- 扩展点名称：`模块名.阶段`（如 `spc.pre_calculate`、`assessor.post_evaluate`）
- 事件主题：`模块名.事件名`（如 `assessor.result`、`spc.updated`）
- DI 绑定 key：`(*InterfaceName)(nil)` 的 reflect.Type
- `inject` 标签：`inject:"true"` 或 `inject:"名称"`

---

## 九、统计汇总

| 类别 | 数量 |
|------|:---:|
| 核心插件接口 | 4（Plugin / PriorityPlugin / HealthCheckable / ConfigurablePlugin） |
| 已注册插件 | 15 |
| 业务模块接口 | 13 |
| DI 容器绑定 | 14 |
| 事件总线话题 | 13 |
| 总线订阅关系 | 6 |
| 扩展点总数 | 25（内核 6 + Assessor 2 + SPC 3 + ATTACK 13） |
| 辅助类型 | 5（PluginInfo / PluginDependency / KernelContext / BusAccess / MessageProtocol） |

```
