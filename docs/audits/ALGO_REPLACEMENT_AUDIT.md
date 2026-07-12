# ASSCOR 算法可替换性专项审计

**日期**: 2026-07-12 | **审查范围**: SSAM 评分体系 + SRD 风险检测体系 | **结论**: 可替换，但两侧耦合面不同

---

## 一、审计范围与方法

逐层追踪 SSAM 和 SRD 的完整依赖链：接口定义 → 实现构造 → DI 绑定 → 消费者类型断言 → 数据桥接 → 完整性校验。判定每一层的可替换性和所需变更量。

---

## 二、SSAM 算法替换分析

### 2.1 替换目标接口

**`ssam.ScoringProvider`** (`internal/ssam/interfaces.go:31-42`):

```go
type ScoringProvider interface {
    ComputeScore(ctx context.Context, input *AssessmentInput) (*AssessmentOutput, error)
    ComputeDomainScores(checks []CheckInput) []DomainScore
    ComputeWeightedSum(domainScores []DomainScore) float64
    ApplyEdgeFactors(baseScore float64, factors []EdgeFactorResult) float64
    SetWeights(weights []WeightConfig)
    GetWeights() []WeightConfig
    SetEdgeFactors(factors []EdgeFactorConfig)
    InitializeDefaults(defaultWeights map[string]float64, defaultFactors []EdgeFactorConfig)
    SetFormula(formulaID string)
    GetFormula() string
}
```

9 个方法，覆盖评分 → 域计算 → 加权 → 边缘因子 → 权重管理 → 公式切换全生命周期。

### 2.2 当前实现链

```
ssam.NewEngine()                          ← external: github.com/chins-xing/ssam
  ↓ 内部使用 ssam.SSAMV20Formula()
  ↓ 支持 RegisterFormula() 自定义公式注册
  ↓
ssam.ScoringProvider (接口)               ← internal/ssam: re_exports 透传类型
  ↓ 字段: engine.Assessor.ssamEngine
  ↓
engine.Assessor.Assess()                  ← 3 个调用点 (assessor.go:243,447,1077)
  ↓ 构造 ssam.AssessmentInput
  ↓ 调用 a.ssamEngine.ComputeScore()
  ↓ 成功: ssam.OutputToModel() 写入 result
  ↓ 失败: computeDynamicFinalScore() 回退
  ↓
AssessorModule → ScoringEngineProvider    ← kernel 层包装
  ↓ DI Bind: k.Container().Bind()
  ↓
kernel.ScoreForHost() → CLI/API 消费      ← 最终消费端
```

### 2.3 替换耦合面 (按变更成本分级)

#### :red_circle: 必须变更 — 硬编码绑定

| # | 位置 | 当前代码 | 所需变更 |
|---|------|----------|----------|
| 1 | `engine/assessor.go:129` | `ssamEngine := ssam.NewEngine()` | 替换为 `NewMyEngine()` |
| 2 | `engine/assessor.go:118` | 字段类型 `ssamEngine ssam.ScoringProvider` | 若保留接口则无需改类型，仅改构造 |

**含义**: 只有 **1 行构造代码** 和 **1 个字段类型** 是硬绑定。字段类型若使用 `interface` 可保持不变。

#### :yellow_circle: 适配器层 — 数据桥接需重写

| # | 位置 | 功能 | 所需变更 |
|---|------|------|----------|
| 3 | `engine/assessor.go:131-132` | `ssam.ConfigToWeights(cfg)` `ssam.ConfigToEdgeFactors(cfg)` | 改为新引擎的 config→weights 适配器 |
| 4 | `engine/assessor.go:236` | `ssam.CheckResultsToInputs(result.Checks)` | 改为新引擎的 model→input 适配器 |
| 5 | `engine/assessor.go:255` | `ssam.OutputToModel(ssamOutput, result)` | 改为新引擎的 output→model 适配器 |

**含义**: `internal/ssam/adapter.go` 中的 5 个桥接函数 (`ConfigToWeights`, `ConfigToEdgeFactors`, `CheckResultsToInputs`, `DomainScoresToOutput`, `OutputToModel`) 都紧密耦合 SSAM 类型体系。替换引擎后需重写对等适配器。

#### :yellow_circle: 权重热加载路径

| # | 位置 | 功能 | 所需变更 |
|---|------|------|----------|
| 6 | `engine/assessor.go:1029` | `a.ssamEngine.SetWeights()` `a.ssamEngine.SetEdgeFactors()` | 新引擎若接口兼容则透明，否则需适配 |

#### :green_circle: 无需变更

| # | 位置 | 原因 |
|---|------|------|
| 7 | `engine/assessor.go:243,447,1077` | `ComputeScore(ctx, ssamInput)` 调用点——接口不变 |
| 8 | `kernel/assessor.go:1036` | `SSAMEngine()` 返回 `ssam.ScoringProvider`——接口不变 |
| 9 | `kernel/assessor.go:116` | `kc.Container().Bind((*ssam.ScoringProvider)(nil), ...)`——DI 绑定接口不变 |
| 10 | `cmd/kernel/main.go:212-213` | `NewScoringEngineModule(cfg)` + DI Bind——无需变更 |

**总计**: 要完整替换 SSAM，需变更 ~6 处，其中 1 处为硬编码构造，5 处为数据桥接适配器。

### 2.4 公式级替换 (轻量路径)

SSAM Engine 的 `ComputeScore()` 内部支持**公式注册机制** (`engine.go:104-118`):

```go
customFormulas := e.getCustomFormulas()
if custom, ok := customFormulas[cfg.FormulaID]; ok && custom != nil {
    finalScore = custom(domainScores, cfg.Weights, output.ThreatCoeff, output.SPCScore, edgeFactors)
} else {
    v2Result := ssam.SSAMV20Formula(...)
    finalScore = v2Result.Total
}
```

**只需 `engine.RegisterFormula(id, formula)` 即可注入新公式，无需替换整个引擎。** 这是 0 变更的路径，仅需调用 `RegisterFormula()` 一次。该能力通过 `ScoringEngineProvider.SetFormula()` 暴露给 kernel 层。

### 2.5 完整性校验影响

`internal/integrity/algo.go:16-33` 对 SSAM 常量 (默认权重、边缘因子、公式 ID) 进行 SHA-256 哈希校验:

```go
for _, w := range ssam.DefaultWeights { payload += fmt.Sprintf("dw:%s=%.4f|", ...) }
for _, ef := range ssam.DefaultEdgeFactors { payload += ... }
payload += "fid:" + ssam.DefaultScoringConfig.FormulaID + "|"
```

**影响**: 若新算法的默认常量集不同，需要:
1. 将 `expectedAlgoDigest` 设置为空字符串（记录模式），运行一次获取新摘要
2. 将获取的摘要填入 `expectedAlgoDigest` 常量
3. 或在 `[integrity]` 中设置 `verify_algo = false` 禁用校验

### 2.6 SSAM 替换评估总结

| 维度 | 评价 | 评语 |
|------|:--:|------|
| 接口抽象 | :green_circle: 充分 | `ScoringProvider` 9 方法覆盖全生命周期 |
| 硬编码耦合 | :yellow_circle: 1 处 | `ssam.NewEngine()` — 可接受 |
| 数据桥接 | :yellow_circle: 5 处 | 需重写 adapter.go 中的适配器函数 |
| 回退安全 | :green_circle: 已就绪 | 3 处调用点均有 `computeDynamicFinalScore()` 回退 |
| 公式注入 | :green_circle: 支持 | `RegisterFormula()` 可 0 变更注入自定义公式 |
| 完整性校验 | :yellow_circle: 需更新 | `VerifyAlgo()` 哈希需重新标定 |
| **总评** | **:green_circle: 可替换** | **~6 处变更，接口完好，回退安全** |

---

## 三、SRD 算法替换分析

SRD (Security Risk Detection) 负责外部安全工具 (OpenSCAP/Lynis/Generic/AtomicRed) 报告的统一处理。

### 3.1 替换目标接口

#### 3.1.1 适配器级: `srd.Adapter` (`internal/srd/adapter.go:12-18`)

```go
type Adapter interface {
    ToolID() string
    ToolName() string
    IsEnabled(cfg Config) bool
    Parse(ctx context.Context, input []byte) (*ExternalAssessmentReport, error)
    SupportsFormat(path string) bool
}
```

5 方法，全局注册表 `srd.Register()` 管理。当前注册: OpenSCAP, Lynis, Generic, AtomicRed。

#### 3.1.2 管理器级: `srd.SRDManagerInterface` (`internal/srd/manager.go:407-413`)

```go
type SRDManagerInterface interface {
    ProcessReport(ctx context.Context, toolID string, data []byte) (*SRDResult, error)
    ProcessFile(ctx context.Context, path string) (*SRDResult, error)
    LatestResult(hostID string) *SRDResult
    GetHistory(hostID string) []*SRDResult
    AllResults() map[string]*SRDResult
}
```

5 方法，由 `SRDPlugin` (kernel 包装器) 消费。

### 3.2 当前实现链

```
srd.Manager (内部实现)
  ├── srd.Pipeline (内部实现, 无接口抽象)
  │     ├── ascorprism.Engine (Prism 引擎)
  │     ├── adapter.Parse() → ExternalAssessmentReport
  │     ├── reportToNodeState() → prismlib.NodeState
  │     ├── prism.ComputeDynamicScore() → AssetRiskResult
  │     ├── prism.ComputeSemanticState() → SemanticRiskReport
  │     └── prism.PredictFuture() → FutureRiskReport
  ├── scanLoop() 定时扫描目录
  └── publishResult() → bus topic "srd.external_result"

kernel.SRDPlugin (包装器)
  └── kernel.Plugin 接口
        └── cmd/kernel/main.go:232 注册
```

### 3.3 替换路径分析

#### 路径 A: 工具适配器替换 (轻量)

只需实现 `srd.Adapter` (5 方法) 并调用 `srd.Register(adapter)`。无需改动任何现有代码。

**消费**: `srd.Pipeline.ProcessFromBytes()` 和 `srd.Pipeline.ProcessFromFile()` 通过 `srd.Get(toolID)` 查找适配器。

**评估**: :green_circle: **完全解耦。** 适配器注册表为全局 map，支持运行时增删。

#### 路径 B: 管理器级替换 (中度)

创建新的插件实现 `kernel.Plugin`，替代 `kernel.NewSRDPlugin()`。

1. 实现 `kernel.Plugin` 8 方法 (`Info`, `Dependencies`, `Priority`, `Init`, `Start`, `Stop`, `State`)
2. 在 `cmd/kernel/main.go:232` 替换注册
3. **关键集成点**: 发布到 bus topic `"srd.external_result"` (若其他组件依赖此 topic)
4. 与 kernel 的桥接通过 `KernelContext` 接口完成

**评估**: :green_circle: **可替换。** `SRDPlugin` 仅 ~90 行，纯适配器模式。

#### 路径 C: Pipeline 替换 (深度)

`srd.Pipeline` 是内部实现类型 (未暴露接口)。其核心功能:

1. 调用 Prism 引擎 (`ascorprism.Engine`) 进行动态评分
2. 将 `ExternalAssessmentReport` → `prismlib.NodeState`
3. 计算语义状态和未来推断

要替换 Pipeline，需要:
- 修改 `srd.Manager` 或创建自定义 Manager
- 自定义 Manager 需实现 `SRDManagerInterface` (5 方法)
- Pipeline 创建在 `srd.NewPipeline()` (`pipeline.go:24`)，硬编码了 `ascorprism.NewEngine()`

**评估**: :yellow_circle: **可行但有耦合。** Pipeline 硬依赖 Prism 引擎。若需同时替换 Prism + SRD 处理逻辑，需自定义 Manager。

### 3.4 SSAM/SRD 独立性验证

| 检查项 | 结果 |
|--------|:--:|
| SRD 是否引用 `internal/ssam` 包? | :x: 否 |
| SRD 是否调用 `ssam.ScoringProvider`? | :x: 否 |
| SRD 的 `node.SSAMScore` 字段来源? | `report.RawScore` — 外部工具原始分，非 ASSCOR SSAM 引擎 |
| SRD Pipeline 使用什么评分引擎? | Prism (`ascorprism.Engine`) — 独立于 SSAM |
| SRD 发布到哪个 bus topic? | `"srd.external_result"` — 独立 topic |

**:green_circle: SRD 与 SSAM 完全解耦。** 可以独立替换任意一方。

### 3.5 SRD 替换评估总结

| 维度 | 评价 | 评语 |
|------|:--:|------|
| 适配器抽象 | :green_circle: 充分 | `srd.Adapter` 5 方法 + 全局注册表，运行时可插拔 |
| 管理器抽象 | :green_circle: 充分 | `SRDManagerInterface` 5 方法，通过 `kernel.Plugin` 包装 |
| Pipeline 抽象 | :yellow_circle: 缺失 | 内部实现类型，硬依赖 Prism |
| 与 SSAM 耦合 | :green_circle: 无 | 包 import、调用、数据类型均完全独立 |
| **总评** | **:green_circle: 可替换** | **适配器级 0 变更，管理器级 ~90 行新插件，Pipeline 级需新 Manager** |

---

## 四、综合结论

### 4.1 替换可行性矩阵

| 替换目标 | 变更量 (行) | 变更文件数 | 风险等级 |
|----------|:--:|:--:|:--:|
| SSAM 评分公式 | 0 | 0 | :green_circle: 无风险 — `RegisterFormula()` API |
| SSAM 完整引擎 | ~100 | ~4 | :yellow_circle: 低风险 — 接口保护，3 处回退 |
| SRD 工具适配器 | ~100 新增 | 1 新增 | :green_circle: 无风险 — 全局注册表 |
| SRD 完整管理器 | ~200 新增 | 2-3 | :yellow_circle: 低风险 — Plugin 接口隔离 |
| SRD Pipeline | ~300 新增 | 3-4 | :yellow_circle: 中风险 — 需新 Manager + 自定义管线 |
| Prism 引擎 | ~150 | ~4 | :yellow_circle: 中风险 — AssessorModule + SRD 均依赖 |

### 4.2 关键架构优势

1. **:lock: 接口先行模式**: SSAM `ScoringProvider` 和 SRD `Adapter` 均先定义接口再实现，替换者只需满足契约
2. **:recycle: 多级回退**: 3 个 `ComputeScore` 调用点均有 legacy 回退路径，新算法崩溃不影响可用性
3. **:electric_plug: 公式热注册**: `RegisterFormula()` 允许运行时注入新公式，无需重启
4. **:shield: 完整性可选**: `verify_algo = false` 可跳过新算法的常量校验
5. **:link: SSAM/SRD 完全解耦**: 两套系统无任何代码级耦合，可独立迁移

### 4.3 建议的替换执行顺序

```
Phase 1: 注入自定义公式 → RegisterFormula("my-v3", myFormula)
Phase 2: 切换到新公式 → SetFormula("my-v3")
Phase 3: 验证分数差异 → 对比 FinalScore / Acceptable / DomainScores
Phase 4: 替换完整引擎 → 实现 ScoringProvider → 替换 NewEngine() 调用
Phase 5: 更新完整性哈希 → 运行一次获取新 digest → 填入 const
Phase 6: (可选) 替换 SRD 适配器 → srd.Register(myAdapter)
```

**:white_check_mark: ASSCOR 可以做到完整的 SSAM 基础算法和 SRD 风险检测算法替换。**
