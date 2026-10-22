# SSAM 接口规范与接入指南

> **版本**：SSAM 2.0 | **模块路径**：`github.com/chins-xing/ssam`  
> **ASSCOR 适配层**：`f:\Argus\internal\engine\ssam\` (薄适配层，委托给 ssam-lib)  
> **日期**：2026-06-28 | **状态**：发布

本文档详细说明 SSAM 独立算法模块的接口规范、数据结构定义、配置适配机制及接入方式。SSAM V2.0 已独立为纯函数式 Go 模块 `github.com/chins-xing/ssam`（位于 `ssam-lib/`），可脱离 ASSCOR 框架独立使用。ASSCOR 平台通过 `internal/engine/ssam/` 薄适配层委托调用 ssam-lib。

---

## 1. 模块概览

`github.com/chins-xing/ssam`（`ssam-lib/`）是 SSAM V2.0 的纯函数式引擎，零外部依赖。包含以下文件：

| 文件 | 职责 |
|------|------|
| `ssam.go` | 纯函数评分入口：`ComputeScore` / `ComputeScoreWithConfidence`、`ComputeDomainScores`、`ComputeWeightedSum`、`ApplyEdgeFactors*` |
| `types.go` | V1.x 数据类型定义（`AssessmentInput`, `AssessmentOutput` 等），保持向后兼容 |
| `types_v2.go` | V2.0 数据类型：`RiskContext`, `RiskLayerDetail`, `RiskLayers`, `FinalScore`, `AssessmentInputV2`, `AssessmentOutputV2`, `ScoringFormulaV2` |
| `formulas.go` | V1.x 公式实现（`ssam_v1.2`, `simple_weighted`） |
| `formulas_v2.go` | V2.0 公式 `SSAMV20Formula` 与 `ComputeScoreV2`：三层语义模型（本征/暴露/威胁）加权 |
| `ir.go` | SSAM IR JSON 中间表示：`AssessmentOutputV2.ToIR()` 输出机器可读的结构化评估结果 |
| `ast.go` | 公式 AST：`FormulaAST`、`EvalAST`、`ASTToFormula`、`RegisterEdgeFactorStrategy`（**无字符串解析器**） |
| `formulas_ast.go` | 内置 AST：`SSAMV12AST()` / `SSAMV20AST()` |
| `confidence.go` | 置信度策略、贝叶斯后验与可接受性判定 |
| `domain_adjust.go` | 域级修正注册（`RegisterDomainAdjust`） |
| `defaults.go` | 默认权重、边缘因子与 `DefaultScoringConfig` |
| `validation.go` | `ValidateInput` / `ValidateOutput` |
| `errors.go` | `SSAMError` 与错误变量 |
| `*_test.go` | 6 个测试文件：`ast_test.go` / `confidence_test.go` / `domain_adjust_test.go` / `ir_test.go` / `ssam_test.go` / `ssam_v2_test.go` |

> **分层提示**：ssam-lib 只提供纯函数，**不含** `Engine` / `Provider` / 钩子。`Engine`、`Provider` 与钩子属于 ASSCOR 适配层 `internal/engine/ssam/`（见 §2）。

ASSCOR 适配层（`internal/engine/ssam/`，build tag `engine`）的非测试文件共 **6 个**：

| 文件 | 职责 |
|------|------|
| `engine.go` | `Engine` 实现 `Provider`；钩子调度、公式选择、委托 ssam-lib 评分 |
| `interfaces.go` | `Provider` / `ScoringProvider` / `DomainProvider` / `EdgeFactorProvider` / `HookProvider` 定义 |
| `adapter.go` | ASSCOR 配置/模型与 SSAM 格式的双向转换 |
| `adapter_engine.go` | `EngineAdapter` 实现内核 `kernel.AssessorEngine` |
| `edgefactor.go` | 边缘因子触发映射与模型参数适配 |
| `re_exports.go` | ssam-lib 类型别名与符号转发 |

---

## 2. 核心接口（ASSCOR 适配层）

> 本节及 §2.2–§2.5 描述的是 **ASSCOR 适配层** `internal/engine/ssam/` 的接口（build tag `engine`），**不是** `ssam-lib` 的公开 API。独立使用 ssam-lib 时请直接调用 §6 的 AST 与 §8.1 的 `ComputeScore` 纯函数。

### 2.1 Provider 聚合接口

`Provider` 定义在 `internal/engine/ssam/interfaces.go`，聚合四个子接口：

```go
type Provider interface {
    ScoringProvider
    DomainProvider
    EdgeFactorProvider
    HookProvider
}
```

`Engine`（`internal/engine/ssam/engine.go:17`）实现 `Provider`，编译期断言位于 `engine.go:37`：

```go
var _ Provider = (*Engine)(nil)
```

### 2.2 ScoringProvider — 评分接口

```go
type ScoringProvider interface {
    ComputeScore(ctx context.Context, input *AssessmentInput) (*AssessmentOutput, error)
    ComputeDomainScores(checks []CheckInput) []DomainScore
    ComputeWeightedSum(domainScores []DomainScore) float64
    ApplyEdgeFactors(baseScore float64, factors []EdgeFactorResult) float64
    SetWeights(weights []WeightConfig)
    GetWeights() []WeightConfig
    SetFormula(formulaID string)
    GetFormula() string
}
```

| 方法 | 说明 |
|------|------|
| `ComputeScore` | 完整评分流程：输入验证 → 域评分 → 边缘因子 → 公式计算 → 输出 |
| `ComputeDomainScores` | 按域聚合检查项，计算各域百分制得分 |
| `ComputeWeightedSum` | 计算域得分的加权和 |
| `ApplyEdgeFactors` | 对基础分应用活跃边缘因子的乘法修正 |
| `SetWeights` / `GetWeights` | 动态设置/获取核心域权重 |
| `SetFormula` / `GetFormula` | 设置/获取评分公式 ID；适配层 `ComputeScore` 在未注册同名自定义公式时固定使用 V2 三层公式（`SSAMV20Formula`），内置 V1 公式仅在直接调用 ssam-lib 时生效 |

### 2.3 DomainProvider — 域信息接口

```go
type DomainProvider interface {
    ListDomains() []string
    GetDomainLabel(id string) string
    GetDefaultWeight(id string) float64
}
```

| 方法 | 说明 |
|------|------|
| `ListDomains` | 返回已配置权重的所有域 ID（排序后） |
| `GetDomainLabel` | 返回域的可读标签（默认返回域 ID 本身） |
| `GetDefaultWeight` | 返回指定域的权重值，未配置则返回 0 |

### 2.4 EdgeFactorProvider — 边缘因子接口

```go
type EdgeFactorProvider interface {
    ListEdgeFactors() []EdgeFactorResult
    EvaluateEdgeFactors(checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult
}
```

| 方法 | 说明 |
|------|------|
| `ListEdgeFactors` | 返回所有已注册的边缘因子配置（Active=false） |
| `EvaluateEdgeFactors` | 根据检查结果评估边缘因子触发状态，返回含 Active 标记的结果 |

### 2.5 HookProvider — 钩子接口

```go
type HookProvider interface {
    RegisterHook(phase HookPhase, id string, hook AssessmentHook, priority int)
    UnregisterHook(id string)
    ExecuteHooks(ctx context.Context, phase HookPhase, input *AssessmentInput, output *AssessmentOutput) []error
}
```

| 方法 | 说明 |
|------|------|
| `RegisterHook` | 在指定阶段注册钩子函数，priority 越小越先执行 |
| `UnregisterHook` | 按 ID 移除钩子 |
| `ExecuteHooks` | 执行指定阶段的所有钩子（按 priority 排序），返回错误列表 |

钩子阶段定义：

```go
type HookPhase string

const (
    HookPreScore  HookPhase = "pre_score"   // 域评分前
    HookPostScore HookPhase = "post_score"  // 域评分后
    HookPreEdge   HookPhase = "pre_edge"    // 边缘因子评估前
    HookPostEdge  HookPhase = "post_edge"   // 边缘因子评估后
)
```

钩子函数签名：

```go
type AssessmentHook func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error
```

---

## 3. 数据结构

### 3.1 AssessmentInput — 评估输入

```go
type AssessmentInput struct {
    HostID       string             `json:"host_id"`
    Hostname     string             `json:"hostname"`
    Timestamp    time.Time          `json:"timestamp"`
    Threshold    float64            `json:"threshold"`
    Checks       []CheckInput       `json:"checks"`
    ThreatCoeff  float64            `json:"threat_coefficient"`
    SPCScore     float64            `json:"spc_score"`
    WeightShifts map[string]float64 `json:"weight_shifts,omitempty"`
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `HostID` | string | 主机唯一标识 |
| `Hostname` | string | 主机名 |
| `Timestamp` | time.Time | 评估时间戳 |
| `Threshold` | float64 | 可接受阈值（0–100），默认 80 |
| `Checks` | []CheckInput | 检查项结果列表 |
| `ThreatCoeff` | float64 | 威胁态势系数（0.60–1.00），0 时自动设为 1.0 |
| `SPCScore` | float64 | SPC 态势修正因子（0.60–1.00），0 时自动设为 1.0 |

> ?? **SPC 评估方法声明**：`SPCScore` 由 SPC 模块基于 CPE 字符串匹配（软件包名称/版本 ? CVE 数据库受影响产品版本）计算得出，不涉及漏洞利用验证、运行时可达性分析或二进制分析。详见 [SPC 安全态势计算模块技术白皮书](../whitepapers/SPC安全态势计算模块技术白皮书.md)。
| `WeightShifts` | map | SPC 输出的域权重临时偏移（可选） |

### 3.2 CheckInput — 检查项输入

```go
type CheckInput struct {
    CheckID    string  `json:"check_id"`
    Domain     string  `json:"domain"`
    Name       string  `json:"name"`
    Passed     bool    `json:"passed"`
    Delta      float64 `json:"delta"`
    Detail     string  `json:"detail"`
    Confidence float64 `json:"confidence,omitempty"` // 情报可信度（方向①）
}
```

| 字段 | 说明 |
|------|------|
| `CheckID` | 检查项唯一标识（如 `AS-001`、`BC-003`） |
| `Domain` | 所属核心域（`attack_surface`/`business_continuity`/`operation_trust`/`resilience`） |
| `Name` | 检查项名称 |
| `Passed` | 是否通过 |
| `Delta` | 未通过时的扣分值（负数，如 -15） |
| `Detail` | 检查详情说明 |
| `Confidence` | 本条情报的可信度 ∈ [0,1]；**0 = 未指定**，由生效的 `ConfidencePolicy` 归一为 `Default`。`enabled=false` 时恒按 1.0 计（历史语义）。见 §3.3.1 |

### 3.3 AssessmentOutput — 评估输出

```go
type AssessmentOutput struct {
    HostID        string             `json:"host_id"`
    FinalScore    float64            `json:"final_score"`
    Acceptable    bool               `json:"acceptable"`
    Threshold     float64            `json:"threshold"`
    DomainScores  []DomainScore      `json:"domain_scores"`
    EdgeFactors   []EdgeFactorResult `json:"edge_factors"`
    ThreatCoeff   float64            `json:"threat_coefficient"`
    SPCScore      float64            `json:"spc_score"`
    FormulaID     string             `json:"formula_id"`
    CalculatedAt  time.Time          `json:"calculated_at"`
    Metadata      map[string]string  `json:"metadata,omitempty"`
    // 置信度后验字段（方向①，additive）
    FinalSigma         float64 `json:"final_sigma,omitempty"`
    Lower95            float64 `json:"score_lower95,omitempty"`
    Upper95            float64 `json:"score_upper95,omitempty"`
    EvidenceConfidence float64 `json:"evidence_confidence,omitempty"`
}
```

| 字段 | 说明 |
|------|------|
| `FinalScore` | 最终评估分数（0–100，保留两位小数）；三层聚合**不做上界钳位**，配置可使它 > 100 |
| `Acceptable` | 是否可接受；默认 `FinalScore >= Threshold`，`accept_by_lower_bound=true` 时改为 `Lower95 >= Threshold`（唯一实现 `ssam.AcceptanceDecision`） |
| `DomainScores` | 各核心域得分（含 `Sigma`/`Confidence`，见 §3.3.1） |
| `EdgeFactors` | 边缘因子评估结果（含 Active 标记、`TriggerConfidence`） |
| `FormulaID` | 使用的评分公式标识 |
| `Metadata` | 自定义元数据（钩子可写入） |
| `FinalSigma` | 最终分后验标准差：域分 σ 的 RSS **再乘 intrinsic 层权重 0.5**；`enabled=false` 时为 0。它是启发式不确定度，不是三层总分的严格后验 σ |
| `Lower95` / `Upper95` | `FinalScore ± 1.96·FinalSigma`，**只把下界钳到 0，上界不夹**——因此 `Total>100` 时区间仍包含点估计（如 108 → 上界可 > 100） |
| `EvidenceConfidence` | 域证据的可信度加权均值 ∈ [0,1]；无失败证据或 `enabled=false` 时为 1.0 |

### 3.3.1 置信度原生字段（方向①）

> 设计：`docs/1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md`。**默认 `enabled=false`**，
> 此时这些字段退化为 `Sigma=0`、区间 `[FinalScore, FinalScore]`、`EvidenceConfidence=1.0`，
> 评分与历史实现逐位一致。默认先验表（`user=0.90`/`adapter=0.80`）**未经标定**。

| 结构 | 字段 | 语义 |
|---|---|---|
| `CheckInput` | `Confidence` | 本条观测的可信度 ∈ [0,1]；0 = 未指定（→ policy `Default`），低于 `Floor` 时抬到 `Floor` |
| `DomainScore` | `Sigma` | 该域得分的后验标准差：`sigma_d = sqrt(Σ abs(delta)²·c·(1−c))` |
| `DomainScore` | `Confidence` | 该域证据平均可信度：`Σ(abs(delta)·c)/Σabs(delta)`；无失败证据时 1.0 |
| `AssessmentOutput` | `FinalSigma` | `0.5 · sqrt(Σ(w_d·σ_d)²)/Σw_d`（仅 intrinsic 层随机） |
| `AssessmentOutput` | `Lower95` / `Upper95` | 以实际 `FinalScore` 为中心的 95% 启发式区间；只钳下界 0 |
| `AssessmentOutput` | `EvidenceConfidence` | 域证据可信度的权重归一均值 |

> ⚠️ 这些是**模型原生字段**，不是展示层标签；但区间是文档化的启发式，
> 不得对外声称“已标定 / CI 覆盖率已验证”。

### 3.4 EdgeFactorConfig — 边缘因子配置

```go
type EdgeFactorConfig struct {
    ID           string  `json:"id"`
    Name         string  `json:"name"`
    Factor       float64 `json:"factor"`
    TriggerCheck string  `json:"trigger_check,omitempty"`
    CascadeTo    string  `json:"cascade_to,omitempty"`
    CascadeValue float64 `json:"cascade_value,omitempty"`
    CascadeOnly  bool    `json:"cascade_only,omitempty"`
}
```

| 字段 | 说明 |
|------|------|
| `ID` | 边缘因子唯一标识（如 `EF-002FA`） |
| `Name` | 可读名称 |
| `Factor` | 乘法修正因子（0.0–1.0，如 0.85 表示 ×0.85） |
| `TriggerCheck` | 触发该因子的检查项 ID |
| `CascadeTo` | 级联目标因子 ID（可选） |
| `CascadeValue` | 级联时覆盖目标因子的值（可选） |
| `CascadeOnly` | 为 true 时，该因子自身不直接参与乘法修正，仅通过级联影响目标因子 |

**级联示例**：3FA 未满足（`EF-3FA`）时，级联将 2FA 因子（`EF-002FA`）的值从 0.85 覆盖为 0.82：

```go
EdgeFactorConfig{
    ID: "EF-3FA", Name: "3FA Not Met", Factor: 0.82,
    TriggerCheck: "EF-002", CascadeTo: "EF-002FA",
    CascadeValue: 0.82, CascadeOnly: true,
}
```

---

## 3.5 SSAM V2.0 数据类型（types_v2.go）

### 3.5.1 RiskContext — 风险上下文

```go
type RiskContext struct {
    ThreatCoeff    float64            `json:"threat_coefficient"`
    SPCScore       float64            `json:"spc_score"`
    WeightShifts   map[string]float64 `json:"weight_shifts,omitempty"`
    EdgeFactors    []EdgeFactorResult `json:"edge_factors"`
    Threshold      float64            `json:"threshold"`
    CVEContext     []CVESummary       `json:"cve_context,omitempty"`
    ThreatActors   []string           `json:"threat_actors,omitempty"`
}
```

### 3.5.2 RiskLayerDetail / RiskLayers — 三层风险层

```go
type RiskLayerDetail struct {
    Score       float64           `json:"score"`
    Weight      float64           `json:"weight"`
    Description string            `json:"description"`
    Factors     []string          `json:"factors"`
    Details     map[string]float64 `json:"details,omitempty"`
}

type RiskLayers struct {
    Intrinsic RiskLayerDetail `json:"intrinsic"`
    Exposure  RiskLayerDetail `json:"exposure"`
    Threat    RiskLayerDetail `json:"threat"`
}
```

| 风险层 | 含义 | 典型输入 |
|--------|------|----------|
| **Intrinsic（本征风险）** | 系统自身的配置安全基线，与外部环境无关 | 核心域得分、边缘因子 |
| **Exposure（暴露风险）** | 系统对外暴露的脆弱性面 | SPC P_score、端口暴露、CVE 匹配 |
| **Threat（威胁风险）** | 当前威胁环境的影响 | CTI μ 系数、威胁组织活跃度、KEV 在野利用 |

### 3.5.3 FinalScore — V2.0 最终评分

```go
type FinalScore struct {
    Value      float64             `json:"value"`
    Acceptable bool                `json:"acceptable"`
    Threshold  float64             `json:"threshold"`
    Layers     RiskLayers          `json:"layers"`
    FormulaID  string              `json:"formula_id"`
    Metadata   map[string]string   `json:"metadata,omitempty"`
}
```

### 3.5.4 AssessmentInputV2 — V2.0 评估输入

```go
type AssessmentInputV2 struct {
    HostID    string       `json:"host_id"`
    Hostname  string       `json:"hostname"`
    Timestamp time.Time    `json:"timestamp"`
    Context   RiskContext  `json:"context"`
    Checks    []CheckInput `json:"checks"`
}
```

### 3.5.5 AssessmentOutputV2 — V2.0 评估输出

```go
type AssessmentOutputV2 struct {
    HostID       string              `json:"host_id"`
    FinalScore   FinalScore          `json:"final_score"`
    DomainScores []DomainScore       `json:"domain_scores"`
    EdgeFactors  []EdgeFactorResult  `json:"edge_factors"`
    CalculatedAt time.Time           `json:"calculated_at"`
}
```

`AssessmentOutputV2` 提供 `.ToIR()` 方法，导出声明的 SSAM IR JSON 结构（见 §13）。

### 3.5.6 ScoringFormulaV2 — V2.0 公式接口

```go
type ScoringFormulaV2 interface {
    ID() string
    Compute(ctx context.Context, input *AssessmentInputV2) (*AssessmentOutputV2, error)
    ValidateInput(input *AssessmentInputV2) error
}
```

内置实现：
- `SSAMV20Formula`（`formulas_v2.go`）：三层独立风险层评估，消除旧版 ThreatCoeff/SPCScore 的双重罚分问题
- `ASTFormula`（`formulas_ast.go`）：通过 Formula DSL 动态构造的公式

---

## 4. SSAM V2.0 三层语义模型

SSAM V2.0 的核心创新是用三个独立的风险层取代 V1.x 中 ThreatCoeff 和 SPCScore 的单一乘法叠加。每个层有独立的语义、权重和输入：

```
AssessmentInputV2
    │
    ├── 本征风险层 (Intrinsic)
    │   ├── 核心域加权得分 (SSAM v1.2 核心公式)
    │   ├── 边缘因子乘法修正
    │   └── 输出：Intrinsic Score ∈ [0, 100]
    │
    ├── 暴露风险层 (Exposure)
    │   ├── SPC P_score 转换
    │   ├── CVE 数量 / 严重度
    │   ├── 端口暴露面
    │   └── 输出：Exposure Score ∈ [0, 100]
    │
    ├── 威胁风险层 (Threat)
    │   ├── CTI μ 系数转换
    │   ├── KEV 在野利用状态
    │   ├── 威胁组织活跃度
    │   └── 输出：Threat Score ∈ [0, 100]
    │
    ▼
FinalScore = Σ(LayerScore_i × LayerWeight_i) / ΣLayerWeight_i
```

**与 V1.x 的关键差异：**

| 特性 | V1.x (ssam_v1.2) | V2.0 (ssam_v2.0) |
|------|------------------|-------------------|
| 外部因素处理 | ThreatCoeff × SPCScore 双乘数叠加 | 三层独立评分 + 加权平均 |
| 双重罚分 | 一个低 SPC 分数同时被乘以 μ，导致过度惩罚 | 各层独立计算，权重可调 |
| 可解释性 | 最终分数难以分解为"哪部分导致" | RiskLayers 提供逐层分解 |
| 灵活性 | 公式固定 | 通过 AST/DSL 动态配置层权重和组合方式 |

---

## 5. SSAM IR（中间表示）

SSAM V2.0 引入 SSAMIR——评估结果的声明式 JSON 中间表示。通过 `AssessmentOutputV2.ToIR()` 导出：

```json
{
  "ssamir_version": "1.0",
  "host_id": "prod-web-01",
  "timestamp": "2026-05-28T10:30:00Z",
  "formula_id": "ssam_v2.0",
  "final_score": {
    "value": 72.35,
    "acceptable": false,
    "threshold": 80.0
  },
  "layers": {
    "intrinsic": { "score": 82.0, "weight": 0.50, "description": "..." },
    "exposure":  { "score": 60.0, "weight": 0.30, "description": "..." },
    "threat":    { "score": 70.0, "weight": 0.20, "description": "..." }
  },
  "domain_scores": {
    "attack_surface": 78.0,
    "business_continuity": 90.0,
    "operation_trust": 85.0,
    "resilience": 72.0
  },
  "edge_factors": [...]
}
```

SSAM IR 的设计目标：
- **下游工具链消费**：SIEM、SOC Dashboard、合规审计系统可直接解析
- **跨语言互操作**：纯 JSON，任何语言可解析
- **版本化兼容**：`ssamir_version` 字段保证前向/后向兼容

---

## 6. Formula AST

`ssam-lib` **不提供**字符串 DSL 解析器（没有 `ParseFormula()` / `EvaluateFormula()`）。公式以 `FormulaAST` 程序化表达，内置两套 AST：

- `SSAMV12AST()` — V1.2 连乘公式
- `SSAMV20AST()` — 默认的 V2 三层加权公式

```go
package main

import (
    "fmt"
    "log"

    "github.com/chins-xing/ssam"
)

func main() {
    ast := ssam.SSAMV20AST() // 也可自行构造 ssam.FormulaAST

    ctx := ssam.EvalContext{
        DomainScores: []ssam.DomainScore{{Domain: "attack_surface", Score: 80}},
        Weights:      ssam.DefaultWeights,
        RiskContext:  ssam.RiskContext{Exposure: 0.9, Threat: 1.0},
    }

    score, err := ssam.EvalAST(ast, ctx) // 直接求值
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("AST score: %.2f\n", score)

    compiled := ssam.ASTToFormula(ast) // 编译为 ssam.ScoringFormula
    fmt.Printf("compiled score: %.2f\n", compiled(ctx.DomainScores, ctx.Weights, 1.0, 0.9, nil))
}
```

AST 节点用 `Op` 字段表达，支持：`weighted_sum`、`multiply`、`divide`、`add`、`min`、`max`、`product_chain`、`ref`、`const`。`EvalAST` 与 `ASTToFormula` 共用域级修正与边缘因子合成策略入口。

> 配置文件驱动的公式（`[v2_formula] expression = ...`）**未实现**；见《项目篇章-系统安全可接受性模型》§V2.0。

---

## 7. 评分流程

`ComputeScore` 的完整执行流程：

```
输入验证 (ValidateInput)
    │
    ▼
ctx 取消检查
    │
    ▼
HookPreScore 钩子
    │
    ▼
域评分 (ComputeDomainScores)
    │  ┌─────────────────────────────────────┐
    │  │ 各域初始 100 分                      │
    │  │ 遍历未通过检查项，累加 Delta（负数）  │
    │  │ 域得分下限 0                         │
    │  └─────────────────────────────────────┘
    │
    ▼
ctx 取消检查
    │
    ▼
HookPostScore 钩子
    │
    ▼
HookPreEdge 钩子
    │
    ▼
边缘因子评估 (ApplyEdgeFactorsToChecks)
    │  ┌─────────────────────────────────────┐
    │  │ 1. 检查项触发：未通过的检查项匹配    │
    │  │    TriggerCheck → 标记因子为活跃      │
    │  │ 2. 级联处理：活跃因子若有 CascadeTo， │
    │  │    将 CascadeValue 覆盖目标因子       │
    │  │ 3. CascadeOnly 因子自身不参与乘法修正 │
    │  │ 4. 自定义因子值覆盖（customFactors）  │
    │  └─────────────────────────────────────┘
    │
    ▼
ctx 取消检查
    │
    ▼
HookPostEdge 钩子
    │
    ▼
公式计算 (applyFormula)
    │  SSAM v1.2 公式：
    │  baseScore = Σ(Si × Wi) / ΣWi
    │  baseScore *= threatCoeff
    │  baseScore *= spcScore
    │  for each active edgeFactor:
    │      baseScore *= factor
    │  finalScore = round(baseScore, 2)
    │
    ▼
判定可接受性 (finalScore >= threshold)
    │
    ▼
返回 AssessmentOutput
```

---

## 8. 接入方式

### 8.1 方式一：独立使用（推荐用于第三方集成）

SSAM 模块可完全脱离 ASSCOR 框架独立使用：

```go
package main

import (
    "fmt"
    "log"

    "github.com/chins-xing/ssam"
)

func main() {
    config := ssam.ScoringConfig{
        Weights:     ssam.DefaultWeights,
        EdgeFactors: ssam.DefaultEdgeFactors,
        FormulaID:   "ssam_v2.0", // 默认三层加权；"ssam_v1.2" 为旧连乘公式
    }

    input := ssam.AssessmentInput{
        HostID:      "server-01",
        Hostname:    "web-prod-01",
        Threshold:   80,
        ThreatCoeff: 1.0,
        SPCScore:    1.0,
        Checks: []ssam.CheckInput{
            {CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Root Login", Passed: true},
            {CheckID: "AS-002", Domain: "attack_surface", Name: "Unused Services", Passed: false, Delta: -10, Detail: "telnet enabled"},
            {CheckID: "BC-001", Domain: "business_continuity", Name: "Critical Service", Passed: true},
            {CheckID: "OT-001", Domain: "operation_trust", Name: "File Permissions", Passed: false, Delta: -15, Detail: "/etc/passwd world-writable"},
            {CheckID: "RS-001", Domain: "resilience", Name: "Auto-ban Accuracy", Passed: true},
        },
    }

    output, err := ssam.ComputeScore(config, input) // 值传入、值返回
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Final Score: %.2f\n", output.FinalScore)
    fmt.Printf("Acceptable:  %v\n", output.Acceptable)
    fmt.Printf("Formula:     %s\n", output.FormulaID)

    for _, ds := range output.DomainScores {
        fmt.Printf("  Domain %-20s: %.0f\n", ds.Domain, ds.Score)
    }
    for _, ef := range output.EdgeFactors {
        if ef.Active {
            fmt.Printf("  EdgeFactor %-12s: ×%.2f (ACTIVE)\n", ef.ID, ef.Factor)
        }
    }
}
```

> `ssam.ComputeScore(config ScoringConfig, input AssessmentInput) (AssessmentOutput, error)`：**按值**接收与返回，不接收 `context`；需要取消/超时由调用方在外层控制。

### 8.2 方式二：自定义配置

```go
config := ssam.DefaultScoringConfig

config.Weights = []ssam.WeightConfig{
    {Domain: "attack_surface", Weight: 40},
    {Domain: "business_continuity", Weight: 20},
    {Domain: "operation_trust", Weight: 25},
    {Domain: "resilience", Weight: 15},
}

config.EdgeFactors = []ssam.EdgeFactorConfig{
    {ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
    {ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled", Factor: 0.75, TriggerCheck: "RS-005"},
    {ID: "EF-SELINUX", Name: "SELinux Disabled", Factor: 0.80, TriggerCheck: "OT-005"},
}

config.FormulaID = "ssam_v1.2" // 也可保持默认 "ssam_v2.0"

output, err := ssam.ComputeScore(config, input)
```

> 适配层的 `Engine.SetWeights` / `Engine.SetEdgeFactors` / `Engine.SetFormula` 是同一份配置的包装接口；ssam-lib 本身只接受 `ScoringConfig`。

### 8.3 方式三：自定义公式（`ScoringFormula` / AST）

ssam-lib **没有全局公式注册表**；自定义公式就是一个 `ScoringFormula` 函数（或由 `ASTToFormula` 编译出的函数），由调用方直接调用。适配层的 `Engine.RegisterFormula` 是 ASSCOR 内部 API，不属于 ssam-lib。

```go
customFormula := func(
    domainScores []ssam.DomainScore,
    weights []ssam.WeightConfig,
    threatCoeff float64,
    spcScore float64,
    edgeFactors []ssam.EdgeFactorResult,
) float64 {
    wMap := make(map[string]float64)
    for _, w := range weights {
        wMap[w.Domain] = w.Weight
    }

    sum := 0.0
    totalWeight := 0.0
    for _, ds := range domainScores {
        if w, ok := wMap[ds.Domain]; ok && w > 0 {
            sum += ds.Score * w
            totalWeight += w
        }
    }
    if totalWeight == 0 {
        return 0
    }

    base := sum / totalWeight
    base *= threatCoeff * spcScore

    for _, f := range edgeFactors {
        if f.Active && f.Factor > 0 && f.Factor < 1.0 {
            base *= f.Factor
        }
    }

    return math.Round(base*100) / 100
}

// 自行准备公式输入：
config := ssam.DefaultScoringConfig
domainScores := ssam.ComputeDomainScores(config.Weights, input.Checks)
factors := ssam.ApplyEdgeFactorsToChecks(config.EdgeFactors, input.Checks, nil)
score := customFormula(domainScores, config.Weights, 1.0, 1.0, factors)
```

### 8.4 方式四：使用钩子扩展评分流程（仅 ASSCOR 适配层）

钩子（`RegisterHook` / `HookPhase`）只存在于 ASSCOR 适配层 `internal/engine/ssam/`，**ssam-lib 没有钩子机制**；且 `internal` 包不能被第三方模块导入，因此本节仅适用于 ASSCOR 仓内开发者（构建需 `-tags engine`）。

```go
import (
    "context"
    "fmt"

    adapter "github.com/chins-xing/asscor/internal/engine/ssam"
)

engine := adapter.NewDefaultEngine()

engine.RegisterHook(adapter.HookPreScore, "log-input", func(
    ctx context.Context,
    input *adapter.AssessmentInput,
    output *adapter.AssessmentOutput,
) error {
    fmt.Printf("[pre_score] Evaluating host=%s with %d checks\n", input.HostID, len(input.Checks))
    return nil
}, 10)

engine.RegisterHook(adapter.HookPostEdge, "enrich-metadata", func(
    ctx context.Context,
    input *adapter.AssessmentInput,
    output *adapter.AssessmentOutput,
) error {
    output.Metadata["evaluated_by"] = "custom-engine"
    output.Metadata["compliance_framework"] = "GB/T 22239-2019 Level 3"
    return nil
}, 20)
```

### 8.5 方式五：通过 ASSCOR DI 容器集成（v0.2.2 依赖倒置架构，现状 v0.2.3 兼容）

ASSCOR v0.2.3 定义了统一的 `kernel.AssessorEngine` 接口（规范定义于 `internal/kernel/engine_types.go`，v0.2.2 依赖倒置架构延续至今，v0.2.3 兼容）。SSAM 通过 `ssam.EngineAdapter` 实现该接口，以插件形式注入：

**注册端（cmd/kernel/main.go 平台层）：**

```go
func main() {
    cfg := config.Load(...)
    scoringEngine := kernel.NewScoringEngineModule(cfg)

    // SSAM 作为 ASSCOR 插件注入（依赖方向: SSAM → ASSCOR）
    if cfg.ScoringEngine != "legacy" {
        adapter := ssam.NewEngineAdapter(cfg)
        scoringEngine.SetPluginEngine(adapter)
    }

    k.Container().Bind((*kernel.ScoringEngineProvider)(nil), scoringEngine)
}
```

**消费端（AssessorModule 内部，对插件透明）：**

```go
type Assessor struct {
    pluginEngine kernel.AssessorEngine  // 统一接口，非 ssam 具体类型
}

func (a *Assessor) tryPluginScore(ctx context.Context, result *model.AssessmentResult) bool {
    if a.pluginEngine == nil {
        return false
    }
    return a.pluginEngine.ComputeScore(ctx, result) == nil
}
```

**关键变化（v0.2.0 → v0.2.2）**:
- 旧: `a.ssamEngine ssam.ScoringProvider` → 新: `a.pluginEngine kernel.AssessorEngine`
- 旧: `ssam.NewEngine()` 在 assessor 内硬编码 → 新: `ssam.NewEngineAdapter(cfg)` 在 main.go 注入
- 旧: `ssam.ScoringProvider` 直接绑定到 DI → 新: `kernel.AssessorEngine` 统一接口
- 旧: ASSCOR 依赖 SSAM 包 → 新: SSAM 依赖 ASSCOR 接口

---

## 9. 配置适配

`adapter.go` 提供 ASSCOR 配置/模型与 SSAM 格式之间的双向转换函数：

### 9.1 配置转换

| 函数 | 方向 | 说明 |
|------|------|------|
| `ConfigToWeights(cfg)` | Config → SSAM | 将 ASSCOR 配置的权重转为 `[]WeightConfig` |
| `ConfigToEdgeFactors(cfg)` | Config → SSAM | 将 ASSCOR 配置的边缘因子转为 `[]EdgeFactorConfig` |

**config.ini 对应配置段：**

```ini
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15
kernel_security = 0
# scoring_engine: 留空=SSAM, legacy=内置引擎
scoring_engine =

[edge_factors]
two_factor_failure = 0.85
syn_cookie_disabled = 0.75
selinux_disabled = 0.80
apparmor_disabled = 0.82
no_siem = 0.90
no_ids = 0.88
```

### 9.2 模型转换

| 函数 | 方向 | 说明 |
|------|------|------|
| `CheckResultsToInputs(checks)` | model → SSAM | `[]model.CheckResult` → `[]CheckInput` |
| `DomainScoresToOutput(scores)` | SSAM → model | `[]DomainScore` → `model.DomainScores` |
| `EdgeFactorsToModel(factors)` | SSAM → model | `[]EdgeFactorResult` → `model.EdgeFactors` |
| `ModelToInput(result)` | model → SSAM | `*model.AssessmentResult` → `*AssessmentInput` |
| `OutputToModel(output, result)` | SSAM → model | 将 `AssessmentOutput` 写入 `*model.AssessmentResult` |

### 9.3 边缘因子 ID 映射

| SSAM ID | model 字段 | config.ini 键 |
|---------|-----------|---------------|
| `EF-002FA` | `EdgeFactors.TwoFactorFailure` | `two_factor_failure` |
| `EF-SYNCOOKIE` | `EdgeFactors.SYNCookieDisabled` | `syn_cookie_disabled` |
| `EF-SELINUX` | `EdgeFactors.SELinuxDisabled` | `selinux_disabled` |
| `EF-APPARMOR` | `EdgeFactors.AppArmorDisabled` | `apparmor_disabled` |
| `EF-NO-SIEM` | `EdgeFactors.NoSIEM` | `no_siem` |
| `EF-NO-IDS` | `EdgeFactors.NoIDS` | `no_ids` |
| `EF-3FA` | 级联至 `EF-002FA` | — |

---

## 10. 输入验证

`ssam.ValidateInput(input AssessmentInput)` 在 `ssam.ComputeScore` 入口自动调用。它**按值接收**参数，因此没有 nil 分支：

| 字段 | 规则 | 错误 |
|------|------|----------|
| `HostID` | 不得为空 | `*SSAMError{Code: "empty_host_id"}` |
| `Threshold` | 必须在 (0, 100] 范围内 | `*SSAMError{Code: "invalid_threshold"}` |
| `Checks[i].Domain` | 不得为空 | `*SSAMError{Code: "empty_domain"}` |

> `ErrNilInput` 只由 **ASSCOR 适配层**的 `Engine.ComputeScore(ctx, *AssessmentInput)` 在收到 nil 指针时返回；ssam-lib 的 `ComputeScore` 接收值类型，不存在 nil 输入。

自定义验证示例：

```go
if err := ssam.ValidateInput(input); err != nil {
    var se *ssam.SSAMError
    if errors.As(err, &se) {
        fmt.Printf("Validation failed: code=%s, message=%s\n", se.Code, se.Message)
    }
    return err
}
```

---

## 11. 默认值

`defaults.go` 提供的默认配置：

**默认权重：**

| 域 | 权重 |
|----|------|
| attack_surface | 35 |
| business_continuity | 25 |
| operation_trust | 25 |
| resilience | 15 |

**默认边缘因子：**

| ID | 名称 | 因子 | 触发检查 |
|----|------|------|----------|
| EF-002FA | 2FA Missing | 0.85 | EF-001 |
| EF-SYNCOOKIE | SYN Cookie Disabled | 0.75 | RS-005 |
| EF-SELINUX | SELinux Disabled | 0.80 | OT-005 |
| EF-APPARMOR | AppArmor Disabled | 0.82 | OT-005 |
| EF-NO-SIEM | SIEM Integration Missing | 0.90 | RS-007 |
| EF-NO-IDS | IDS/IPS Missing | 0.88 | RS-006 |
| EF-3FA | 3FA Not Met | 0.82 | EF-002（级联至 EF-002FA） |

使用默认配置评分：

```go
config := ssam.DefaultScoringConfig // 默认权重 + 7 个边缘因子 + FormulaID "ssam_v2.0"
output, err := ssam.ComputeScore(config, input)
```

---

## 12. 并发安全

ssam-lib 的评分函数是纯函数、**不使用 goroutine**；但包级存在两处共享可变状态：边缘因子合成策略（`ast.go:215` `strategyMu`）与域级修正函数（`domain_adjust.go:31` `domainAdjustMu`）。它们通过 `RegisterEdgeFactorStrategy` / `RegisterDomainAdjust` 在启动期写入、评分期读取，由 `sync.RWMutex` 保护；默认（未注册）路径下评分结果逐位不变。

ASSCOR 适配层（`internal/engine/ssam/`）的 `Engine` 另有一个 `sync.RWMutex`，保护权重、边缘因子、公式 ID 与钩子配置（`engine.go:18`）；核心计算仍委托无状态的 ssam-lib 纯函数。

---

## 13. 错误处理

| 错误变量 | 含义 |
|----------|------|
| `*SSAMError{Code, Message}` | 唯一的错误类型（`errors.As(err, &se)` 可取出）；字段验证失败时 `Code` 为 `empty_host_id` / `invalid_threshold` / `empty_domain` 等 |
| `ErrNilInput` | 输入指针为 nil；仅由 ASSCOR 适配层 `Engine.ComputeScore` 返回（ssam-lib 按值接收，不使用） |
| `ErrUnknownFormula` | 指定的公式 ID 不存在 |
| `ErrEmptyWeights` | 未配置任何权重 |
| `ErrInvalidScore` | 输出分数超出 [0, 100] 范围 |

`ComputeScore` 的错误返回策略：

- 输入验证失败 → 返回 `*SSAMError`（具体 `Code` 见 §10）
- 正常完成 → 返回 `(output, nil)`
- 适配层 `Engine.ComputeScore` 额外处理：nil 指针 → `ErrNilInput`，上下文取消 → `ctx.Err()`

---

## 14. ASSCOR 内核基础设施接口

以下接口属于 ASSCOR 内核（`internal/kernel`），与 SSAM 模块配合使用。

### 14.1 DI 容器

```go
container := kernel.NewContainer()

container.Bind((*ssam.ScoringProvider)(nil), engine)
container.BindNamed("config", (*config.Config)(nil), cfg)

impl, ok := container.Resolve((*ssam.ScoringProvider)(nil))
impl, ok := container.ResolveNamed("config")

container.Inject(targetStruct)
container.Remove((*ssam.ScoringProvider)(nil))
```

**结构体字段注入：**

```go
type MyModule struct {
    Scorer ssam.ScoringProvider `inject:"true"`
    Config *config.Config       `inject:"config"`
}
```

### 14.2 消息总线

```go
bus := kernel.NewBus(1000)

bus.Subscribe("assessor.result", "my-handler", func(ctx context.Context, msg kernel.Message) error {
    result := msg.Payload.(*model.AssessmentResult)
    return nil
})

bus.Publish(ctx, kernel.Message{
    Topic: "assessor.result", Payload: result, Source: "assessor",
})

bus.PublishSync(ctx, msg)
bus.Unsubscribe("assessor.result", "my-handler")
```

### 14.3 熔断器

```go
cb := kernel.NewCircuitBreaker(kernel.CircuitBreakerConfig{
    FailureRatio:  0.5,
    MinRequests:   10,
    Timeout:       30 * time.Second,
    WindowSize:    60 * time.Second,
    OnStateChange: func(service, method string) {
        log.Printf("circuit state changed: %s/%s", service, method)
    },
})

curState := cb.State("spc", "fetch")
_, failures, successes := cb.Stats("spc", "fetch")
cb.Reset("spc", "fetch")
```

熔断器通过拦截器模式集成到请求链路中（见 14.4 拦截器链）。

### 14.4 拦截器链

```go
chain := kernel.NewInterceptorChain()

limiter := kernel.NewRateLimiter(100, 200, func(service, method, reason string) {
    log.Printf("[rate-limit] %s/%s rejected: %s", service, method, reason)
})
cb := kernel.NewCircuitBreaker(kernel.CircuitBreakerConfig{
    FailureRatio: 0.5, MinRequests: 10, Timeout: 30 * time.Second,
})
auditLog := kernel.NewAuditLogInterceptor(func(event kernel.InterceptorEvent) {
    log.Printf("[audit] %s/%s %v", event.Service, event.Method, event.Duration)
})

chain.Use(limiter.Interceptor())
chain.Use(cb.Interceptor())
chain.Use(auditLog.Interceptor())

handler := chain.Then(func(ctx context.Context, svc, method string, payload []byte) ([]byte, error) {
    return handleRequest(svc, method, payload)
})
```

---

## 15. 完整集成示例

以下示例展示如何将 SSAM 模块集成到自定义安全评估系统中：

```go
package main

import (
    "fmt"
    "log"
    "strings"

    "github.com/chins-xing/ssam"
)

func main() {
    config := ssam.ScoringConfig{
        Weights:     ssam.DefaultWeights,
        EdgeFactors: ssam.DefaultEdgeFactors,
        FormulaID:   "ssam_v2.0",
    }

    input := ssam.AssessmentInput{
        HostID:      "prod-web-01",
        Hostname:    "web.example.com",
        Threshold:   80,
        ThreatCoeff: 0.95,
        SPCScore:    0.92,
        Checks: []ssam.CheckInput{
            {CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Hardening", Passed: true},
            {CheckID: "AS-003", Domain: "attack_surface", Name: "Open Ports", Passed: false, Delta: -15, Detail: "port 23 open"},
            {CheckID: "BC-001", Domain: "business_continuity", Name: "Service Status", Passed: true},
            {CheckID: "OT-002", Domain: "operation_trust", Name: "Audit Log", Passed: false, Delta: -20, Detail: "auditd not running"},
            {CheckID: "RS-001", Domain: "resilience", Name: "Fail2ban", Passed: true},
        },
    }

    output, err := ssam.ComputeScore(config, input)
    if err != nil {
        log.Fatalf("assessment failed: %v", err)
    }

    fmt.Printf("\n=== Assessment Result ===\n")
    fmt.Printf("Host:        %s\n", output.HostID)
    fmt.Printf("Final Score: %.2f / 100\n", output.FinalScore)
    fmt.Printf("Acceptable:  %v (threshold: %.0f)\n", output.Acceptable, output.Threshold)
    fmt.Printf("Threat Coeff: %.2f\n", output.ThreatCoeff)
    fmt.Printf("SPC Score:    %.2f\n", output.SPCScore)
    fmt.Printf("Formula:      %s\n", output.FormulaID)

    fmt.Printf("\nDomain Scores:\n")
    for _, ds := range output.DomainScores {
        bar := strings.Repeat("█", int(ds.Score/5))
        fmt.Printf("  %-20s [%-20s] %5.0f\n", ds.Domain, bar, ds.Score)
    }

    fmt.Printf("\nEdge Factors:\n")
    for _, ef := range output.EdgeFactors {
        status := "inactive"
        if ef.Active {
            status = fmt.Sprintf("ACTIVE (×%.2f)", ef.Factor)
        }
        fmt.Printf("  %-12s %-25s %s\n", ef.ID, ef.Name, status)
    }
}
```

---

## 13. 测试

SSAM 模块包含完整的单元测试和集成测试：

```bash
# 运行 SSAM 模块测试
go test ./internal/engine/ssam/... -v

# 运行适配器集成测试
go test ./internal/engine/ssam/... -v -run TestConfigTo

# 运行完整评分流程测试
go test ./internal/engine/ssam/... -v -run TestComputeScore

# 运行钩子测试
go test ./internal/engine/ssam/... -v -run TestHooks
```

测试覆盖的关键场景：

- 全通过/全失败/部分通过的评分计算
- 边缘因子触发与级联
- 自定义公式注册与切换
- 钩子注册/注销/执行
- 输入验证（nil、空字段、越界值）
- 上下文取消
- 并发安全
- ASSCOR 配置适配双向转换
