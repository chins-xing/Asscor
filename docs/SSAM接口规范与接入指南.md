# SSAM 接口规范与接入指南

> **版本**：SSAM 2.0 | **模块路径**：`github.com/asscor/ssam`  
> **ASSCOR 适配层**：`f:\Argus\internal\ssam\` (薄适配层，委托给 ssam-lib)  
> **日期**：2026-05-28 | **状态**：发布

本文档详细说明 SSAM 独立算法模块的接口规范、数据结构定义、配置适配机制及接入方式。SSAM V2.0 已独立为纯函数式 Go 模块 `github.com/asscor/ssam`（位于 `ssam-lib/`），可脱离 ASSCOR 框架独立使用。ASSCOR 平台通过 `internal/ssam/` 薄适配层委托调用 ssam-lib。

---

## 1. 模块概览

`github.com/asscor/ssam`（`ssam-lib/`）是 SSAM V2.0 的纯函数式引擎，零外部依赖。包含以下文件：

| 文件 | 职责 |
|------|------|
| `ssam.go` | Engine 核心实现：`Provider` 接口、输入验证、钩子机制、公式调度 |
| `types.go` | V1.x 数据类型定义（`AssessmentInput`, `AssessmentOutput` 等），保持向后兼容 |
| `types_v2.go` | V2.0 数据类型：`RiskContext`, `RiskLayerDetail`, `RiskLayers`, `FinalScore`, `AssessmentInputV2`, `AssessmentOutputV2`, `ScoringFormulaV2` |
| `formulas.go` | V1.x 公式实现（`ssam_v1.2`, `simple_weighted`），保持向后兼容 |
| `formulas_v2.go` | V2.0 公式 `SSAMV20Formula`：三层语义模型（本征/暴露/威胁）独立风险层评估 |
| `ir.go` | SSAM IR JSON 中间表示：`AssessmentOutputV2.ToIR()` 输出机器可读的结构化评估结果 |
| `ast.go` | Formula DSL/AST：`ParseFormula(expression)` 解析公式字符串为 AST；`EvaluateFormula(ast, ctx)` 求值 |
| `formulas_ast.go` | AST 驱动的公式实现，支持运行时动态构造评分公式 |
| `engine_test.go` | 完整测试覆盖（V1.x 回归 + V2.0 三层模型 + IR 导出 + AST 解析） |

ASSCOR 适配层（`internal/ssam/`）精简为两个文件：

| 文件 | 职责 |
|------|------|
| `adapter.go` | ASSCOR 配置/模型与 SSAM 格式的双向转换（委托给 ssam-lib Engine） |
| `defaults.go` | 默认权重、边缘因子及工厂函数 |

---

## 2. 核心接口

### 2.1 Provider 聚合接口

`Provider` 是 SSAM 模块对外暴露的顶层接口，聚合了四个子接口：

```go
type Provider interface {
    ScoringProvider
    DomainProvider
    EdgeFactorProvider
    HookProvider
}
```

`Engine` 结构体实现了 `Provider` 接口，并通过编译时断言保证：

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
| `SetFormula` / `GetFormula` | 切换/获取评分公式（内置 `ssam_v1.2` 和 `simple_weighted`） |
| `SetFormulaV2` / `GetFormulaV2` | 切换/获取 V2.0 评分公式（内置 `ssam_v2.0`，使用三层语义模型） |

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
| `WeightShifts` | map | SPC 输出的域权重临时偏移（可选） |

### 3.2 CheckInput — 检查项输入

```go
type CheckInput struct {
    CheckID string  `json:"check_id"`
    Domain  string  `json:"domain"`
    Name    string  `json:"name"`
    Passed  bool    `json:"passed"`
    Delta   float64 `json:"delta"`
    Detail  string  `json:"detail"`
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
}
```

| 字段 | 说明 |
|------|------|
| `FinalScore` | 最终评估分数（0–100，保留两位小数） |
| `Acceptable` | 是否可接受（`FinalScore >= Threshold`） |
| `DomainScores` | 各核心域得分 |
| `EdgeFactors` | 边缘因子评估结果（含 Active 标记） |
| `FormulaID` | 使用的评分公式标识 |
| `Metadata` | 自定义元数据（钩子可写入） |

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

## 6. Formula DSL / AST

SSAM V2.0 提供公式 DSL，允许在运行时通过字符串表达式构造评分公式，无需修改代码：

```go
import "github.com/asscor/ssam"

ast, err := ssam.ParseFormula("intrinsic * 0.5 + exposure * 0.3 + threat * 0.2")
if err != nil {
    log.Fatal(err)
}

engine := ssam.NewDefaultEngine()
engine.SetFormulaAST(ast)

output, err := engine.ComputeScoreV2(ctx, inputV2)
```

支持的 DSL 语法：
- 变量：`intrinsic`, `exposure`, `threat`（三层风险层得分）
- 运算符：`+`, `-`, `*`, `/`, `(`, `)`
- 字面量：整数和浮点数
- 函数：`min(a,b)`, `max(a,b)`, `round(x)`, `sqrt(x)`

DSL 表达式会被 `ParseFormula()` 编译为 AST，由 `EvaluateFormula()` 高效求值，无需运行时字符串解析。

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
    "context"
    "fmt"
    "log"

    "github.com/asscor/ssam"
)

func main() {
    engine := ssam.NewDefaultEngine()

    input := &ssam.AssessmentInput{
        HostID:    "server-01",
        Hostname:  "web-prod-01",
        Threshold: 80,
        ThreatCoeff: 1.0,
        SPCScore:    1.0,
        Checks: []ssam.CheckInput{
            {CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Root Login", Passed: true, Delta: 0},
            {CheckID: "AS-002", Domain: "attack_surface", Name: "Unused Services", Passed: false, Delta: -10, Detail: "telnet enabled"},
            {CheckID: "BC-001", Domain: "business_continuity", Name: "Critical Service", Passed: true, Delta: 0},
            {CheckID: "OT-001", Domain: "operation_trust", Name: "File Permissions", Passed: false, Delta: -15, Detail: "/etc/passwd world-writable"},
            {CheckID: "RS-001", Domain: "resilience", Name: "Auto-ban Accuracy", Passed: true, Delta: 0},
        },
    }

    output, err := engine.ComputeScore(context.Background(), input)
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

### 8.2 方式二：自定义配置

```go
engine := ssam.NewEngine()

engine.SetWeights([]ssam.WeightConfig{
    {Domain: "attack_surface", Weight: 40},
    {Domain: "business_continuity", Weight: 20},
    {Domain: "operation_trust", Weight: 25},
    {Domain: "resilience", Weight: 15},
})

engine.SetEdgeFactors([]ssam.EdgeFactorConfig{
    {ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
    {ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled", Factor: 0.75, TriggerCheck: "EF-SYNCOOKIE"},
    {ID: "EF-SELINUX", Name: "SELinux Disabled", Factor: 0.80, TriggerCheck: "EF-SELINUX"},
})

engine.SetFormula("ssam_v1.2")
```

### 8.3 方式三：注册自定义公式

```go
engine := ssam.NewDefaultEngine()

engine.RegisterFormula("custom_v1", func(
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
})

engine.SetFormula("custom_v1")
```

### 8.4 方式四：使用钩子扩展评分流程

```go
engine := ssam.NewDefaultEngine()

engine.RegisterHook(ssam.HookPreScore, "log-input", func(
    ctx context.Context,
    input *ssam.AssessmentInput,
    output *ssam.AssessmentOutput,
) error {
    fmt.Printf("[pre_score] Evaluating host=%s with %d checks\n", input.HostID, len(input.Checks))
    return nil
}, 10)

engine.RegisterHook(ssam.HookPostEdge, "enrich-metadata", func(
    ctx context.Context,
    input *ssam.AssessmentInput,
    output *ssam.AssessmentOutput,
) error {
    output.Metadata["evaluated_by"] = "custom-engine"
    output.Metadata["compliance_framework"] = "GB/T 22239-2019 Level 3"
    return nil
}, 20)
```

### 8.5 方式五：通过 ASSCOR DI 容器集成

在 ASSCOR 内核中，SSAM Engine 通过依赖注入容器注册和消费：

**注册端（AssessorModule.Init）：**

```go
func (m *AssessorModule) Init(ctx context.Context, kc KernelContext) error {
    m.engine = engine.NewAssessor(m.cfg)

    kc.Container().Bind((*ssam.ScoringProvider)(nil), m.engine.SSAMEngine())

    return nil
}
```

**消费端（任意内核模块）：**

```go
type MyModule struct {
    Scorer ssam.ScoringProvider `inject:"true"`
}

func (m *MyModule) Init(ctx context.Context, kc KernelContext) error {
    if err := kc.Container().Inject(m); err != nil {
        return err
    }
    return nil
}
```

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

`ValidateInput` 在 `ComputeScore` 入口自动调用，验证规则如下：

| 字段 | 规则 | 错误类型 |
|------|------|----------|
| `input` | 不得为 nil | `ErrNilInput` |
| `HostID` | 不得为空 | `ValidationError{Field: "host_id"}` |
| `Threshold` | 必须在 (0, 100] 范围内 | `ValidationError{Field: "threshold"}` |
| `Checks[i].Domain` | 不得为空 | `ValidationError{Field: "checks[i].domain"}` |

自定义验证示例：

```go
if err := ssam.ValidateInput(input); err != nil {
    var ve ssam.ValidationError
    if errors.As(err, &ve) {
        fmt.Printf("Validation failed: field=%s, message=%s\n", ve.Field, ve.Message)
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
| EF-SYNCOOKIE | SYN Cookie Disabled | 0.75 | EF-SYNCOOKIE |
| EF-SELINUX | SELinux Disabled | 0.80 | EF-SELINUX |
| EF-APPARMOR | AppArmor Disabled | 0.82 | EF-APPARMOR |
| EF-NO-SIEM | SIEM Integration Missing | 0.90 | EF-NO-SIEM |
| EF-NO-IDS | IDS/IPS Missing | 0.88 | EF-NO-IDS |
| EF-3FA | 3FA Not Met | 0.82 | EF-002（级联至 EF-002FA） |

使用默认配置创建引擎：

```go
engine := ssam.NewDefaultEngine()
```

---

## 12. 并发安全

ssam-lib（`github.com/asscor/ssam`）是纯函数式库，零 goroutine、零锁、零共享状态。评估函数是无副作用的纯函数：相同的输入产生相同的输出，天然线程安全。并发调用由调用方管理。

ASSCOR 适配层（`internal/ssam/`）的 `Engine` 包装器在读写权重、边缘因子、钩子配置时使用 `sync.RWMutex` 保护，但核心计算路径为无锁纯函数调用 ssam-lib。

---

## 13. 错误处理

| 错误变量 | 含义 |
|----------|------|
| `ErrNilInput` | 输入为 nil |
| `ErrUnknownFormula` | 指定的公式 ID 不存在 |
| `ErrEmptyWeights` | 未配置任何权重 |
| `ErrInvalidScore` | 输出分数超出 [0, 100] 范围 |
| `ValidationError` | 输入字段验证失败，含 `Field` 和 `Message` 字段 |

`ComputeScore` 的错误返回策略：

- 输入为 nil → 返回 `ErrNilInput`
- 输入验证失败 → 返回 `ValidationError`
- 上下文取消 → 返回 `ctx.Err()`
- 正常完成 → 返回 `(output, nil)`

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
    "context"
    "fmt"
    "log"
    "math"
    "strings"
    "time"

    "github.com/asscor/ssam"
)

func main() {
    engine := ssam.NewEngine()

    engine.SetWeights(ssam.DefaultWeights)
    engine.SetEdgeFactors(ssam.DefaultEdgeFactors)

    engine.RegisterHook(ssam.HookPostScore, "audit-log", func(
        ctx context.Context,
        input *ssam.AssessmentInput,
        output *ssam.AssessmentOutput,
    ) error {
        for _, ds := range output.DomainScores {
            fmt.Printf("[audit] domain=%s score=%.0f\n", ds.Domain, ds.Score)
        }
        return nil
    }, 10)

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    input := &ssam.AssessmentInput{
        HostID:      "prod-web-01",
        Hostname:    "web.example.com",
        Threshold:   80,
        ThreatCoeff: 0.95,
        SPCScore:    0.92,
        Checks: []ssam.CheckInput{
            {CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Hardening", Passed: true, Delta: 0},
            {CheckID: "AS-003", Domain: "attack_surface", Name: "Open Ports", Passed: false, Delta: -15, Detail: "port 23 open"},
            {CheckID: "BC-001", Domain: "business_continuity", Name: "Service Status", Passed: true, Delta: 0},
            {CheckID: "OT-002", Domain: "operation_trust", Name: "Audit Log", Passed: false, Delta: -20, Detail: "auditd not running"},
            {CheckID: "RS-001", Domain: "resilience", Name: "Fail2ban", Passed: true, Delta: 0},
        },
    }

    output, err := engine.ComputeScore(ctx, input)
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
go test ./internal/ssam/... -v

# 运行适配器集成测试
go test ./internal/ssam/... -v -run TestConfigTo

# 运行完整评分流程测试
go test ./internal/ssam/... -v -run TestComputeScore

# 运行钩子测试
go test ./internal/ssam/... -v -run TestHooks
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
