# SSAM Interface Specification and Integration Guide

> **Version**: SSAM 2.0 | **Module Path**: `github.com/chins-xing/ssam`
> **ASSCOR Adapter Layer**: `internal/engine/ssam/` (thin adapter layer delegating to ssam-lib)
> **Date**: 2026-06-28 | **Status**: Released

This document specifies in detail the interface contract, data-structure definitions, configuration-adaptation mechanism, and integration methods of the SSAM standalone algorithm module. SSAM V2.0 has been isolated as the purely functional Go module `github.com/chins-xing/ssam` (located in `ssam-lib/`) and can be used independently of the ASSCOR framework. The ASSCOR platform delegates all calls to ssam-lib through the thin adapter layer at `internal/engine/ssam/`.

---

## 1. Module Overview

`github.com/chins-xing/ssam` (`ssam-lib/`) is the purely functional engine behind SSAM V2.0, with zero external dependencies. It comprises the following files:

| File | Responsibility |
|------|----------------|
| `ssam.go` | Engine core implementation: `Provider` interface, input validation, hook mechanism, formula dispatch |
| `types.go` | V1.x data types (`AssessmentInput`, `AssessmentOutput`, etc.), kept for backward compatibility |
| `types_v2.go` | V2.0 data types: `RiskContext`, `RiskLayerDetail`, `RiskLayers`, `FinalScore`, `AssessmentInputV2`, `AssessmentOutputV2`, `ScoringFormulaV2` |
| `formulas.go` | V1.x formula implementations (`ssam_v1.2`, `simple_weighted`), kept for backward compatibility |
| `formulas_v2.go` | V2.0 formula `SSAMV20Formula`: three-layer semantic model (intrinsic/exposure/threat) with independent per-layer risk assessment |
| `ir.go` | SSAM IR JSON intermediate representation: `AssessmentOutputV2.ToIR()` emits a machine-readable, structured assessment result |
| `ast.go` | Formula DSL/AST: `ParseFormula(expression)` parses a formula string into an AST; `EvaluateFormula(ast, ctx)` evaluates it |
| `formulas_ast.go` | AST-driven formula implementation, supporting dynamic construction of scoring formulas at runtime |
| `engine_test.go` | Full test coverage (V1.x regression + V2.0 three-layer model + IR export + AST parsing) |

The ASSCOR adapter layer (`internal/engine/ssam/`) is deliberately kept small — two files:

| File | Responsibility |
|------|----------------|
| `adapter.go` | Bidirectional conversion between ASSCOR configs/models and SSAM formats (delegates to the ssam-lib Engine) |
| `defaults.go` | Default weights, edge factors, and factory functions |

---

## 2. Core Interfaces

### 2.1 Provider Aggregate Interface

`Provider` is the top-level interface exposed by the SSAM module; it aggregates four sub-interfaces:

```go
type Provider interface {
    ScoringProvider
    DomainProvider
    EdgeFactorProvider
    HookProvider
}
```

The `Engine` struct implements the `Provider` interface, guaranteed by a compile-time assertion:

```go
var _ Provider = (*Engine)(nil)
```

### 2.2 ScoringProvider — Scoring Interface

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

| Method | Description |
|--------|-------------|
| `ComputeScore` | Full scoring pipeline: input validation → domain scoring → edge factors → formula computation → output |
| `ComputeDomainScores` | Aggregates checks by domain and computes a 0–100 score for each domain |
| `ComputeWeightedSum` | Computes the weighted sum of the domain scores |
| `ApplyEdgeFactors` | Applies multiplicative correction of the active edge factors to the base score |
| `SetWeights` / `GetWeights` | Dynamically set/get the core-domain weights |
| `SetFormula` / `GetFormula` | Switch/get the scoring formula (built-ins `ssam_v1.2` and `simple_weighted`) |
| `SetFormulaV2` / `GetFormulaV2` | Switch/get the V2.0 scoring formula (built-in `ssam_v2.0`, which uses the three-layer semantic model) |

### 2.3 DomainProvider — Domain Information Interface

```go
type DomainProvider interface {
    ListDomains() []string
    GetDomainLabel(id string) string
    GetDefaultWeight(id string) float64
}
```

| Method | Description |
|--------|-------------|
| `ListDomains` | Returns the IDs of all domains that have weights configured (sorted) |
| `GetDomainLabel` | Returns a human-readable label for a domain (defaults to the domain ID itself) |
| `GetDefaultWeight` | Returns the weight of the given domain, or 0 when not configured |

### 2.4 EdgeFactorProvider — Edge Factor Interface

```go
type EdgeFactorProvider interface {
    ListEdgeFactors() []EdgeFactorResult
    EvaluateEdgeFactors(checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult
}
```

| Method | Description |
|--------|-------------|
| `ListEdgeFactors` | Returns all registered edge-factor configurations (`Active=false`) |
| `EvaluateEdgeFactors` | Evaluates edge-factor triggering against the check results and returns the results with the `Active` flag set |

### 2.5 HookProvider — Hook Interface

```go
type HookProvider interface {
    RegisterHook(phase HookPhase, id string, hook AssessmentHook, priority int)
    UnregisterHook(id string)
    ExecuteHooks(ctx context.Context, phase HookPhase, input *AssessmentInput, output *AssessmentOutput) []error
}
```

| Method | Description |
|--------|-------------|
| `RegisterHook` | Registers a hook function for the given phase; a lower `priority` runs earlier |
| `UnregisterHook` | Removes a hook by ID |
| `ExecuteHooks` | Executes all hooks registered for the given phase (sorted by priority) and returns the error list |

Hook-phase definitions:

```go
type HookPhase string

const (
    HookPreScore  HookPhase = "pre_score"   // before domain scoring
    HookPostScore HookPhase = "post_score"  // after domain scoring
    HookPreEdge   HookPhase = "pre_edge"    // before edge-factor evaluation
    HookPostEdge  HookPhase = "post_edge"   // after edge-factor evaluation
)
```

Hook function signature:

```go
type AssessmentHook func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error
```

---

## 3. Data Structures

### 3.1 AssessmentInput — Assessment Input

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

| Field | Type | Description |
|-------|------|-------------|
| `HostID` | string | Unique host identifier |
| `Hostname` | string | Host name |
| `Timestamp` | time.Time | Assessment timestamp |
| `Threshold` | float64 | Acceptable threshold (0–100), defaults to 80 |
| `Checks` | []CheckInput | List of check results |
| `ThreatCoeff` | float64 | Threat-posture coefficient (0.60–1.00); auto-set to 1.0 when 0 |
| `SPCScore` | float64 | SPC posture-correction factor (0.60–1.00); auto-set to 1.0 when 0 |
| `WeightShifts` | map[string]float64 | Temporary domain-weight shifts produced by SPC (optional) |

> **SPC Assessment-Methodology Declaration**: `SPCScore` is produced by the SPC module through CPE string matching — i.e., comparing installed software package names/versions against the affected product versions in the CVE database. It does **not** involve exploit verification, runtime reachability analysis, or binary analysis. See the [SPC Security Posture Computation Module Technical Whitepaper](SPC安全态势计算模块技术白皮书.md).

### 3.2 CheckInput — Check Item Input

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

| Field | Description |
|-------|-------------|
| `CheckID` | Unique check identifier (e.g. `AS-001`, `BC-003`) |
| `Domain` | The core domain the check belongs to (`attack_surface`/`business_continuity`/`operation_trust`/`resilience`) |
| `Name` | Check name |
| `Passed` | Whether the check passed |
| `Delta` | Points deducted on failure (negative, e.g. -15) |
| `Detail` | Check detail description |

### 3.3 AssessmentOutput — Assessment Output

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

| Field | Description |
|-------|-------------|
| `FinalScore` | Final assessment score (0–100, rounded to two decimal places) |
| `Acceptable` | Whether acceptable (`FinalScore >= Threshold`) |
| `DomainScores` | Per-core-domain scores |
| `EdgeFactors` | Edge-factor evaluation results (including the `Active` flag) |
| `FormulaID` | Identifier of the scoring formula used |
| `Metadata` | Custom metadata (writable by hooks) |

### 3.4 EdgeFactorConfig — Edge Factor Configuration

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

| Field | Description |
|-------|-------------|
| `ID` | Unique edge-factor identifier (e.g. `EF-002FA`) |
| `Name` | Human-readable name |
| `Factor` | Multiplicative correction factor (0.0–1.0; e.g. 0.85 means ×0.85) |
| `TriggerCheck` | ID of the check that triggers this factor |
| `CascadeTo` | ID of the target factor to cascade to (optional) |
| `CascadeValue` | Value that overrides the target factor when cascading (optional) |
| `CascadeOnly` | When true, this factor does not participate in the multiplicative correction itself and only affects the target factor via the cascade |

**Cascade example**: when 3FA is not satisfied (`EF-3FA`), the cascade overrides the 2FA factor (`EF-002FA`) value from 0.85 to 0.82:

```go
EdgeFactorConfig{
    ID: "EF-3FA", Name: "3FA Not Met", Factor: 0.82,
    TriggerCheck: "EF-002", CascadeTo: "EF-002FA",
    CascadeValue: 0.82, CascadeOnly: true,
}
```

---

## 3.5 SSAM V2.0 Data Types (types_v2.go)

### 3.5.1 RiskContext — Risk Context

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

### 3.5.2 RiskLayerDetail / RiskLayers — Three Risk Layers

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

| Risk Layer | Meaning | Typical Inputs |
|------------|---------|----------------|
| **Intrinsic (intrinsic risk)** | The system's own configuration-security baseline, independent of the external environment | Core-domain scores, edge factors |
| **Exposure (exposure risk)** | The vulnerability surface the system exposes to the outside | SPC P_score, port exposure, CVE matches |
| **Threat (threat risk)** | The impact of the current threat environment | CTI μ coefficient, threat-actor activity, KEV in-the-wild exploitation |

### 3.5.3 FinalScore — V2.0 Final Score

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

### 3.5.4 AssessmentInputV2 — V2.0 Assessment Input

```go
type AssessmentInputV2 struct {
    HostID    string       `json:"host_id"`
    Hostname  string       `json:"hostname"`
    Timestamp time.Time    `json:"timestamp"`
    Context   RiskContext  `json:"context"`
    Checks    []CheckInput `json:"checks"`
}
```

### 3.5.5 AssessmentOutputV2 — V2.0 Assessment Output

```go
type AssessmentOutputV2 struct {
    HostID       string              `json:"host_id"`
    FinalScore   FinalScore          `json:"final_score"`
    DomainScores []DomainScore       `json:"domain_scores"`
    EdgeFactors  []EdgeFactorResult  `json:"edge_factors"`
    CalculatedAt time.Time           `json:"calculated_at"`
}
```

`AssessmentOutputV2` provides a `.ToIR()` method that exports the declared SSAM IR JSON structure (see §5).

### 3.5.6 ScoringFormulaV2 — V2.0 Formula Interface

```go
type ScoringFormulaV2 interface {
    ID() string
    Compute(ctx context.Context, input *AssessmentInputV2) (*AssessmentOutputV2, error)
    ValidateInput(input *AssessmentInputV2) error
}
```

Built-in implementations:
- `SSAMV20Formula` (`formulas_v2.go`): evaluates the three independent risk layers, removing the double-penalty problem of the legacy ThreatCoeff/SPCScore combination
- `ASTFormula` (`formulas_ast.go`): a formula dynamically constructed through the Formula DSL

---

## 4. SSAM V2.0 Three-Layer Semantic Model

The core innovation of SSAM V2.0 is replacing the single multiplicative stacking of ThreatCoeff and SPCScore used in V1.x with three independent risk layers. Each layer has its own semantics, weight, and inputs:

```
AssessmentInputV2
    │
    ├── Intrinsic Risk Layer (Intrinsic)
    │   ├── Weighted core-domain score (SSAM v1.2 core formula)
    │   ├── Edge-factor multiplicative correction
    │   └── Output: Intrinsic Score ∈ [0, 100]
    │
    ├── Exposure Risk Layer (Exposure)
    │   ├── SPC P_score conversion
    │   ├── CVE count / severity
    │   ├── Port exposure surface
    │   └── Output: Exposure Score ∈ [0, 100]
    │
    ├── Threat Risk Layer (Threat)
    │   ├── CTI μ-coefficient conversion
    │   ├── KEV in-the-wild exploitation status
    │   ├── Threat-actor activity
    │   └── Output: Threat Score ∈ [0, 100]
    │
    ▼
FinalScore = Σ(LayerScore_i × LayerWeight_i) / ΣLayerWeight_i
```

**Key differences from V1.x:**

| Feature | V1.x (ssam_v1.2) | V2.0 (ssam_v2.0) |
|---------|------------------|------------------|
| External-factor handling | ThreatCoeff × SPCScore double-multiplier stacking | Three independent layers scored separately + weighted average |
| Double penalty | A low SPC score is additionally multiplied by μ, causing excessive penalization | Each layer is computed independently; weights are tunable |
| Explainability | The final score is hard to decompose into "what caused it" | RiskLayers provide per-layer decomposition |
| Flexibility | Fixed formula | Layer weights and composition dynamically configurable via AST/DSL |

---

## 5. SSAM IR (Intermediate Representation)

SSAM V2.0 introduces SSAMIR — a declarative JSON intermediate representation of assessment results, exported through `AssessmentOutputV2.ToIR()`:

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

Design goals of SSAM IR:
- **Consumed by downstream toolchains**: SIEMs, SOC dashboards, and compliance-audit systems can parse it directly
- **Cross-language interoperability**: pure JSON, parseable by any language
- **Versioned compatibility**: the `ssamir_version` field guarantees forward/backward compatibility

---

## 6. Formula DSL / AST

SSAM V2.0 ships a formula DSL that lets you construct scoring formulas at runtime from string expressions, without modifying code:

```go
import "github.com/chins-xing/ssam"

ast, err := ssam.ParseFormula("intrinsic * 0.5 + exposure * 0.3 + threat * 0.2")
if err != nil {
    log.Fatal(err)
}

engine := ssam.NewDefaultEngine()
engine.SetFormulaAST(ast)

output, err := engine.ComputeScoreV2(ctx, inputV2)
```

Supported DSL syntax:
- Variables: `intrinsic`, `exposure`, `threat` (the three risk-layer scores)
- Operators: `+`, `-`, `*`, `/`, `(`, `)`
- Literals: integers and floats
- Functions: `min(a,b)`, `max(a,b)`, `round(x)`, `sqrt(x)`

A DSL expression is compiled by `ParseFormula()` into an AST, which `EvaluateFormula()` evaluates efficiently — no runtime string parsing is needed.

---

## 7. Scoring Pipeline

Full execution flow of `ComputeScore`:

```
Input validation (ValidateInput)
    │
    ▼
ctx cancellation check
    │
    ▼
HookPreScore hooks
    │
    ▼
Domain scoring (ComputeDomainScores)
    │  ┌─────────────────────────────────────────────┐
    │  │ Each domain starts at 100                   │
    │  │ Iterate over failed checks, accumulating    │
    │  │ Delta (negative); domain score floors at 0  │
    │  └─────────────────────────────────────────────┘
    │
    ▼
ctx cancellation check
    │
    ▼
HookPostScore hooks
    │
    ▼
HookPreEdge hooks
    │
    ▼
Edge-factor evaluation (ApplyEdgeFactorsToChecks)
    │  ┌─────────────────────────────────────────────┐
    │  │ 1. Check triggering: a failed check matches │
    │  │    its TriggerCheck → mark factor active    │
    │  │ 2. Cascade handling: an active factor with  │
    │  │    CascadeTo overwrites the target factor   │
    │  │    with CascadeValue                        │
    │  │ 3. A CascadeOnly factor does not itself     │
    │  │    participate in multiplicative correction │
    │  │ 4. Custom factor-value overrides            │
    │  │    (customFactors)                          │
    │  └─────────────────────────────────────────────┘
    │
    ▼
ctx cancellation check
    │
    ▼
HookPostEdge hooks
    │
    ▼
Formula computation (applyFormula)
    │  SSAM v1.2 formula:
    │  baseScore = Σ(Si × Wi) / ΣWi
    │  baseScore *= threatCoeff
    │  baseScore *= spcScore
    │  for each active edgeFactor:
    │      baseScore *= factor
    │  finalScore = round(baseScore, 2)
    │
    ▼
Acceptability check (finalScore >= threshold)
    │
    ▼
Return AssessmentOutput
```

---

## 8. Integration Methods

### 8.1 Method 1: Standalone Use (Recommended for Third-Party Integration)

The SSAM module can be used entirely standalone, decoupled from the ASSCOR framework:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/chins-xing/ssam"
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

### 8.2 Method 2: Custom Configuration

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

### 8.3 Method 3: Registering a Custom Formula

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

### 8.4 Method 4: Extending the Scoring Pipeline with Hooks

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

### 8.5 Method 5: Integration Through the ASSCOR DI Container (v0.2.2 dependency-inversion architecture, still current in v0.2.3)

ASSCOR v0.2.3 defines a unified `kernel.AssessorEngine` interface (specified in `internal/kernel/engine_types.go`; the v0.2.2 dependency-inversion architecture continues into v0.2.3, which stays compatible). SSAM implements this interface via `ssam.EngineAdapter` and is injected as a plugin:

**Registration side (platform layer in cmd/kernel/main.go):**

```go
func main() {
    cfg := config.Load(...)
    scoringEngine := kernel.NewScoringEngineModule(cfg)

    // SSAM injected as an ASSCOR plugin (dependency direction: SSAM → ASSCOR)
    if cfg.ScoringEngine != "legacy" {
        adapter := ssam.NewEngineAdapter(cfg)
        scoringEngine.SetPluginEngine(adapter)
    }

    k.Container().Bind((*kernel.ScoringEngineProvider)(nil), scoringEngine)
}
```

**Consumer side (inside AssessorModule, transparent to the plugin):**

```go
type Assessor struct {
    pluginEngine kernel.AssessorEngine  // unified interface, not a concrete ssam type
}

func (a *Assessor) tryPluginScore(ctx context.Context, result *model.AssessmentResult) bool {
    if a.pluginEngine == nil {
        return false
    }
    return a.pluginEngine.ComputeScore(ctx, result) == nil
}
```

**Key changes (v0.2.0 → v0.2.2):**
- Old: `a.ssamEngine ssam.ScoringProvider` → New: `a.pluginEngine kernel.AssessorEngine`
- Old: `ssam.NewEngine()` hardcoded inside the assessor → New: `ssam.NewEngineAdapter(cfg)` injected in main.go
- Old: `ssam.ScoringProvider` bound directly into the DI container → New: unified `kernel.AssessorEngine` interface
- Old: ASSCOR depended on the SSAM package → New: SSAM depends on the ASSCOR interface

---

## 9. Configuration Adaptation

`adapter.go` provides bidirectional conversion functions between ASSCOR configs/models and the SSAM formats:

### 9.1 Configuration Conversion

| Function | Direction | Description |
|----------|-----------|-------------|
| `ConfigToWeights(cfg)` | Config → SSAM | Converts ASSCOR-configured weights into `[]WeightConfig` |
| `ConfigToEdgeFactors(cfg)` | Config → SSAM | Converts ASSCOR-configured edge factors into `[]EdgeFactorConfig` |

**Corresponding config.ini section:**

```ini
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15
kernel_security = 0
# scoring_engine: empty = SSAM, legacy = built-in engine
scoring_engine =

[edge_factors]
two_factor_failure = 0.85
syn_cookie_disabled = 0.75
selinux_disabled = 0.80
apparmor_disabled = 0.82
no_siem = 0.90
no_ids = 0.88
```

### 9.2 Model Conversion

| Function | Direction | Description |
|----------|-----------|-------------|
| `CheckResultsToInputs(checks)` | model → SSAM | `[]model.CheckResult` → `[]CheckInput` |
| `DomainScoresToOutput(scores)` | SSAM → model | `[]DomainScore` → `model.DomainScores` |
| `EdgeFactorsToModel(factors)` | SSAM → model | `[]EdgeFactorResult` → `model.EdgeFactors` |
| `ModelToInput(result)` | model → SSAM | `*model.AssessmentResult` → `*AssessmentInput` |
| `OutputToModel(output, result)` | SSAM → model | Writes an `AssessmentOutput` into `*model.AssessmentResult` |

### 9.3 Edge-Factor ID Mapping

| SSAM ID | model Field | config.ini Key |
|---------|-------------|----------------|
| `EF-002FA` | `EdgeFactors.TwoFactorFailure` | `two_factor_failure` |
| `EF-SYNCOOKIE` | `EdgeFactors.SYNCookieDisabled` | `syn_cookie_disabled` |
| `EF-SELINUX` | `EdgeFactors.SELinuxDisabled` | `selinux_disabled` |
| `EF-APPARMOR` | `EdgeFactors.AppArmorDisabled` | `apparmor_disabled` |
| `EF-NO-SIEM` | `EdgeFactors.NoSIEM` | `no_siem` |
| `EF-NO-IDS` | `EdgeFactors.NoIDS` | `no_ids` |
| `EF-3FA` | cascades to `EF-002FA` | — |

---

## 10. Input Validation

`ValidateInput` is invoked automatically at the entry point of `ComputeScore`. Validation rules:

| Field | Rule | Error Type |
|-------|------|------------|
| `input` | Must not be nil | `ErrNilInput` |
| `HostID` | Must not be empty | `ValidationError{Field: "host_id"}` |
| `Threshold` | Must be within (0, 100] | `ValidationError{Field: "threshold"}` |
| `Checks[i].Domain` | Must not be empty | `ValidationError{Field: "checks[i].domain"}` |

Custom-validation example:

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

## 11. Default Values

Default configuration provided by `defaults.go`:

**Default weights:**

| Domain | Weight |
|--------|--------|
| attack_surface | 35 |
| business_continuity | 25 |
| operation_trust | 25 |
| resilience | 15 |

**Default edge factors:**

| ID | Name | Factor | Triggering Check |
|----|------|--------|------------------|
| EF-002FA | 2FA Missing | 0.85 | EF-001 |
| EF-SYNCOOKIE | SYN Cookie Disabled | 0.75 | EF-SYNCOOKIE |
| EF-SELINUX | SELinux Disabled | 0.80 | EF-SELINUX |
| EF-APPARMOR | AppArmor Disabled | 0.82 | EF-APPARMOR |
| EF-NO-SIEM | SIEM Integration Missing | 0.90 | EF-NO-SIEM |
| EF-NO-IDS | IDS/IPS Missing | 0.88 | EF-NO-IDS |
| EF-3FA | 3FA Not Met | 0.82 | EF-002 (cascades to EF-002FA) |

Create an engine with the default configuration:

```go
engine := ssam.NewDefaultEngine()
```

---

## 12. Concurrency Safety

ssam-lib (`github.com/chins-xing/ssam`) is a purely functional library: zero goroutines, zero locks, zero shared state. Assessment functions are side-effect-free pure functions — identical inputs always yield identical outputs, so they are inherently thread-safe. Concurrent invocations are managed by the caller.

The ASSCOR adapter layer (`internal/engine/ssam/`) protects reads/writes of weights, edge factors, and hook configuration in its `Engine` wrapper with a `sync.RWMutex`; the core computation path, however, calls into ssam-lib as lock-free pure functions.

---

## 13. Error Handling

| Error Variable | Meaning |
|----------------|---------|
| `ErrNilInput` | The input is nil |
| `ErrUnknownFormula` | The specified formula ID does not exist |
| `ErrEmptyWeights` | No weights configured |
| `ErrInvalidScore` | The output score falls outside the [0, 100] range |
| `ValidationError` | Input-field validation failed; carries `Field` and `Message` |

Error-return policy of `ComputeScore`:

- Input is nil → returns `ErrNilInput`
- Input validation fails → returns `ValidationError`
- Context canceled → returns `ctx.Err()`
- Successful completion → returns `(output, nil)`

---

## 14. ASSCOR Kernel Infrastructure Interfaces

The following interfaces belong to the ASSCOR kernel (`internal/kernel`) and work alongside the SSAM module.

### 14.1 DI Container

```go
container := kernel.NewContainer()

container.Bind((*ssam.ScoringProvider)(nil), engine)
container.BindNamed("config", (*config.Config)(nil), cfg)

impl, ok := container.Resolve((*ssam.ScoringProvider)(nil))
impl, ok := container.ResolveNamed("config")

container.Inject(targetStruct)
container.Remove((*ssam.ScoringProvider)(nil))
```

**Struct-field injection:**

```go
type MyModule struct {
    Scorer ssam.ScoringProvider `inject:"true"`
    Config *config.Config       `inject:"config"`
}
```

### 14.2 Message Bus

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

### 14.3 Circuit Breaker

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

The circuit breaker is wired into the request chain through the interceptor pattern (see §14.4, interceptor chain).

### 14.4 Interceptor Chain

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

## 15. Complete Integration Example

The following example demonstrates integrating the SSAM module into a custom security-assessment system:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "math"
    "strings"
    "time"

    "github.com/chins-xing/ssam"
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

## 16. Testing

The SSAM module ships with complete unit and integration tests:

```bash
# Run the SSAM module tests
go test ./internal/engine/ssam/... -v

# Run the adapter integration tests
go test ./internal/engine/ssam/... -v -run TestConfigTo

# Run the full scoring-pipeline tests
go test ./internal/engine/ssam/... -v -run TestComputeScore

# Run the hook tests
go test ./internal/engine/ssam/... -v -run TestHooks
```

Key scenarios covered by the tests:

- Scoring with all-passed / all-failed / partially-passed checks
- Edge-factor triggering and cascading
- Custom-formula registration and switching
- Hook registration / unregistration / execution
- Input validation (nil, empty fields, out-of-range values)
- Context cancellation
- Concurrency safety
- Bidirectional ASSCOR configuration adaptation
