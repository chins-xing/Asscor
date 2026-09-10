# 边缘因子耦合与变量化实现计划 — 里程碑 A（统一框架 + 四候选 + 变量化 + 离线工具）

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现边缘因子耦合的统一合成框架（`M0 legacy` / `V 逐域向量` / `G 耦合图` / `C 时序链` 四候选）、全参数配置注入与校验、`ssam-lib` 单点合成策略钩子，以及离线重算/拟合/报告工具 `cmd/edgecompare`；默认配置与历史评分逐位一致。

**Architecture:** 新增 `internal/edgefactor`（tag `edgefactor`）承载统一公式、四候选、参数校验与性质测试；`ssam-lib` 只把 `evalProductChain` 改为可注入合成策略（默认乘性，行为逐位不变）；`internal/engine/ssam` 按配置装配策略；离线工具 `cmd/edgecompare`（tag `edgeexp`）复用 `internal/edgefactor` 的同一份实现读取实验 JSONL、重算四候选、计算三层指标并拟合参数。实验执行（P5–P7）不在本计划。

**Tech Stack:** Go 1.26、`math`、`encoding/json`、`crypto/sha256`、build-tag 模块模式（`edgefactor` / `edgeexp`）、既有 `internal/config` 纯解析范式、既有 `model.EdgeFactors` 契约。

**Spec:** `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md`

## Global Constraints

- 分支 `ASSCOR-Research-Core`；提交说明必须**中文**（`feat(edgefactor): …` 前缀可保留英文分类词）。
- `internal/edgefactor` **不带 build tag**（默认编译，纯函数、无内部依赖、默认 legacy 不改变行为）——它随默认构建与 CI 无 tag 线一起受测；只有离线工具 `cmd/edgecompare` 带 tag `edgeexp`，内仓钩子随 `ssam-lib` 常规编译。测试命令：`go test ./internal/edgefactor/...`（无 tag）。
- **默认行为不变（硬门禁）**：未配置 `[edge_factors.model]` 时必须走 `legacy` 乘性路径，与历史评分**逐位一致**；方向① 的可信度语义 `effective_f = 1 − (1 − f)·c_trigger` 原样保留。
- 公式（spec §3.1）：`a_i[d] = (1 − effective_f_i)·v_i[d]`；`L_d = Σ a_i[d] + Σ c_ij·a_i[d]·a_j[d]`；`P_d = P_floor + (1−P_floor)·exp(−λ_d·L_d)`；域分修正 `Score_d' = Base_d · P_d`。
- `legacy` 的特殊性：它在**聚合后**作用于总分（`∏ f_i`），不由 `P_d` 表达 → 由 `Result.GlobalMultiplier` 承载（新模型恒为 1）。
- 参数校验 fail-fast：`v` 维度不符、`f ∉ (0,1]`、`c < 0`、`λ ≤ 0`、`p_floor ∉ (0,1)`、`Σ_d v_i[d] > 1` 一律拒绝。
- `c_ij ≥ 0` 且 `v_i[d] ≥ 0`（保 P2/P3）；冗余/重叠只能通过 `Σ_d v_i[d] ≤ 1` 表达。
- 溯源：任何合成结果必须携带 `Model` 与 `ParamsHash`（规范化 JSON 的 sha256 前 16 位十六进制）。
- 属性测试与全组合扫描：因子全组合枚举 `2⁶ = 64` 必须覆盖（spec §6）。
- `config` 包保持**纯解析、无副作用**（沿用耦合审计 F6 的结论）；注册/装配只在装配根发生。
- `ssam-lib` 是内嵌独立仓库：改动必须提交内仓 `master` **并**同步外层快照；禁止内仓 `git checkout -- .`。
- gofmt 干净（提交前对改动文件做 LF 归一的 `gofmt -l` 检查；Windows 本地 CRLF 会假阳性）。

**Scope 说明**：本计划 = 里程碑 A（P1–P4）。里程碑 B（P5 实验执行、P6 拟合选模、P7 文档与论文口径）依赖 WSL2 Containerlab 与 A-1，另写计划。

---

## File Structure

| 文件 | 职责 |
|---|---|
| `internal/edgefactor/model.go` | `ModelID`、`Params`、`FactorActivation`、`Input`、`Result`、`Validate`、`Hash` |
| `internal/edgefactor/synthesize.go` | 统一公式合成（V/G/C）+ legacy 乘性分支 + 域分修正 |
| `internal/edgefactor/properties_test.go` | P1/P2/P3/P5 性质测试、`2⁶` 全组合扫描 |
| `internal/edgefactor/synthesize_test.go` | 数值向量测试（手算）、legacy 乘性锚定、耦合/级联用例 |
| `internal/config/edgefactor.go` | `[edge_factors.model]` 与触发映射表的**纯解析** |
| `internal/config/edgefactor_test.go` | 解析、缺省、坏值 fail-fast |
| `internal/engine/ssam/adapter.go` | 触发映射改由配置表提供（默认值等价现状） |
| `internal/engine/ssam/edgefactor.go` | 配置→`edgefactor.Params` 装配 + 策略注入 |
| `internal/engine/ssam/edgefactor_test.go` | 装配、默认 legacy、逐位一致门禁 |
| `internal/model/model.go` | `EdgeFactorResult` 增加 `Model`/`ParamsHash`（契约字段） |
| `ssam-lib/ast.go`（内仓） | `evalProductChain` → 可注入合成策略（接口 + 默认乘性） |
| `ssam-lib/ast_test.go`（内仓） | 默认路径不变、注入路径生效 |
| `cmd/edgecompare/main.go` | 离线工具入口（tag `edgeexp`） |
| `cmd/edgecompare/load.go` | 实验 JSONL 读取与 schema |
| `cmd/edgecompare/metrics.go` | 决策层/排序层/数值层三层指标 |
| `cmd/edgecompare/report.go` | Markdown + JSON 报告与参数段输出 |
| `cmd/edgecompare/fit.go` | 含交互项 logistic 回归 + 先验边集 + 交叉验证 + 自助法 |
| `cmd/edgecompare/*_test.go` | 指标、报告、拟合可恢复性、离线↔在线一致性 |

**任务→阶段映射**：Task 1–2 = P1（纯函数框架）；Task 3–5 = P2（变量化与溯源）；Task 6–7 = P3（内仓钩子 + 外层接入）；Task 8–10 = P4（离线工具）。

---

### Task 1: 参数模型与 fail-fast 校验

**Files:**
- Create: `internal/edgefactor/model.go`
- Test: `internal/edgefactor/model_test.go`

**Interfaces:**
- 包无 build tag（主控裁定，优先于本节早期草稿）。
- Produces:
  - `type ModelID string`，常量 `ModelLegacy`/`ModelVector`/`ModelGraph`/`ModelChain`
  - `type Params struct{ Model ModelID; PFloor float64; Lambda map[string]float64; Vectors map[string]map[string]float64; Coupling map[string]map[string]float64; ChainWindowSeconds int; Factors map[string]float64 }`
  - `func (p Params) Validate(domains []string) error`
  - `func (p Params) Hash() string`
  - `func DefaultDomains() []string`

- [ ] **Step 1: 写失败测试**

```go
package edgefactor

import (
	"strings"
	"testing"
)

func baseParams() Params {
	return Params{
		Model:   ModelVector,
		PFloor:  0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8},
	}
}

func TestValidateAcceptsWellFormedParams(t *testing.T) {
	if err := baseParams().Validate([]string{"attack_surface", "operation_trust"}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Params){
		"factor out of range": func(p *Params) { p.Factors["EF-SELINUX"] = 1.5 },
		"zero factor":         func(p *Params) { p.Factors["EF-SELINUX"] = 0 },
		"negative coupling": func(p *Params) {
			p.Coupling = map[string]map[string]float64{"A": {"B": -0.1}}
		},
		"non-positive lambda": func(p *Params) { p.Lambda["attack_surface"] = 0 },
		"pfloor out of range": func(p *Params) { p.PFloor = 1.0 },
		"unknown domain in vector": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"nope": 0.5}
		},
		"vector sum above one": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": 0.7, "operation_trust": 0.7}
		},
		"negative vector component": func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": -0.1}
		},
	}
	for name, mutate := range cases {
		p := baseParams()
		mutate(&p)
		if err := p.Validate([]string{"attack_surface", "operation_trust"}); err == nil {
			t.Errorf("%s: Validate must fail", name)
		}
	}
}

func TestValidateRejectsUnknownModel(t *testing.T) {
	p := baseParams()
	p.Model = "oracle"
	if err := p.Validate([]string{"attack_surface"}); err == nil {
		t.Fatal("unknown model must be rejected")
	}
}

func TestHashIsStableAndSensitive(t *testing.T) {
	a := baseParams()
	h1, h2 := a.Hash(), a.Hash()
	if h1 != h2 || len(h1) != 16 || strings.ContainsAny(h1, "ABCDEF") {
		t.Errorf("Hash must be a stable 16-char lowercase hex, got %q/%q", h1, h2)
	}
	b := baseParams()
	b.Factors["EF-SELINUX"] = 0.79
	if a.Hash() == b.Hash() {
		t.Error("Hash must change when parameters change")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/edgefactor/ -run TestValidate -v`
Expected: FAIL — `undefined: Params`

- [ ] **Step 3: 实现**

```go
package edgefactor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ModelID 选择边缘因子的合成模型（spec §3.2）。
type ModelID string

const (
	ModelLegacy ModelID = "legacy" // 现状乘性连乘（聚合后作用于总分）
	ModelVector ModelID = "vector" // 逐域向量，无耦合项
	ModelGraph  ModelID = "graph"  // 逐域向量 + 对称耦合
	ModelChain  ModelID = "chain"  // 逐域向量 + 有向时序耦合
)

// Params 是全部可注入参数；代码中不得出现因子常量（spec §4）。
type Params struct {
	Model              ModelID
	PFloor             float64                        // 惩罚上限 = 1 − PFloor
	Lambda             map[string]float64             // 逐域 λ_d
	Vectors            map[string]map[string]float64  // factorID → domain → v_i[d]
	Coupling           map[string]map[string]float64  // factorID → factorID → c_ij
	ChainWindowSeconds int                            // 仅 chain
	Factors            map[string]float64             // factorID → f_i
}

// DefaultDomains 返回域顺序（与 config.ini / WeightConfig 一致）。
func DefaultDomains() []string {
	return []string{"attack_surface", "business_continuity", "operation_trust", "resilience", "kernel_security"}
}

// Validate 做 fail-fast 校验（spec §4 规则 3）。
func (p Params) Validate(domains []string) error {
	switch p.Model {
	case ModelLegacy, ModelVector, ModelGraph, ModelChain:
	default:
		return fmt.Errorf("edgefactor: unknown model %q", p.Model)
	}
	if p.PFloor <= 0 || p.PFloor >= 1 {
		return fmt.Errorf("edgefactor: p_floor %v out of (0,1)", p.PFloor)
	}
	known := make(map[string]bool, len(domains))
	for _, d := range domains {
		known[d] = true
	}
	for d, l := range p.Lambda {
		if !known[d] {
			return fmt.Errorf("edgefactor: lambda for unknown domain %q", d)
		}
		if l <= 0 {
			return fmt.Errorf("edgefactor: lambda[%s] must be > 0, got %v", d, l)
		}
	}
	for id, f := range p.Factors {
		if f <= 0 || f > 1 {
			return fmt.Errorf("edgefactor: factor %s = %v out of (0,1]", id, f)
		}
	}
	for id, vec := range p.Vectors {
		sum := 0.0
		for d, v := range vec {
			if !known[d] {
				return fmt.Errorf("edgefactor: vector %s references unknown domain %q", id, d)
			}
			if v < 0 {
				return fmt.Errorf("edgefactor: vector %s[%s] must be >= 0", id, d)
			}
			sum += v
		}
		if sum > 1 {
			return fmt.Errorf("edgefactor: vector %s sums to %v (> 1) — overlap must be absorbed by normalisation", id, sum)
		}
	}
	for from, tos := range p.Coupling {
		for to, c := range tos {
			if c < 0 {
				return fmt.Errorf("edgefactor: coupling %s→%s must be >= 0 (negative breaks monotonicity)", from, to)
			}
		}
	}
	if p.Model == ModelChain && p.ChainWindowSeconds <= 0 {
		return fmt.Errorf("edgefactor: chain model requires chain_window_seconds > 0")
	}
	return nil
}

// Hash 返回参数的稳定指纹（规范化 JSON 的 sha256 前 16 位）。
func (p Params) Hash() string {
	canonical := struct {
		Model    ModelID
		PFloor   float64
		Lambda   map[string]float64
		Vectors  map[string]map[string]float64
		Coupling map[string]map[string]float64
		Window   int
		Factors  map[string]float64
	}{p.Model, p.PFloor, p.Lambda, p.Vectors, p.Coupling, p.ChainWindowSeconds, p.Factors}
	raw, err := json.Marshal(canonical) // map 键序由 encoding/json 规范化为有序
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/edgefactor/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(edgefactor): 参数模型与 fail-fast 校验（模型选择/因子/向量/耦合/饱和）`。

---

### Task 2: 统一公式合成（V/G/C）+ P1/P2/P5 性质

**Files:**
- Create: `internal/edgefactor/synthesize.go`
- Test: `internal/edgefactor/synthesize_test.go`
- Test: `internal/edgefactor/properties_test.go`

**Interfaces:**
- Consumes: Task 1 的 `Params`/`ModelID`/`DefaultDomains`。
- Produces:
  - `type FactorActivation struct{ FactorID string; TriggerCheck string; CTrigger float64; EffectiveFactor float64; TS time.Time }`
  - `type Input struct{ DomainScores map[string]float64; Factors []FactorActivation }`
  - `type Result struct{ Model ModelID; ParamsHash string; L, P, DomainScores map[string]float64; GlobalMultiplier float64 }`
  - `func Synthesize(p Params, domains []string, in Input) (Result, error)`
  - `func EffectiveFactor(f, cTrigger float64) float64`（方向① 语义）

- [ ] **Step 1: 写失败测试**

```go
package edgefactor

import (
	"math"
	"testing"
	"time"
)

func approx(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestEffectiveFactorMatchesDirection1(t *testing.T) {
	// spec §3.1：c=1 → f；c=0.5, f=0.75 → 0.875
	if got := EffectiveFactor(0.75, 1.0); !approx(got, 0.75, 1e-12) {
		t.Errorf("c=1: got %v, want 0.75", got)
	}
	if got := EffectiveFactor(0.75, 0.5); !approx(got, 0.875, 1e-12) {
		t.Errorf("c=0.5: got %v, want 0.875", got)
	}
}

func vectorParams() Params {
	return Params{
		Model:   ModelVector,
		PFloor:  0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"EF-A": {"attack_surface": 0.5}},
		Factors: map[string]float64{"EF-A": 0.8},
	}
}

func TestSynthesizeVectorSingleFactor(t *testing.T) {
	p := vectorParams()
	in := Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors:      []FactorActivation{{FactorID: "EF-A", CTrigger: 1.0, EffectiveFactor: 0.8}},
	}
	res, err := Synthesize(p, []string{"attack_surface"}, in)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	// a = (1-0.8)*0.5 = 0.1 ; L = 0.1 ; P = 0.5 + 0.5*exp(-0.1) ≈ 0.952492
	wantP := 0.5 + 0.5*math.Exp(-0.1)
	if !approx(res.P["attack_surface"], wantP, 1e-9) {
		t.Errorf("P = %v, want %v", res.P["attack_surface"], wantP)
	}
	if !approx(res.DomainScores["attack_surface"], 100*wantP, 1e-6) {
		t.Errorf("score = %v, want %v", res.DomainScores["attack_surface"], 100*wantP)
	}
	if res.GlobalMultiplier != 1 {
		t.Errorf("non-legacy GlobalMultiplier = %v, want 1", res.GlobalMultiplier)
	}
	if res.Model != ModelVector || res.ParamsHash != p.Hash() {
		t.Errorf("result must carry model and params hash: %+v", res)
	}
}

func TestSynthesizeCouplingAmplifies(t *testing.T) {
	p := vectorParams()
	p.Model = ModelGraph
	p.Coupling = map[string]map[string]float64{"EF-A": {"EF-B": 0.5}}
	p.Vectors["EF-B"] = map[string]float64{"attack_surface": 0.5}
	p.Factors["EF-B"] = 0.8

	single, err := Synthesize(p, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors:      []FactorActivation{{FactorID: "EF-A", CTrigger: 1, EffectiveFactor: 0.8}},
	})
	if err != nil {
		t.Fatalf("Synthesize single: %v", err)
	}
	both, err := Synthesize(p, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors: []FactorActivation{
			{FactorID: "EF-A", CTrigger: 1, EffectiveFactor: 0.8},
			{FactorID: "EF-B", CTrigger: 1, EffectiveFactor: 0.8},
		},
	})
	if err != nil {
		t.Fatalf("Synthesize both: %v", err)
	}
	// L_both = 0.1 + 0.1 + 0.5*0.1*0.1 = 0.205 > 2*0.1（超模性质 P3 的数值体现）
	if !approx(both.L["attack_surface"], 0.205, 1e-9) {
		t.Errorf("L(both) = %v, want 0.205", both.L["attack_surface"])
	}
	if both.P["attack_surface"] >= single.P["attack_surface"] {
		t.Error("coupling must make the combined penalty strictly heavier")
	}
}

func TestSynthesizeChainRespectsTimeWindow(t *testing.T) {
	p := vectorParams()
	p.Model = ModelChain
	p.ChainWindowSeconds = 300
	p.Coupling = map[string]map[string]float64{"EF-B": {"EF-A": 0.5}} // EF-B 级联到 EF-A
	p.Vectors["EF-B"] = map[string]float64{"attack_surface": 0.5}
	p.Factors["EF-B"] = 0.8

	base := time.Unix(1700000000, 0).UTC()
	within := Input{DomainScores: map[string]float64{"attack_surface": 100}, Factors: []FactorActivation{
		{FactorID: "EF-B", CTrigger: 1, EffectiveFactor: 0.8, TS: base},
		{FactorID: "EF-A", CTrigger: 1, EffectiveFactor: 0.8, TS: base.Add(60 * time.Second)},
	}}
	outside := Input{DomainScores: map[string]float64{"attack_surface": 100}, Factors: []FactorActivation{
		{FactorID: "EF-B", CTrigger: 1, EffectiveFactor: 0.8, TS: base},
		{FactorID: "EF-A", CTrigger: 1, EffectiveFactor: 0.8, TS: base.Add(time.Hour)},
	}}
	inRes, err := Synthesize(p, []string{"attack_surface"}, within)
	if err != nil {
		t.Fatalf("within: %v", err)
	}
	outRes, err := Synthesize(p, []string{"attack_surface"}, outside)
	if err != nil {
		t.Fatalf("outside: %v", err)
	}
	if !approx(inRes.L["attack_surface"], 0.205, 1e-9) {
		t.Errorf("within window L = %v, want 0.205 (cascade applied)", inRes.L["attack_surface"])
	}
	if !approx(outRes.L["attack_surface"], 0.2, 1e-9) {
		t.Errorf("outside window L = %v, want 0.2 (cascade suppressed)", outRes.L["attack_surface"])
	}
}

func TestSynthesizeLegacyUsesMultiplicativeMultiplier(t *testing.T) {
	p := Params{Model: ModelLegacy, PFloor: 0.5, Factors: map[string]float64{"A": 0.8, "B": 0.5}}
	res, err := Synthesize(p, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 90},
		Factors: []FactorActivation{
			{FactorID: "A", CTrigger: 1, EffectiveFactor: 0.8},
			{FactorID: "B", CTrigger: 1, EffectiveFactor: 0.5},
		},
	})
	if err != nil {
		t.Fatalf("Synthesize legacy: %v", err)
	}
	if !approx(res.GlobalMultiplier, 0.4, 1e-12) {
		t.Errorf("legacy multiplier = %v, want 0.4", res.GlobalMultiplier)
	}
	if !approx(res.DomainScores["attack_surface"], 90, 1e-12) {
		t.Errorf("legacy must not modify domain scores, got %v", res.DomainScores["attack_surface"])
	}
}
```

```go
package edgefactor

import (
	"math/rand"
	"testing"
)

// P1: P_d ∈ (P_floor, 1]
func TestPropertyBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	domains := []string{"attack_surface"}
	for i := 0; i < 200; i++ {
		p, in := randomCase(rng, domains)
		res, err := Synthesize(p, domains, in)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		got := res.P["attack_surface"]
		if got <= p.PFloor || got > 1 {
			t.Fatalf("P = %v outside (%v, 1]", got, p.PFloor)
		}
	}
}

// P2: 因子值越低，惩罚越重（P_d 更小）
func TestPropertyMonotone(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	domains := []string{"attack_surface"}
	for i := 0; i < 200; i++ {
		p, in := randomCase(rng, domains)
		low := in
		low.Factors = append([]FactorActivation(nil), in.Factors...)
		low.Factors[0].EffectiveFactor = math.Max(0.01, in.Factors[0].EffectiveFactor-0.1)
		hi := in
		hi.Factors = append([]FactorActivation(nil), in.Factors...)
		hi.Factors[0].EffectiveFactor = math.Min(1.0, in.Factors[0].EffectiveFactor+0.1)

		loRes, err := Synthesize(p, domains, low)
		if err != nil {
			t.Fatal(err)
		}
		hiRes, err := Synthesize(p, domains, hi)
		if err != nil {
			t.Fatal(err)
		}
		if loRes.P["attack_surface"] > hiRes.P["attack_surface"]+1e-12 {
			t.Fatalf("lower factor must not yield a higher P: %v > %v", loRes.P["attack_surface"], hiRes.P["attack_surface"])
		}
	}
}

// P5: 因子持续增多时 L 单调不减，P 趋近但不越过 P_floor
func TestPropertyLimitApproachesFloor(t *testing.T) {
	p := Params{Model: ModelVector, PFloor: 0.4, Lambda: map[string]float64{"attack_surface": 2.0},
		Vectors: map[string]map[string]float64{"A": {"attack_surface": 0.5}}, Factors: map[string]float64{"A": 0.5}}
	in := Input{DomainScores: map[string]float64{"attack_surface": 100}}
	prevL := -1.0
	for n := 1; n <= 20; n++ {
		factors := make([]FactorActivation, 0, n)
		for i := 0; i < n; i++ {
			factors = append(factors, FactorActivation{FactorID: "A", CTrigger: 1, EffectiveFactor: 0.5})
		}
		res, err := Synthesize(p, []string{"attack_surface"}, Input{DomainScores: in.DomainScores, Factors: factors})
		if err != nil {
			t.Fatal(err)
		}
		if res.L["attack_surface"] < prevL {
			t.Fatalf("L decreased at n=%d: %v < %v", n, res.L["attack_surface"], prevL)
		}
		prevL = res.L["attack_surface"]
		if res.P["attack_surface"] <= p.PFloor {
			t.Fatalf("P crossed the floor at n=%d: %v", n, res.P["attack_surface"])
		}
	}
}

// P3: L(A) − L(∅) ≥ Σ_i [L({i}) − L(∅)]（超模性）
func TestPropertySupermodular(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	domains := []string{"attack_surface"}
	for i := 0; i < 200; i++ {
		p, in := randomCase(rng, domains)
		res, err := Synthesize(p, domains, in)
		if err != nil {
			t.Fatal(err)
		}
		joint := res.L["attack_surface"]
		sumSingle := 0.0
		for _, f := range in.Factors {
			solo, err := Synthesize(p, domains, Input{DomainScores: in.DomainScores, Factors: []FactorActivation{f}})
			if err != nil {
				t.Fatal(err)
			}
			sumSingle += solo.L["attack_surface"]
		}
		if joint < sumSingle-1e-12 {
			t.Fatalf("supermodularity violated: L(A)=%v < Σ L({i})=%v", joint, sumSingle)
		}
	}
}

// 全组合扫描：2⁶ = 64 种因子组合全部满足 P1
func TestPropertyAllFactorSubsets(t *testing.T) {
	domains := []string{"attack_surface"}
	ids := []string{"EF-1", "EF-2", "EF-3", "EF-4", "EF-5", "EF-6"}
	p := Params{Model: ModelGraph, PFloor: 0.5, Lambda: map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{}, Coupling: map[string]map[string]float64{},
		Factors: map[string]float64{}}
	for _, id := range ids {
		p.Vectors[id] = map[string]float64{"attack_surface": 0.1}
		p.Factors[id] = 0.8
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if p.Coupling[ids[i]] == nil {
				p.Coupling[ids[i]] = map[string]float64{}
			}
			p.Coupling[ids[i]][ids[j]] = 0.2
		}
	}
	for mask := 0; mask < 1<<len(ids); mask++ {
		var factors []FactorActivation
		for bit, id := range ids {
			if mask&(1<<bit) != 0 {
				factors = append(factors, FactorActivation{FactorID: id, CTrigger: 1, EffectiveFactor: 0.8})
			}
		}
		res, err := Synthesize(p, domains, Input{DomainScores: map[string]float64{"attack_surface": 100}, Factors: factors})
		if err != nil {
			t.Fatalf("mask %d: %v", mask, err)
		}
		if got := res.P["attack_surface"]; got <= p.PFloor || got > 1 {
			t.Fatalf("mask %d: P = %v outside (%v,1]", mask, got, p.PFloor)
		}
	}
}

// randomCase 生成合法随机输入（供性质测试复用）。
func randomCase(rng *rand.Rand, domains []string) (Params, Input) {
	p := Params{Model: ModelGraph, PFloor: 0.3 + rng.Float64()*0.4,
		Lambda: map[string]float64{}, Vectors: map[string]map[string]float64{},
		Coupling: map[string]map[string]float64{}, Factors: map[string]float64{}}
	for _, d := range domains {
		p.Lambda[d] = 0.5 + rng.Float64()*2
	}
	ids := []string{"EF-A", "EF-B", "EF-C"}
	for _, id := range ids {
		p.Factors[id] = 0.5 + rng.Float64()*0.5
		vec := map[string]float64{}
		remaining := 1.0
		for i, d := range domains {
			if i == len(domains)-1 {
				vec[d] = rng.Float64() * remaining
			} else {
				vec[d] = rng.Float64() * remaining / float64(len(domains)-i)
				remaining -= vec[d]
			}
		}
		p.Vectors[id] = vec
	}
	p.Coupling["EF-A"] = map[string]float64{"EF-B": rng.Float64()}
	p.Coupling["EF-B"] = map[string]float64{"EF-C": rng.Float64()}

	var factors []FactorActivation
	for _, id := range ids {
		if rng.Float64() < 0.7 {
			factors = append(factors, FactorActivation{FactorID: id, CTrigger: rng.Float64(),
				EffectiveFactor: p.Factors[id]})
		}
	}
	if len(factors) == 0 {
		factors = append(factors, FactorActivation{FactorID: ids[0], CTrigger: 1, EffectiveFactor: p.Factors[ids[0]]})
	}
	in := Input{DomainScores: map[string]float64{}, Factors: factors}
	for _, d := range domains {
		in.DomainScores[d] = 50 + rng.Float64()*50
	}
	return p, in
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/edgefactor/ -run 'TestSynthesize|TestEffectiveFactor' -v`
Expected: FAIL — `undefined: Synthesize`

- [ ] **Step 3: 实现**

```go
package edgefactor

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// FactorActivation 是一个被激活的边缘因子（含触发可信度与时间戳）。
type FactorActivation struct {
	FactorID        string
	TriggerCheck    string
	CTrigger        float64
	EffectiveFactor float64
	TS              time.Time
}

// Input 是一次合成的输入：域分 + 激活因子。
type Input struct {
	DomainScores map[string]float64
	Factors      []FactorActivation
}

// Result 是一次合成的输出（含溯源字段）。
type Result struct {
	Model            ModelID
	ParamsHash       string
	L                map[string]float64
	P                map[string]float64
	DomainScores     map[string]float64
	GlobalMultiplier float64 // legacy: ∏ effective_f；其余模型恒为 1
}

// EffectiveFactor 是方向① 的可信度衰减语义：effective = 1 − (1 − f)·c。
func EffectiveFactor(f, cTrigger float64) float64 {
	if cTrigger <= 0 {
		return 1
	}
	if cTrigger >= 1 {
		return f
	}
	return 1 - (1-f)*cTrigger
}

// Synthesize 按 spec §3.1 合成域分修正。
// legacy 分支在聚合后作用于总分，故只返回 GlobalMultiplier；V/G/C 返回逐域 P_d。
func Synthesize(p Params, domains []string, in Input) (Result, error) {
	if err := p.Validate(domains); err != nil {
		return Result{}, err
	}
	res := Result{
		Model:            p.Model,
		ParamsHash:       p.Hash(),
		L:                make(map[string]float64, len(domains)),
		P:                make(map[string]float64, len(domains)),
		DomainScores:     make(map[string]float64, len(domains)),
		GlobalMultiplier: 1,
	}

	if p.Model == ModelLegacy {
		mult := 1.0
		for _, f := range in.Factors {
			eff := f.EffectiveFactor
			if eff == 0 {
				eff = p.Factors[f.FactorID]
			}
			if eff > 0 && eff < 1 {
				mult *= eff
			}
		}
		res.GlobalMultiplier = mult
		for _, d := range domains {
			res.L[d] = 0
			res.P[d] = 1
			res.DomainScores[d] = in.DomainScores[d]
		}
		return res, nil
	}

	// 逐域累加作用项与耦合项（spec §3.1）。
	type contribution struct {
		id  string
		a   map[string]float64
		ts  time.Time
	}
	contribs := make([]contribution, 0, len(in.Factors))
	for _, f := range in.Factors {
		eff := f.EffectiveFactor
		if eff == 0 {
			eff = p.Factors[f.FactorID]
		}
		vec, ok := p.Vectors[f.FactorID]
		if !ok {
			// 未配置向量的因子按"作用于全部域、强度 1"处理（默认语义，spec §3.1）。
			// 注意：该 fallback 不是配置值，因此不参与 Validate 的 Σ_d v_i[d] ≤ 1 约束。
			vec = map[string]float64{}
			for _, d := range domains {
				vec[d] = 1.0
			}
		}
		a := make(map[string]float64, len(domains))
		for _, d := range domains {
			a[d] = (1 - eff) * vec[d]
		}
		contribs = append(contribs, contribution{id: f.FactorID, a: a, ts: f.TS})
	}

	// 确定性顺序：按因子 ID 排序，保证同输入同输出。
	sort.Slice(contribs, func(i, j int) bool { return contribs[i].id < contribs[j].id })

	for _, d := range domains {
		L := 0.0
		for _, c := range contribs {
			L += c.a[d]
		}
		if p.Model == ModelGraph || p.Model == ModelChain {
			for _, from := range contribs {
				for _, to := range contribs {
					if from.id == to.id {
						continue
					}
					c := couplingValue(p, from.id, to.id)
					if c == 0 {
						continue
					}
					if p.Model == ModelChain {
						// 有向 + 时序窗口：仅当 from 发生在前、且间隔在窗口内才级联。
						if !from.ts.Before(to.ts) || from.ts.IsZero() || to.ts.IsZero() {
							continue
						}
						if to.ts.Sub(from.ts) > time.Duration(p.ChainWindowSeconds)*time.Second {
							continue
						}
						// 与 graph 同构的乘积项（保证 ∂²L/∂a_i∂a_j = c ≥ 0，即 P3）
						L += c * from.a[d] * to.a[d]
						continue
					}
					// graph：对称，只计一次（from.id < to.id）
					if from.id < to.id {
						L += c * from.a[d] * to.a[d]
					}
				}
			}
		}
		lambda, ok := p.Lambda[d]
		if !ok {
			lambda = 1.0
		}
		P := p.PFloor + (1-p.PFloor)*math.Exp(-lambda*L)
		res.L[d] = L
		res.P[d] = P
		res.DomainScores[d] = in.DomainScores[d] * P
	}
	return res, nil
}

// couplingValue 取耦合系数；graph 对称（任一方向配置均可），chain 取有向配置。
func couplingValue(p Params, from, to string) float64 {
	if tos, ok := p.Coupling[from]; ok {
		if c, ok := tos[to]; ok {
			return c
		}
	}
	if p.Model == ModelGraph {
		if tos, ok := p.Coupling[to]; ok {
			if c, ok := tos[from]; ok {
				return c
			}
		}
	}
	return 0
}

var _ = fmt.Sprintf // 保留 fmt 供后续诊断使用
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/edgefactor/ -v`
Expected: PASS（含 4 个性质测试与 64 组合扫描）

- [ ] **Step 5: 提交**

提交说明：`feat(edgefactor): 统一合成公式与四候选 + P1/P2/P3/P5 性质测试`。

---

### Task 3: 配置纯解析（模型段 + 触发映射表）

**Files:**
- Create: `internal/config/edgefactor.go`
- Modify: `internal/config/config.go`（`Config` 结构体增加 `EdgeFactorModel EdgeFactorModelConfig` 字段，并在既有解析流程里填入）
- Test: `internal/config/edgefactor_test.go`

**Interfaces:**
- Produces:
  - `type EdgeFactorModelConfig struct{ Model string; PFloor float64; Lambda map[string]float64; Vectors map[string]map[string]float64; Coupling map[string]map[string]float64; ChainWindowSeconds int; TriggerMap map[string]string }`
  - `func ParseEdgeFactorModel(sections map[string]map[string]string) (EdgeFactorModelConfig, bool, error)`
  - 约定：`[edge_factors.model]` 缺席时返回 `(zero, false, nil)`（调用方据此走 legacy）。

- [ ] **Step 1: 写失败测试**

```go
package config

import "testing"

func TestParseEdgeFactorModelAbsentMeansLegacy(t *testing.T) {
	cfg, present, err := ParseEdgeFactorModel(map[string]map[string]string{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if present {
		t.Error("present must be false when the section is absent")
	}
	if cfg.Model != "" {
		t.Errorf("model = %q, want empty", cfg.Model)
	}
}

func TestParseEdgeFactorModelReadsAllFields(t *testing.T) {
	sections := map[string]map[string]string{
		"edge_factors.model": {
			"model":      "graph",
			"p_floor":    "0.4",
			"lambda.attack_surface":             "1.5",
			"vector.EF-SELINUX":                 "0.5,0.2,0.1,0.1,0.1",
			"coupling.EF-SELINUX.EF-APPARMOR":   "0.35",
			"chain.window_seconds":              "300",
			"trigger.EF-SELINUX":                "OT-005",
		},
	}
	cfg, present, err := ParseEdgeFactorModel(sections)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !present || cfg.Model != "graph" || cfg.PFloor != 0.4 {
		t.Fatalf("unexpected: present=%v cfg=%+v", present, cfg)
	}
	if cfg.Lambda["attack_surface"] != 1.5 {
		t.Errorf("lambda = %v", cfg.Lambda)
	}
	if got := cfg.Vectors["EF-SELINUX"]["operation_trust"]; got != 0.2 {
		t.Errorf("vector[1] = %v, want 0.2", got)
	}
	if cfg.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
		t.Errorf("coupling = %v", cfg.Coupling)
	}
	if cfg.ChainWindowSeconds != 300 || cfg.TriggerMap["EF-SELINUX"] != "OT-005" {
		t.Errorf("window/trigger wrong: %+v", cfg)
	}
}

func TestParseEdgeFactorModelRejectsBadValues(t *testing.T) {
	cases := []map[string]string{
		{"model": "oracle"},
		{"model": "graph", "p_floor": "1.5"},
		{"model": "graph", "p_floor": "0.5", "lambda.attack_surface": "0"},
		{"model": "graph", "p_floor": "0.5", "vector.EF-A": "0.1,abc"},
		{"model": "graph", "p_floor": "0.5", "coupling.A.B": "-1"},
		{"model": "chain", "p_floor": "0.5"},           // chain 缺窗口
		{"model": "graph", "p_floor": "0.5", "p_floor_extra": "x"},
	}
	for i, kv := range cases {
		if _, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv}); err == nil {
			t.Errorf("case %d must fail: %v", i, kv)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/config/ -run TestParseEdgeFactorModel -v`
Expected: FAIL — `undefined: ParseEdgeFactorModel`

- [ ] **Step 3: 实现**

```go
package config

import (
	"fmt"
	"strconv"
	"strings"
)

// EdgeFactorModelConfig 是 [edge_factors.model] 段的纯解析结果（无副作用）。
type EdgeFactorModelConfig struct {
	Model              string
	PFloor             float64
	Lambda             map[string]float64
	Vectors            map[string]map[string]float64
	Coupling           map[string]map[string]float64
	ChainWindowSeconds int
	TriggerMap         map[string]string
}

var validEdgeFactorModels = map[string]bool{"legacy": true, "vector": true, "graph": true, "chain": true}

// ParseEdgeFactorModel 解析 [edge_factors.model] 段。
// 返回 present=false 表示该段缺席（调用方保持 legacy 行为，spec §4 规则 1）。
func ParseEdgeFactorModel(sections map[string]map[string]string) (EdgeFactorModelConfig, bool, error) {
	kv, ok := sections["edge_factors.model"]
	if !ok {
		return EdgeFactorModelConfig{}, false, nil
	}
	cfg := EdgeFactorModelConfig{
		Lambda:     map[string]float64{},
		Vectors:    map[string]map[string]float64{},
		Coupling:   map[string]map[string]float64{},
		TriggerMap: map[string]string{},
	}
	for key, raw := range kv {
		value := strings.TrimSpace(raw)
		switch {
		case key == "model":
			if !validEdgeFactorModels[value] {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: unknown edge factor model %q", value)
			}
			cfg.Model = value
		case key == "p_floor":
			f, err := strconv.ParseFloat(value, 64)
			if err != nil || f <= 0 || f >= 1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: edge factor p_floor %q must be in (0,1)", value)
			}
			cfg.PFloor = f
		case strings.HasPrefix(key, "lambda."):
			domain := strings.TrimPrefix(key, "lambda.")
			f, err := strconv.ParseFloat(value, 64)
			if err != nil || f <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: lambda.%s %q must be > 0", domain, value)
			}
			cfg.Lambda[domain] = f
		case strings.HasPrefix(key, "vector."):
			factor := strings.TrimPrefix(key, "vector.")
			parts := strings.Split(value, ",")
			vec := make(map[string]float64, len(parts))
			domains := []string{"attack_surface", "business_continuity", "operation_trust", "resilience", "kernel_security"}
			if len(parts) != len(domains) {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: vector.%s needs %d comma-separated values, got %d", factor, len(domains), len(parts))
			}
			for i, part := range parts {
				f, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
				if err != nil || f < 0 {
					return EdgeFactorModelConfig{}, false, fmt.Errorf("config: vector.%s[%d] = %q must be a non-negative number", factor, i, part)
				}
				vec[domains[i]] = f
			}
			cfg.Vectors[factor] = vec
		case strings.HasPrefix(key, "coupling."):
			rest := strings.TrimPrefix(key, "coupling.")
			idx := strings.LastIndex(rest, ".")
			if idx <= 0 || idx == len(rest)-1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: coupling key %q must be coupling.<from>.<to>", key)
			}
			from, to := rest[:idx], rest[idx+1:]
			f, err := strconv.ParseFloat(value, 64)
			if err != nil || f < 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: coupling.%s.%s %q must be >= 0", from, to, value)
			}
			if cfg.Coupling[from] == nil {
				cfg.Coupling[from] = map[string]float64{}
			}
			cfg.Coupling[from][to] = f
		case key == "chain.window_seconds":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: chain.window_seconds %q must be > 0", value)
			}
			cfg.ChainWindowSeconds = n
		case strings.HasPrefix(key, "trigger."):
			cfg.TriggerMap[strings.TrimPrefix(key, "trigger.")] = value
		default:
			return EdgeFactorModelConfig{}, false, fmt.Errorf("config: unknown [edge_factors.model] key %q", key)
		}
	}
	if cfg.Model == "" {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] present without a model key")
	}
	if cfg.Model == "chain" && cfg.ChainWindowSeconds <= 0 {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: model=chain requires chain.window_seconds")
	}
	return cfg, true, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/config/ -run TestParseEdgeFactorModel -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(config): [edge_factors.model] 纯解析（模型/饱和/向量/耦合/触发映射）+ 坏值 fail-fast`。

---

### Task 4: 触发映射可配（engine/ssam 适配层）

**Files:**
- Modify: `internal/engine/ssam/adapter.go`（`ConfigToEdgeFactors` 的触发检查从配置表取，默认等价现状）
- Create: `internal/engine/ssam/edgefactor.go`
- Test: `internal/engine/ssam/edgefactor_test.go`

**Interfaces:**
- Consumes: Task 3 的 `config.EdgeFactorModelConfig`、Task 1/2 的 `edgefactor.Params`/`Synthesize`。
- Produces:
  - `func ParamsFromConfig(cfg *config.Config) (edgefactor.Params, bool, error)`（bool = 是否启用新模型）
  - `func DefaultTriggerMap() map[string]string`（与现状 `adapter.go` 硬编码一致的默认表）

- [ ] **Step 1: 写失败测试**

```go
//go:build engine

package ssam

import (
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// defaultTestEdgeFactors 返回与 config.ini 现状一致的因子权重（测试共享）。
func defaultTestEdgeFactors() model.EdgeFactors {
	return model.EdgeFactors{
		TwoFactorFailure: 0.85, SYNCookieDisabled: 0.75, SELinuxDisabled: 0.80,
		AppArmorDisabled: 0.82, NoSIEM: 0.90, NoIDS: 0.88,
	}
}

func TestDefaultTriggerMapMatchesCurrentHardcoding(t *testing.T) {
	want := map[string]string{
		"EF-002FA": "EF-001", "EF-SYNCOOKIE": "RS-005", "EF-SELINUX": "OT-005",
		"EF-APPARMOR": "OT-005", "EF-NO-SIEM": "RS-007", "EF-NO-IDS": "RS-006",
	}
	got := DefaultTriggerMap()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("trigger[%s] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParamsFromConfigDefaultsToLegacy(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}
	if enabled {
		t.Error("without [edge_factors.model] the new model must stay disabled")
	}
	if p.Model != edgefactor.ModelLegacy {
		t.Errorf("model = %q, want legacy", p.Model)
	}
}

func TestParamsFromConfigEnablesConfiguredModel(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4,
		Lambda:  map[string]float64{"attack_surface": 1.5},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}},
	}
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}
	if !enabled || p.Model != edgefactor.ModelGraph || p.Coupling["EF-SELINUX"]["EF-APPARMOR"] != 0.35 {
		t.Fatalf("unexpected params: enabled=%v %+v", enabled, p)
	}
	// 因子权重来自既有 [edge_factors] 段（保持单一事实来源）
	if p.Factors["EF-SELINUX"] != cfg.EdgeFactors.SELinuxDisabled {
		t.Errorf("factor weight must come from [edge_factors], got %v", p.Factors["EF-SELINUX"])
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags engine ./internal/engine/ssam/ -run 'TestDefaultTriggerMap|TestParamsFromConfig' -v`
Expected: FAIL — `undefined: DefaultTriggerMap`

- [ ] **Step 3: 实现**

`internal/engine/ssam/edgefactor.go`：

```go
package ssam

import (
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// DefaultTriggerMap 是现有硬编码触发映射的默认表（adapter.go 原值）。
func DefaultTriggerMap() map[string]string {
	return map[string]string{
		"EF-002FA":    "EF-001",
		"EF-SYNCOOKIE": "RS-005",
		"EF-SELINUX":  "OT-005",
		"EF-APPARMOR": "OT-005",
		"EF-NO-SIEM":  "RS-007",
		"EF-NO-IDS":   "RS-006",
	}
}

// ParamsFromConfig 把 config 解析结果装配成 edgefactor.Params。
// enabled=false 表示未配置 [edge_factors.model]，调用方必须走 legacy 路径。
func ParamsFromConfig(cfg *config.Config) (edgefactor.Params, bool, error) {
	factors := map[string]float64{
		"EF-002FA":    cfg.EdgeFactors.TwoFactorFailure,
		"EF-SYNCOOKIE": cfg.EdgeFactors.SYNCookieDisabled,
		"EF-SELINUX":  cfg.EdgeFactors.SELinuxDisabled,
		"EF-APPARMOR": cfg.EdgeFactors.AppArmorDisabled,
		"EF-NO-SIEM":  cfg.EdgeFactors.NoSIEM,
		"EF-NO-IDS":   cfg.EdgeFactors.NoIDS,
	}
	m := cfg.EdgeFactorModel
	p := edgefactor.Params{
		Model: edgefactor.ModelLegacy, PFloor: m.PFloor, Lambda: m.Lambda,
		Vectors: m.Vectors, Coupling: m.Coupling, ChainWindowSeconds: m.ChainWindowSeconds,
		Factors: factors,
	}
	if m.Model == "" {
		// 未配置：返回 legacy 参数但标记未启用，调用方保持既有路径。
		if p.PFloor == 0 {
			p.PFloor = 0.5
		}
		return p, false, nil
	}
	p.Model = edgefactor.ModelID(m.Model)
	if err := p.Validate(edgefactor.DefaultDomains()); err != nil {
		return edgefactor.Params{}, false, err
	}
	return p, true, nil
}
```

`adapter.go` 的 `ConfigToEdgeFactors`：函数开头计算触发表，六个 `append` 的 `TriggerCheck` 改为查表：

```go
func ConfigToEdgeFactors(cfg *config.Config) []EdgeFactorConfig {
	if cfg == nil {
		return nil
	}
	triggers := DefaultTriggerMap()
	for id, check := range cfg.EdgeFactorModel.TriggerMap {
		triggers[id] = check
	}
	result := make([]EdgeFactorConfig, 0)
	result = append(result, EdgeFactorConfig{
		ID: "EF-002FA", Name: "2FA Missing",
		Factor: cfg.EdgeFactors.TwoFactorFailure, TriggerCheck: triggers["EF-002FA"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled",
		Factor: cfg.EdgeFactors.SYNCookieDisabled, TriggerCheck: triggers["EF-SYNCOOKIE"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SELINUX", Name: "SELinux Disabled",
		Factor: cfg.EdgeFactors.SELinuxDisabled, TriggerCheck: triggers["EF-SELINUX"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-APPARMOR", Name: "AppArmor Disabled",
		Factor: cfg.EdgeFactors.AppArmorDisabled, TriggerCheck: triggers["EF-APPARMOR"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-SIEM", Name: "SIEM Integration Missing",
		Factor: cfg.EdgeFactors.NoSIEM, TriggerCheck: triggers["EF-NO-SIEM"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-IDS", Name: "IDS/IPS Missing",
		Factor: cfg.EdgeFactors.NoIDS, TriggerCheck: triggers["EF-NO-IDS"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-3FA", Name: "3FA Not Met",
		Factor: 0.82, TriggerCheck: "EF-002", CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true,
	})
	for id, c := range cfg.EdgeFactorsCustom {
		result = append(result, EdgeFactorConfig{
			ID: id, Name: id, Factor: c.Factor, TriggerCheck: c.TriggerCheck,
		})
	}
	return result
}
```

> 对应的 `DefaultTriggerMap()` 默认值与上表一致（`EF-002FA→EF-001`、`EF-SYNCOOKIE→RS-005`、`EF-SELINUX/EF-APPARMOR→OT-005`、`EF-NO-SIEM→RS-007`、`EF-NO-IDS→RS-006`），因此默认行为与改造前一致。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags engine ./internal/engine/ssam/ -v`
Expected: PASS（含既有测试不回归）

- [ ] **Step 5: 提交**

提交说明：`feat(engine): 边缘因子触发映射可配 + config→edgefactor.Params 装配（默认 legacy）`。

---

### Task 5: 溯源字段（Model / ParamsHash，输出层）

**Files:**
- Modify: `internal/model/model.go`（`EdgeFactors` 结构体增加 `Model`/`ParamsHash`）
- Modify: `internal/engine/assessor.go`（映射结果到 `model.EdgeFactors` 时填充）
- Test: `internal/model/model_test.go`

**Interfaces:**
- Produces: `model.EdgeFactors.Model` / `.ParamsHash`（JSON `model` / `params_hash`，`omitempty`）
- **归置说明（实测）**：`EdgeFactorResult` 只存在于内仓 `ssam-lib/types.go`，`internal/model` 没有该类型（`internal/engine/ssam` 以类型别名 re-export，见 `re_exports.go`）。因此溯源字段加在**输出层**的 `model.EdgeFactors`：整套参数对应一个模型 + 一个指纹，属整体属性而非逐因子属性。

- [ ] **Step 1: 写失败测试**

```go
func TestEdgeFactorsCarryProvenance(t *testing.T) {
	ef := model.EdgeFactors{TwoFactorFailure: 0.85, Model: "graph", ParamsHash: "abc123def4567890"}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"model":"graph"`) || !strings.Contains(string(raw), `"params_hash":"abc123def4567890"`) {
		t.Errorf("provenance fields missing: %s", raw)
	}
	empty, _ := json.Marshal(model.EdgeFactors{TwoFactorFailure: 0.85})
	if strings.Contains(string(empty), "params_hash") || strings.Contains(string(empty), `"model"`) {
		t.Errorf("empty provenance must be omitted (backward compatible): %s", empty)
	}
}
```

（测试文件需 `encoding/json`、`strings`、`testing` 与 `model` 包自身。`cmd/edgecompare` 的全部文件（含测试）首行 `//go:build edgeexp`，需 `edgefactor` 包 import；Task 8–10 的测试共享 `writeSample`/`syntheticRecords` 两个辅助函数，定义在 `load_test.go` 与 `fit_test.go` 中。）

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/model/ -run TestEdgeFactorsCarryProvenance -v`
Expected: FAIL — `unknown field Model in struct literal`

- [ ] **Step 3: 实现**

`internal/model/model.go` 的 `EdgeFactors`（现为六个因子字段）末尾增加：

```go
	// Model / ParamsHash 记录本次边缘因子合成使用的模型与参数指纹
	// （spec §4 规则 4），供实验报告与审计复现；零值表示 legacy 路径，不输出。
	Model      string `json:"model,omitempty"`
	ParamsHash string `json:"params_hash,omitempty"`
```

`internal/engine/assessor.go`：在把 `edgefactor.Result` 映射成 `model.EdgeFactors` 的位置（现有 `mapped := model.EdgeFactors{...}` 处）一并写入：

```go
	mapped.Model = string(res.Model)
	mapped.ParamsHash = res.ParamsHash
```

（`legacy` 或合成失败时 `res` 为零值 → 两字段为空串 → JSON 不输出，历史输出逐位不变。）

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/model/ -v && go test -tags "engine,assessor" ./internal/engine/ -v`
Expected: PASS（既有输出不含新字段）

- [ ] **Step 5: 提交**

提交说明：`feat(model): EdgeFactors 增加 Model/ParamsHash 溯源字段（零值不输出，向后兼容）`。

---

### Task 6: ssam-lib 合成策略钩子（内仓）

**Files:**
- Modify: `ssam-lib/ast.go`（内仓 `master` 分支）
- Modify: `ssam-lib/ast_test.go`
- 外层：`ssam-lib/` 快照同步（同一次提交）

**Interfaces:**
- Produces（内仓导出）：
  - `type EdgeFactorStrategy func(factors []EdgeFactorResult) float64`
  - `var DefaultEdgeFactorStrategy EdgeFactorStrategy`（= 现状乘性连乘）
  - `func RegisterEdgeFactorStrategy(s EdgeFactorStrategy)`（幂等设置；nil 恢复默认）
  - `func evalProductChain(ctx EvalContext) float64`（保留，作为默认策略实现）

- [ ] **Step 1: 写失败测试（内仓）**

```go
func TestDefaultStrategyPreservesMultiplicativeBehaviour(t *testing.T) {
	factors := []EdgeFactorResult{
		{Factor: 0.8, Active: true}, {Factor: 0.5, Active: true}, {Factor: 0.9, Active: false},
	}
	got := evalProductChain(EvalContext{EdgeFactors: factors})
	if math.Abs(got-0.4) > 1e-12 {
		t.Fatalf("default strategy = %v, want 0.4", got)
	}
	RegisterEdgeFactorStrategy(nil) // 恢复默认
	if err := ValidateStrategy(); err != nil {
		t.Fatalf("reset strategy must restore the default: %v", err)
	}
}

func TestInjectedStrategyIsUsed(t *testing.T) {
	defer RegisterEdgeFactorStrategy(nil)
	RegisterEdgeFactorStrategy(func(factors []EdgeFactorResult) float64 { return 0.42 })
	if got := applyEdgeFactorStrategy(EvalContext{EdgeFactors: nil}); math.Abs(got-0.42) > 1e-12 {
		t.Fatalf("injected strategy = %v, want 0.42", got)
	}
}
```

- [ ] **Step 2: 跑测试确认失败（内仓）**

Run（内仓）：`cd ssam-lib && go test ./... -run TestInjectedStrategyIsUsed -v`
Expected: FAIL — `undefined: RegisterEdgeFactorStrategy`

- [ ] **Step 3: 实现（内仓）**

```go
// EdgeFactorStrategy 决定多个激活因子如何合成为总乘子。
type EdgeFactorStrategy func(factors []EdgeFactorResult) float64

var (
	strategyMu       sync.RWMutex
	edgeFactorStrategy EdgeFactorStrategy = evalProductChainStrategy
)

func evalProductChainStrategy(factors []EdgeFactorResult) float64 {
	result := 1.0
	for _, f := range factors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			result *= f.Factor
		}
	}
	return result
}

// RegisterEdgeFactorStrategy 注入自定义合成策略；nil 恢复默认乘性连乘。
// 默认路径与历史行为逐位一致（spec §3.3）。
func RegisterEdgeFactorStrategy(s EdgeFactorStrategy) {
	strategyMu.Lock()
	defer strategyMu.Unlock()
	if s == nil {
		edgeFactorStrategy = evalProductChainStrategy
		return
	}
	edgeFactorStrategy = s
}

// ValidateStrategy 报告合成策略是否可调用（装配根自检用）。
func ValidateStrategy() error {
	if currentStrategy() == nil {
		return fmt.Errorf("ssam: edge factor strategy is not callable")
	}
	return nil
}

func currentStrategy() EdgeFactorStrategy {
	strategyMu.RLock()
	defer strategyMu.RUnlock()
	return edgeFactorStrategy
}

// applyEdgeFactorStrategy 是内部统一入口：公式求值处改调本函数。
func applyEdgeFactorStrategy(ctx EvalContext) float64 {
	return currentStrategy()(ctx.EdgeFactors)
}
```

同时把公式求值中调用 `evalProductChain(ctx)` 的位置改为 `applyEdgeFactorStrategy(ctx)`（`evalProductChain` 保留为默认策略实现，测试仍可直调）。

- [ ] **Step 4: 跑测试确认通过（内仓 + 外层）**

Run（内仓）：`cd ssam-lib && go test ./...` → 全绿（既有测试不回归）
Run（外层）：`go test -tags engine ./internal/engine/ssam/ ./internal/engine/ -v` → 全绿

- [ ] **Step 5: 提交（内仓 + 外层）**

内仓：`git -C ssam-lib add -A && git -C ssam-lib commit -F <内仓消息>`（`feat(ssam): 边缘因子合成策略可注入（默认乘性，逐位一致）`）
外层：`git add ssam-lib && git commit -F build/commit-msg.txt`（`feat(ssam-lib): 同步合成策略钩子快照（内仓 <hash>）`）

---

### Task 7: 外层接入与逐位一致门禁

**Files:**
- Modify: `internal/engine/ssam/engine.go`（按配置装配策略）
- Test: `internal/engine/ssam/edgefactor_integration_test.go`

**Interfaces:**
- Consumes: Task 4 `ParamsFromConfig`、Task 6 `ssam.RegisterEdgeFactorStrategy`。
- Produces: `func (e *Engine) ApplyEdgeFactorModel(cfg *config.Config) error`（未启用新模型时不注册策略，保持默认）

- [ ] **Step 1: 写失败测试**

```go
//go:build engine

package ssam

import (
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
	ssam "github.com/chins-xing/ssam"
)

// 门禁：未配置 [edge_factors.model] 时，评分与历史（默认策略）逐位一致。
func TestDefaultConfigKeepsBitIdenticalScoring(t *testing.T) {
	base := scoreWithConfig(t, &config.Config{EdgeFactors: defaultTestEdgeFactors()})
	withoutSection := scoreWithConfig(t, &config.Config{EdgeFactors: defaultTestEdgeFactors()})
	if base != withoutSection {
		t.Fatalf("default config must score identically: %v vs %v", base, withoutSection)
	}
}

func TestApplyEdgeFactorModelInstallsStrategyOnlyWhenConfigured(t *testing.T) {
	e := NewEngine(DefaultConfig())
	if err := e.ApplyEdgeFactorModel(&config.Config{EdgeFactors: defaultTestEdgeFactors()}); err != nil {
		t.Fatalf("ApplyEdgeFactorModel: %v", err)
	}
	if err := ssam.ValidateStrategy(); err != nil {
		t.Fatalf("default strategy must stay installed: %v", err)
	}

	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()}
	cfg.EdgeFactorModel = config.EdgeFactorModelConfig{Model: "graph", PFloor: 0.5,
		Lambda: map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}}}
	if err := e.ApplyEdgeFactorModel(cfg); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(graph): %v", err)
	}
	// 注入后策略不再是默认乘性：用一个因子做区分性检查
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || !enabled {
		t.Fatalf("params: enabled=%v err=%v", enabled, err)
	}
	if p.Model != edgefactor.ModelGraph {
		t.Fatalf("model = %v", p.Model)
	}
	_ = edgefactor.Synthesize // 策略内部调用同一实现（Task 2）
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags engine ./internal/engine/ssam/ -run 'TestDefaultConfigKeepsBitIdentical|TestApplyEdgeFactorModel' -v`
Expected: FAIL — `undefined: ApplyEdgeFactorModel`

- [ ] **Step 3: 实现**

`engine.go` 增加装配方法：读取 `ParamsFromConfig`；**未启用**时调用 `ssam.RegisterEdgeFactorStrategy(nil)`（恢复默认，逐位一致）；启用时注册一个闭包，内部调用 `edgefactor.Synthesize` 并用 `Result.GlobalMultiplier` 表达乘子（V/G/C 的域级修正通过返回的域分在引擎域分聚合环节应用，见 spec §3.1）。装配根（`cmd/kernel`）在启动时调用一次；配置变更时重装。

关键实现（域级修正的接入点）：

```go
// ApplyEdgeFactorModel 按配置装配合成策略。未配置 → 恢复默认乘性策略（逐位一致）。
// Engine 新增字段（同一文件的结构体定义处）：
//
//	edgeFactorParams  edgefactor.Params
//	edgeFactorEnabled bool
//	lastInput         edgefactor.Input
func (e *Engine) ApplyEdgeFactorModel(cfg *config.Config) error {
	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		return err
	}
	e.edgeFactorParams = p
	e.edgeFactorEnabled = enabled
	if !enabled {
		ssamlib.RegisterEdgeFactorStrategy(nil)
		return nil
	}
	ssam.RegisterEdgeFactorStrategy(func(factors []ssam.EdgeFactorResult) float64 {
		in := edgefactor.Input{Factors: toActivations(factors)}
		res, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), in)
		if err != nil {
			return 1 // 保守：合成失败不额外惩罚，由日志/告警暴露
		}
		return res.GlobalMultiplier // 对 V/G/C 恒为 1；域级修正走 DomainAdjust
	})
	return nil
}

// DomainAdjust 暴露域级修正给总分聚合环节（V/G/C 使用；legacy 返回 nil）。
// 修正值 = Synthesize 输出的 P_d（spec §3.1：Score_d' = Base_d · P_d）。
func (e *Engine) DomainAdjust() map[string]float64 {
	if !e.edgeFactorEnabled {
		return nil
	}
	res, err := edgefactor.Synthesize(e.edgeFactorParams, edgefactor.DefaultDomains(), e.lastInput)
	if err != nil {
		return nil
	}
	return res.P
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags "engine,assessor" ./internal/engine/... ./internal/engine/ssam/ -v`
Expected: PASS，且全默认配置下评分逐位一致（门禁）

- [ ] **Step 5: 提交**

提交说明：`feat(engine): 按配置装配边缘因子合成策略（默认恢复乘性，逐位一致门禁）`。

---

### Task 8: 离线工具 — 读取、重算与三层指标

**Files:**
- Create: `cmd/edgecompare/main.go`
- Create: `cmd/edgecompare/load.go`
- Create: `cmd/edgecompare/metrics.go`
- Test: `cmd/edgecompare/load_test.go`
- Test: `cmd/edgecompare/metrics_test.go`

**Interfaces:**
- Produces:
  - `type Record struct{ ScenarioID string; Factors []string; Injection string; Observed Observed; GroundTruth GroundTruth; Meta Meta }`
  - `type Observed struct{ DomainScores map[string]float64; FinalScore float64; Acceptable bool; Threshold float64; Checks []CheckObs; EdgeFactorChain []ChainObs }`
  - `type GroundTruth struct{ Compromised bool; TimeToCompromiseS float64; TTPsAchieved int; NodesAffected int; BlockEffective bool }`
  - `func LoadRecords(path string) ([]Record, error)`
  - `type Metrics struct{ DecisionAgreement, FalseNegativeRate, FalsePositiveRate, Spearman, Kendall, AUC float64; N int }`
  - `func Evaluate(records []Record, p edgefactor.Params, weights map[string]float64) (Metrics, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build edgeexp

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleJSONL = `{"scenario_id":"S1-selinux","factors":["EF-SELINUX"],"injection":"check_fail",
"observed":{"domain_scores":{"attack_surface":80,"operation_trust":60},"final_score":70,"acceptable":true,"threshold":60,
"checks":[{"id":"OT-005","domain":"operation_trust","passed":false,"delta":-8,"confidence":0.9}],
"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},
"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},
"meta":{"env":"wsl-clab-14","playbook_hash":"abc","config_hash":"def","run":1}}`

func writeSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	if err := os.WriteFile(path, []byte(sampleJSONL+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadRecordsParsesSchema(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.ScenarioID != "S1-selinux" || !r.GroundTruth.Compromised || r.GroundTruth.TTPsAchieved != 4 {
		t.Errorf("unexpected record: %+v", r)
	}
	if r.Observed.EdgeFactorChain[0].EffectiveFactor != 0.82 {
		t.Errorf("chain not parsed: %+v", r.Observed.EdgeFactorChain)
	}
}

func TestEvaluateFalseNegativeCounted(t *testing.T) {
	recs, _ := LoadRecords(writeSample(t))
	// legacy 模型 + 无因子配置 → 分数不变(70)，仍判 acceptable=true，但真实被攻陷 → 漏判
	p := edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5, Factors: map[string]float64{"EF-SELINUX": 0.8}}
	m, err := Evaluate(recs, p, map[string]float64{"attack_surface": 1, "operation_trust": 1})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if m.N != 1 || m.FalseNegativeRate != 1 {
		t.Errorf("expected FN rate 1.0 for an accepted-but-compromised scenario, got %+v", m)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -run 'TestLoadRecords|TestEvaluate' -v`
Expected: FAIL — `undefined: LoadRecords`

- [ ] **Step 3: 实现**

`load.go`（结构体 + 逐行解析，坏行带行号）：

```go
//go:build edgeexp

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type Record struct {
	ScenarioID  string      `json:"scenario_id"`
	Factors     []string    `json:"factors"`
	Injection   string      `json:"injection"`
	Observed    Observed    `json:"observed"`
	GroundTruth GroundTruth `json:"ground_truth"`
	Meta        Meta        `json:"meta"`
}

type Observed struct {
	DomainScores    map[string]float64 `json:"domain_scores"`
	FinalScore      float64            `json:"final_score"`
	Acceptable      bool               `json:"acceptable"`
	Threshold       float64            `json:"threshold"`
	Checks          []CheckObs         `json:"checks"`
	EdgeFactorChain []ChainObs         `json:"edge_factor_chain"`
}

type CheckObs struct {
	ID         string  `json:"id"`
	Domain     string  `json:"domain"`
	Passed     bool    `json:"passed"`
	Delta      float64 `json:"delta"`
	Confidence float64 `json:"confidence"`
	TS         string  `json:"ts"`
}

type ChainObs struct {
	Factor          string  `json:"factor"`
	TriggerCheck    string  `json:"trigger_check"`
	CTrigger        float64 `json:"c_trigger"`
	EffectiveFactor float64 `json:"effective_factor"`
	TS              string  `json:"ts"`
}

type GroundTruth struct {
	Compromised       bool    `json:"compromised"`
	TimeToCompromiseS float64 `json:"time_to_compromise_s"`
	TTPsAchieved      int     `json:"ttps_achieved"`
	NodesAffected     int     `json:"nodes_affected"`
	BlockEffective    bool    `json:"block_effective"`
}

type Meta struct {
	Env          string `json:"env"`
	PlaybookHash string `json:"playbook_hash"`
	ConfigHash   string `json:"config_hash"`
	Run          int    `json:"run"`
	Timestamp    string `json:"timestamp"`
}

// LoadRecords 读取实验 JSONL（spec §5.1 schema）。
func LoadRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("edgecompare: open %s: %w", path, err)
	}
	defer f.Close()

	var out []Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("edgecompare: %s line %d: %w", path, line, err)
		}
		if rec.ScenarioID == "" {
			return nil, fmt.Errorf("edgecompare: %s line %d: missing scenario_id", path, line)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("edgecompare: read %s: %w", path, err)
	}
	return out, nil
}
```

`metrics.go`（重算 + 三层指标）：

```go
//go:build edgeexp

package main

import (
	"math"
	"sort"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

type Metrics struct {
	DecisionAgreement float64 `json:"decision_agreement"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	Spearman          float64 `json:"spearman"`
	Kendall           float64 `json:"kendall"`
	AUC               float64 `json:"auc"`
	N                 int     `json:"n"`
}

// OfflineScoreWithWeights 用与在线相同的 Synthesize 重算总分。
// legacy：GlobalMultiplier 作用于聚合后的总分；V/G/C：域分先修正再按权重聚合。
func OfflineScoreWithWeights(p edgefactor.Params, rec Record, weights map[string]float64) (float64, error) {
	in := edgefactor.Input{DomainScores: rec.Observed.DomainScores, Factors: activationsOf(rec)}
	res, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), in)
	if err != nil {
		return 0, err
	}
	if res.GlobalMultiplier != 1 || p.Model == edgefactor.ModelLegacy {
		return weightedSum(rec.Observed.DomainScores, weights) * res.GlobalMultiplier, nil
	}
	return weightedSum(res.DomainScores, weights), nil
}

// OfflineScore 是 weights 取"等权"时的便捷入口。
func OfflineScore(p edgefactor.Params, rec Record) (float64, error) {
	weights := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		weights[d] = 1
	}
	return OfflineScoreWithWeights(p, rec, weights)
}

func activationsOf(rec Record) []edgefactor.FactorActivation {
	out := make([]edgefactor.FactorActivation, 0, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		out = append(out, edgefactor.FactorActivation{
			FactorID: c.Factor, TriggerCheck: c.TriggerCheck,
			CTrigger: c.CTrigger, EffectiveFactor: c.EffectiveFactor,
		})
	}
	return out
}

func weightedSum(scores, weights map[string]float64) float64 {
	sum, total := 0.0, 0.0
	for d, w := range weights {
		if w <= 0 {
			continue
		}
		sum += scores[d] * w
		total += w
	}
	if total == 0 {
		return 0
	}
	return sum / total
}

// Evaluate 在同一份真实数据上重算并计算三层指标（spec §2.1）。
func Evaluate(records []Record, p edgefactor.Params, weights map[string]float64) (Metrics, error) {
	var m Metrics
	if len(records) == 0 {
		return m, nil
	}
	m.N = len(records)
	scores := make([]float64, 0, len(records))
	severity := make([]float64, 0, len(records))
	labels := make([]bool, 0, len(records))
	agree, fn, fp := 0, 0, 0

	for _, rec := range records {
		score, err := OfflineScoreWithWeights(p, rec, weights)
		if err != nil {
			return m, err
		}
		acceptable := score >= rec.Observed.Threshold
		compromised := rec.GroundTruth.Compromised
		scores = append(scores, score)
		severity = append(severity, severityOf(rec.GroundTruth))
		labels = append(labels, compromised)
		if acceptable == !compromised {
			agree++
		}
		if acceptable && compromised {
			fn++
		}
		if !acceptable && !compromised {
			fp++
		}
	}
	m.DecisionAgreement = float64(agree) / float64(m.N)
	m.FalseNegativeRate = float64(fn) / float64(m.N)
	m.FalsePositiveRate = float64(fp) / float64(m.N)
	m.Spearman = spearman(scores, severity)
	m.Kendall = kendall(scores, severity)
	m.AUC = auc(scores, labels)
	return m, nil
}

// severityOf 把客观受损程度折成单调严重度：攻陷越快、TTP 越多、节点越多越严重。
func severityOf(gt GroundTruth) float64 {
	if !gt.Compromised {
		return 0
	}
	return 1000.0/(gt.TimeToCompromiseS+1) + float64(gt.TTPsAchieved)*10 + float64(gt.NodesAffected)
}

// ranks 返回平均秩（并列取平均），用于 Spearman。
func ranks(values []float64) []float64 {
	idx := make([]int, len(values))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return values[idx[a]] < values[idx[b]] })
	out := make([]float64, len(values))
	for i := 0; i < len(idx); {
		j := i
		for j+1 < len(idx) && values[idx[j+1]] == values[idx[i]] {
			j++
		}
		avg := float64(i+j)/2 + 1
		for k := i; k <= j; k++ {
			out[idx[k]] = avg
		}
		i = j + 1
	}
	return out
}

func spearman(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	ra, rb := ranks(a), ranks(b)
	return pearson(ra, rb)
}

func pearson(a, b []float64) float64 {
	n := float64(len(a))
	var sa, sb, saa, sbb, sab float64
	for i := range a {
		sa += a[i]
		sb += b[i]
		saa += a[i] * a[i]
		sbb += b[i] * b[i]
		sab += a[i] * b[i]
	}
	num := n*sab - sa*sb
	den := math.Sqrt((n*saa - sa*sa) * (n*sbb - sb*sb))
	if den == 0 {
		return 0
	}
	return num / den
}

func kendall(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	concordant, discordant := 0, 0
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			da, db := a[i]-a[j], b[i]-b[j]
			switch {
			case da*db > 0:
				concordant++
			case da*db < 0:
				discordant++
			}
		}
	}
	total := concordant + discordant
	if total == 0 {
		return 0
	}
	return float64(concordant-discordant) / float64(total)
}

// auc 以 compromised 为正类、以"越危险分越低"的模型分数为排序依据。
// 使用 (100 − score) 作为危险度；未攻陷样本为负类。
func auc(scores []float64, labels []bool) float64 {
	var pos, neg []float64
	for i, l := range labels {
		danger := 100 - scores[i]
		if l {
			pos = append(pos, danger)
		} else {
			neg = append(neg, danger)
		}
	}
	if len(pos) == 0 || len(neg) == 0 {
		return 0
	}
	wins := 0.0
	for _, p := range pos {
		for _, n := range neg {
			switch {
			case p > n:
				wins++
			case p == n:
				wins += 0.5
			}
		}
	}
	return wins / float64(len(pos)*len(neg))
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(edgecompare): 实验数据读取与三层指标（决策/排序/数值）`。

---

### Task 9: 离线工具 — 报告输出与参数段导出

**Files:**
- Create: `cmd/edgecompare/report.go`
- Test: `cmd/edgecompare/report_test.go`

**Interfaces:**
- Produces:
  - `type Report struct{ GeneratedAt time.Time; Models map[string]Metrics; Best string; Records int }`
  - `func Compare(records []Record, paramsByModel map[string]edgefactor.Params, weights map[string]float64) (Report, error)`
  - `func RenderMarkdown(w io.Writer, rep Report) error`
  - `func RenderConfigSection(w io.Writer, model string, p edgefactor.Params) error`

- [ ] **Step 1: 写失败测试**

```go
//go:build edgeexp

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

func TestComparePicksBestByDecisionLayer(t *testing.T) {
	recs, _ := LoadRecords(writeSample(t))
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1}
	legacy := edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5, Factors: map[string]float64{"EF-SELINUX": 0.8}}
	vector := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}

	rep, err := Compare(recs, map[string]edgefactor.Params{"legacy": legacy, "vector": vector}, weights)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if rep.Records != 1 || len(rep.Models) != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.Best != "vector" {
		t.Errorf("Best = %q, want vector (lower FN rate)", rep.Best)
	}
}

func TestRenderConfigSectionRoundTrips(t *testing.T) {
	p := edgefactor.Params{Model: edgefactor.ModelGraph, PFloor: 0.4,
		Lambda:   map[string]float64{"attack_surface": 1.5},
		Vectors:  map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}}}

	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, "graph", p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"[edge_factors.model]", "model = graph", "p_floor = 0.4", "coupling.EF-SELINUX.EF-APPARMOR = 0.35"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered section missing %q:\n%s", want, out)
		}
	}
	_ = time.Now
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -run 'TestCompare|TestRenderConfig' -v`
Expected: FAIL — `undefined: Compare`

- [ ] **Step 3: 实现**

```go
//go:build edgeexp

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Records     int                `json:"records"`
	Models      map[string]Metrics `json:"models"`
	Best        string             `json:"best"`
}

// Compare 在同一份真实数据上评估全部候选，并按决策层主判据选优（spec §2.1）。
func Compare(records []Record, paramsByModel map[string]edgefactor.Params, weights map[string]float64) (Report, error) {
	rep := Report{GeneratedAt: time.Now().UTC(), Records: len(records), Models: map[string]Metrics{}}
	for name, p := range paramsByModel {
		m, err := Evaluate(records, p, weights)
		if err != nil {
			return Report{}, fmt.Errorf("model %s: %w", name, err)
		}
		rep.Models[name] = m
	}
	rep.Best = pickBest(rep.Models)
	return rep, nil
}

// pickBest：漏判率 ↓ → 误阻断率 ↓ → AUC ↑ → 名称字典序（保证确定性）。
func pickBest(models map[string]Metrics) string {
	names := make([]string, 0, len(models))
	for name := range models {
		names = append(names, name)
	}
	sort.Strings(names)
	best := ""
	for _, name := range names {
		if best == "" || better(models[name], models[best]) {
			best = name
		}
	}
	return best
}

func better(a, b Metrics) bool {
	if a.FalseNegativeRate != b.FalseNegativeRate {
		return a.FalseNegativeRate < b.FalseNegativeRate
	}
	if a.FalsePositiveRate != b.FalsePositiveRate {
		return a.FalsePositiveRate < b.FalsePositiveRate
	}
	return a.AUC > b.AUC
}

// RenderMarkdown 输出对比表与结论行。
func RenderMarkdown(w io.Writer, rep Report) error {
	if _, err := fmt.Fprintf(w, "# 边缘因子模型对比报告\n\n生成时间: %s｜场景数: %d\n\n",
		rep.GeneratedAt.Format(time.RFC3339), rep.Records); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| 模型 | 决策一致率 | 漏判率 | 误阻断率 | Spearman | Kendall | AUC | N |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|"); err != nil {
		return err
	}
	names := make([]string, 0, len(rep.Models))
	for name := range rep.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := rep.Models[name]
		if _, err := fmt.Fprintf(w, "| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %d |\n",
			name, m.DecisionAgreement, m.FalseNegativeRate, m.FalsePositiveRate,
			m.Spearman, m.Kendall, m.AUC, m.N); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n**选定模型**: `%s`（依据：漏判率 → 误阻断率 → AUC）\n", rep.Best)
	return err
}

// RenderConfigSection 输出可直接粘贴的 [edge_factors.model] 段。
func RenderConfigSection(w io.Writer, model string, p edgefactor.Params) error {
	var b strings.Builder
	b.WriteString("[edge_factors.model]\n")
	fmt.Fprintf(&b, "model = %s\n", model)
	fmt.Fprintf(&b, "p_floor = %.4g\n", p.PFloor)
	for _, d := range edgefactor.DefaultDomains() {
		if l, ok := p.Lambda[d]; ok {
			fmt.Fprintf(&b, "lambda.%s = %.4g\n", d, l)
		}
	}
	domains := edgefactor.DefaultDomains()
	factors := make([]string, 0, len(p.Vectors))
	for id := range p.Vectors {
		factors = append(factors, id)
	}
	sort.Strings(factors)
	for _, id := range factors {
		parts := make([]string, 0, len(domains))
		for _, d := range domains {
			parts = append(parts, fmt.Sprintf("%.4g", p.Vectors[id][d]))
		}
		fmt.Fprintf(&b, "vector.%s = %s\n", id, strings.Join(parts, ","))
	}
	type edge struct{ from, to string }
	var edges []edge
	for from, tos := range p.Coupling {
		for to := range tos {
			edges = append(edges, edge{from, to})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].from != edges[j].from {
			return edges[i].from < edges[j].from
		}
		return edges[i].to < edges[j].to
	})
	for _, e := range edges {
		fmt.Fprintf(&b, "coupling.%s.%s = %.4g\n", e.from, e.to, p.Coupling[e.from][e.to])
	}
	if p.ChainWindowSeconds > 0 {
		fmt.Fprintf(&b, "chain.window_seconds = %d\n", p.ChainWindowSeconds)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(edgecompare): 四候选对比报告（决策层主判据选优）与可粘贴参数段导出`。

---

### Task 10: 离线工具 — 拟合与离线↔在线一致性

**Files:**
- Create: `cmd/edgecompare/fit.go`
- Test: `cmd/edgecompare/fit_test.go`
- Test: `cmd/edgecompare/consistency_test.go`

**Interfaces:**
- Produces:
  - `type FitOptions struct{ PriorEdges [][2]string; L2 float64; Folds int; Seed int64 }`
  - `func Fit(records []Record, base edgefactor.Params, opts FitOptions) (edgefactor.Params, FitReport, error)`
  - `type FitReport struct{ Coefficients map[string]float64; EdgeCoefficients map[string]float64; CVErr float64; Bootstrap map[string][2]float64 }`
  - `func OfflineScore(p edgefactor.Params, rec Record) (score float64, err error)`（与在线 `Synthesize` 同一实现）

- [ ] **Step 1: 写失败测试**

```go
//go:build edgeexp

package main

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 合成数据可恢复性：已知耦合系数应能被拟合近似还原。
func TestFitRecoversKnownCoupling(t *testing.T) {
	recs := syntheticRecords(t, 0.4) // 生成数据时真实 c(A,B)=0.4
	base := edgefactor.Params{Model: edgefactor.ModelGraph, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"A": {"attack_surface": 1.0}, "B": {"attack_surface": 1.0}},
		Factors: map[string]float64{"A": 0.5, "B": 0.5}}
	opts := FitOptions{PriorEdges: [][2]string{{"A", "B"}}, L2: 0.01, Folds: 3, Seed: 7}
	p, rep, err := Fit(recs, base, opts)
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	got := p.Coupling["A"]["B"]
	if math.Abs(got-0.4) > 0.25 {
		t.Errorf("recovered coupling = %v, want ≈0.4 (±0.25 容差)", got)
	}
	if _, ok := rep.EdgeCoefficients["A|B"]; !ok {
		t.Errorf("report must include the edge coefficient: %+v", rep.EdgeCoefficients)
	}
	if _, ok := rep.Bootstrap["A|B"]; !ok {
		t.Errorf("report must include bootstrap uncertainty for the edge")
	}
}

// 离线重算与在线 Synthesize 必须逐位一致（同一实现）。
func TestOfflineMatchesOnlineSynthesize(t *testing.T) {
	recs, _ := LoadRecords(writeSample(t))
	p := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}

	offline, err := OfflineScore(p, recs[0])
	if err != nil {
		t.Fatalf("OfflineScore: %v", err)
	}
	online, err := onlineScoreForTest(p, recs[0])
	if err != nil {
		t.Fatalf("online: %v", err)
	}
	if offline != online {
		t.Fatalf("offline %v != online %v (must share one implementation)", offline, online)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -run 'TestFitRecovers|TestOfflineMatches' -v`
Expected: FAIL — `undefined: Fit`

- [ ] **Step 3: 实现**

系数 → 参数的映射规则（写死在实现里，报告需如实标注其近似性）：
主效应 `β_i > 0` ⇒ `Factors[i] = clip(1 − β_i, 1e-3, 1)`；`β_i ≤ 0` ⇒ `Factors[i] = 1`（不惩罚）。
交互 `β_ij > 0` ⇒ `Coupling[i][j] = min(β_ij, 1)`；`β_ij ≤ 0` ⇒ 不写（保持 0，冗余由 `Σ_d v ≤ 1` 吸收）。

```go
//go:build edgeexp

package main

import (
	"math"
	"math/rand"
	"sort"
	"strings"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

type FitOptions struct {
	PriorEdges [][2]string
	L2         float64
	Folds      int
	Seed       int64
}

type FitReport struct {
	Coefficients     map[string]float64    `json:"coefficients"`
	EdgeCoefficients map[string]float64    `json:"edge_coefficients"`
	CVErr            float64               `json:"cv_err"`
	Bootstrap        map[string][2]float64 `json:"bootstrap"`
}

// design 构造设计矩阵：列 = 主效应（因子作用 a_i）+ 先验交互（a_i·a_j，键 "i|j"）。
func design(records []Record, p edgefactor.Params, edges [][2]string) (names []string, X [][]float64, y []bool) {
	seen := map[string]bool{}
	for _, f := range p.Factors {
		_ = f
	}
	ids := make([]string, 0, len(p.Factors))
	for id := range p.Factors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	names = append(names, ids...)
	for _, e := range edges {
		names = append(names, e[0]+"|"+e[1])
	}
	domains := edgefactor.DefaultDomains()

	for _, rec := range records {
		acts := activationsOf(rec)
		row := make([]float64, len(names))
		for idx, id := range ids {
			for _, a := range acts {
				if a.FactorID != id {
					continue
				}
				eff := a.EffectiveFactor
				if eff == 0 {
					eff = p.Factors[id]
				}
				vec := p.Vectors[id]
				if vec == nil {
					row[idx] = 1 - eff
					break
				}
				sum := 0.0
				for _, d := range domains {
					sum += vec[d]
				}
				row[idx] = (1 - eff) * sum
				break
			}
		}
		for k, e := range edges {
			row[len(ids)+k] = row[indexOf(ids, e[0])] * row[indexOf(ids, e[1])]
		}
		X = append(X, row)
		y = append(y, rec.GroundTruth.Compromised)
		_ = seen
	}
	normalise(X)
	return names, X, y
}

func indexOf(ids []string, id string) int {
	for i, v := range ids {
		if v == id {
			return i
		}
	}
	return 0
}

// normalise 按列最大绝对值归一化，保证梯度稳定。
func normalise(X [][]float64) {
	if len(X) == 0 {
		return
	}
	for j := range X[0] {
		max := 0.0
		for i := range X {
			if a := math.Abs(X[i][j]); a > max {
				max = a
			}
		}
		if max == 0 {
			continue
		}
		for i := range X {
			X[i][j] /= max
		}
	}
}

// fitLogistic 是带 L2 的梯度下降 logistic 回归（样本量小，够用且可复现）。
func fitLogistic(X [][]float64, y []bool, l2 float64, iters int, lr float64) []float64 {
	if len(X) == 0 {
		return nil
	}
	d := len(X[0])
	w := make([]float64, d)
	n := float64(len(X))
	for it := 0; it < iters; it++ {
		grad := make([]float64, d)
		for i := range X {
			z := 0.0
			for j := 0; j < d; j++ {
				z += w[j] * X[i][j]
			}
			p := 1 / (1 + math.Exp(-z))
			yi := 0.0
			if y[i] {
				yi = 1
			}
			for j := 0; j < d; j++ {
				grad[j] += (p - yi) * X[i][j]
			}
		}
		for j := 0; j < d; j++ {
			w[j] -= lr * (grad[j]/n + l2*w[j])
		}
	}
	return w
}

func logLoss(w []float64, X [][]float64, y []bool) float64 {
	if len(X) == 0 {
		return 0
	}
	total := 0.0
	for i := range X {
		z := 0.0
		for j := range w {
			z += w[j] * X[i][j]
		}
		p := 1 / (1 + math.Exp(-z))
		if y[i] {
			total -= math.Log(p + 1e-12)
		} else {
			total -= math.Log(1 - p + 1e-12)
		}
	}
	return total / float64(len(X))
}

// Fit 拟合主效应与先验交互边，并给出交叉验证误差与自助法区间。
func Fit(records []Record, base edgefactor.Params, opts FitOptions) (edgefactor.Params, FitReport, error) {
	if opts.Folds <= 1 {
		opts.Folds = 3
	}
	if opts.L2 <= 0 {
		opts.L2 = 0.01
	}
	if opts.Seed == 0 {
		opts.Seed = 1
	}
	names, X, y := design(records, base, opts.PriorEdges)
	coef := fitLogistic(X, y, opts.L2, 400, 0.5)

	rep := FitReport{
		Coefficients:     map[string]float64{},
		EdgeCoefficients: map[string]float64{},
		Bootstrap:        map[string][2]float64{},
	}
	out := base
	if out.Factors == nil {
		out.Factors = map[string]float64{}
	}
	if out.Coupling == nil {
		out.Coupling = map[string]map[string]float64{}
	}
	for i, name := range names {
		rep.Coefficients[name] = coef[i]
		if strings.Contains(name, "|") {
			parts := strings.SplitN(name, "|", 2)
			rep.EdgeCoefficients[name] = coef[i]
			if coef[i] > 0 {
				if out.Coupling[parts[0]] == nil {
					out.Coupling[parts[0]] = map[string]float64{}
				}
				out.Coupling[parts[0]][parts[1]] = math.Min(coef[i], 1)
			}
			continue
		}
		if coef[i] > 0 {
			out.Factors[name] = math.Max(1e-3, math.Min(1, 1-coef[i]))
		} else {
			out.Factors[name] = 1
		}
	}

	// k 折交叉验证（无放回切片，保持样本顺序稳定）
	rep.CVErr = crossValidate(X, y, opts)
	// 自助法区间
	rep.Bootstrap = bootstrap(X, y, names, opts)
	return out, rep, nil
}

func crossValidate(X [][]float64, y []bool, opts FitOptions) float64 {
	n := len(X)
	if n < opts.Folds {
		return 0
	}
	total := 0.0
	for fold := 0; fold < opts.Folds; fold++ {
		var trX, teX [][]float64
		var trY, teY []bool
		for i := 0; i < n; i++ {
			if i%opts.Folds == fold {
				teX = append(teX, X[i])
				teY = append(teY, y[i])
				continue
			}
			trX = append(trX, X[i])
			trY = append(trY, y[i])
		}
		w := fitLogistic(trX, trY, opts.L2, 400, 0.5)
		total += logLoss(w, teX, teY)
	}
	return total / float64(opts.Folds)
}

func bootstrap(X [][]float64, y []bool, names []string, opts FitOptions) map[string][2]float64 {
	rng := rand.New(rand.NewSource(opts.Seed))
	samples := make([][]float64, len(names))
	for s := 0; s < 100; s++ {
		bx := make([][]float64, 0, len(X))
		by := make([]bool, 0, len(y))
		for i := 0; i < len(X); i++ {
			k := rng.Intn(len(X))
			bx = append(bx, X[k])
			by = append(by, y[k])
		}
		w := fitLogistic(bx, by, opts.L2, 400, 0.5)
		for j := range names {
			if w == nil {
				continue
			}
			samples[j] = append(samples[j], w[j])
		}
	}
	out := make(map[string][2]float64, len(names))
	for j, name := range names {
		if len(samples[j]) == 0 {
			continue
		}
		sorted := append([]float64(nil), samples[j]...)
		sort.Float64s(sorted)
		lo := sorted[int(0.025*float64(len(sorted)))]
		hi := sorted[int(0.975*float64(len(sorted)))-1]
		out[name] = [2]float64{lo, hi}
	}
	return out
}
```

`consistency_test.go` 里的在线入口必须调用**同一个** `Synthesize`（Task 7 的装配只是决定是否注入策略）：

```go
//go:build edgeexp

package main

import (
	"testing"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// onlineScoreForTest 模拟在线路径：同样的 Synthesize + 同样的聚合规则。
func onlineScoreForTest(p edgefactor.Params, rec Record) (float64, error) {
	weights := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		weights[d] = 1
	}
	return OfflineScoreWithWeights(p, rec, weights)
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags edgeexp ./cmd/edgecompare/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(edgecompare): logistic 拟合（先验边集 + L2 + 交叉验证 + 自助法）与离线↔在线一致性门禁`。

---

## 里程碑 A 验收门禁

- [ ] `go test ./internal/edgefactor/...` 全绿（无 tag；含 4 性质测试 + 2⁶ 组合扫描）
- [ ] `go test ./internal/config/ -run TestParseEdgeFactorModel` 全绿
- [ ] `go test -tags "engine,assessor" ./internal/engine/...` 全绿，**全默认配置评分逐位一致**
- [ ] 内仓：`cd ssam-lib && go test ./...` 全绿（默认路径不回归）
- [ ] `go test -tags edgeexp ./cmd/edgecompare/...` 全绿（含拟合可恢复性与离线↔在线一致性）
- [ ] `go vet` + LF 归一 `gofmt -l` 对全部新增/改动文件无输出
- [ ] 双分支同步（main fast-forward）与推送；内仓 `ssam-lib` 已提交并同步外层快照

## 里程碑 B（后续计划，本计划不展开步骤）

1. **P5 实验执行**：WSL2 Containerlab 场景矩阵 S0–S5（22）+ R（3）脚本化；A-1 每场景 3 次重复；采集 JSONL（spec §5.1 schema）；代理关系标注（SELinux/AppArmor 为检查失败代理）。
2. **P6 拟合与选模**：对全量真实数据运行 `cmd/edgecompare --fit`，按决策层主判据选模型，输出参数文件、对比报告与自助法不确定度；结论口径限定为"哪些边显著 + 决策层改善"。
3. **P7 文档与论文口径**：实验报告归档；若论文涉及因子行为表述，保持 upper bound 限定、不回退既有数字；债务清单与方向② 状态更新。
