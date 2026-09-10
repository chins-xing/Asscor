package edgefactor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
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
	PFloor             float64                       // 惩罚上限 = 1 − PFloor
	Lambda             map[string]float64            // 逐域 λ_d
	Vectors            map[string]map[string]float64 // factorID → domain → v_i[d]
	Coupling           map[string]map[string]float64 // factorID → factorID → c_ij
	ChainWindowSeconds int                           // 仅 chain
	Factors            map[string]float64            // factorID → f_i
}

// DefaultDomains 返回域顺序（与 config.ini / WeightConfig 一致）。
func DefaultDomains() []string {
	return []string{"attack_surface", "business_continuity", "operation_trust", "resilience", "kernel_security"}
}

// hashSentinel 是 Hash 在参数不可序列化（防御分支）时返回的固定指纹。
const hashSentinel = "0000000000000000"

// nonFinite 报告 v 是否为 NaN 或 ±Inf。非有限值必须被 Validate 挡在门外：
// NaN 与任何比较都是 false，会静默绕过全部范围检查，并让下游公式产出 NaN。
func nonFinite(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

// Validate 做 fail-fast 校验（spec §4 规则 3）。
func (p Params) Validate(domains []string) error {
	switch p.Model {
	case ModelLegacy, ModelVector, ModelGraph, ModelChain:
	default:
		return fmt.Errorf("edgefactor: unknown model %q", p.Model)
	}
	if nonFinite(p.PFloor) {
		return fmt.Errorf("edgefactor: p_floor = %v must be finite", p.PFloor)
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
		if nonFinite(l) {
			return fmt.Errorf("edgefactor: lambda[%s] = %v must be finite", d, l)
		}
		if l <= 0 {
			return fmt.Errorf("edgefactor: lambda[%s] must be > 0, got %v", d, l)
		}
	}
	for id, f := range p.Factors {
		if nonFinite(f) {
			return fmt.Errorf("edgefactor: factor %s = %v must be finite", id, f)
		}
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
			if nonFinite(v) {
				return fmt.Errorf("edgefactor: vector %s[%s] = %v must be finite", id, d, v)
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
			if nonFinite(c) {
				return fmt.Errorf("edgefactor: coupling %s→%s = %v must be finite", from, to, c)
			}
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
// 非有限参数已被 Validate 拒绝，故下面的哨兵分支仅为防御：encoding/json 拒绝
// 非有限浮点，若不兜底就会返回空串，静默破坏溯源字段的「16 位 hex」契约。
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
		return hashSentinel
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}
