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
//
// 前置约定（三条 fail-fast，全部拒绝静默退化）：
//   - FactorActivation.EffectiveFactor == 0 表示「未提供」：回落到配置权重 p.Factors[id]；
//     两者都缺即报错，绝不静默按 1（无惩罚）处理。
//   - ModelChain 要求每个激活因子都带时间戳；零值 TS 直接报错，不允许静默退化成 vector。
//   - 本次请求的每个 domain 都必须有 p.Lambda[d]（legacy 豁免，它不读 λ）。
func Synthesize(p Params, domains []string, in Input) (Result, error) {
	if err := p.Validate(domains); err != nil {
		return Result{}, err
	}

	// λ_d 是 V/G/C 公式的必需项：缺失即报错，不得静默取 1.0 这类代码内建常量。
	// 只校验**本次请求的域**（不是全部 5 个默认域），故单域调用仍然合法。
	// legacy 不读 λ（惩罚完全由 GlobalMultiplier 表达），因此对它豁免。
	if p.Model != ModelLegacy {
		for _, d := range domains {
			if _, ok := p.Lambda[d]; !ok {
				return Result{}, fmt.Errorf("edgefactor: no lambda configured for domain %q", d)
			}
		}
	}

	// chain 是有向时序模型：缺时间戳意味着全部耦合项静默失效（结果精确等于 vector），
	// 故 fail-fast，而不是让时序语义无声消失。
	if p.Model == ModelChain {
		for _, f := range in.Factors {
			if f.TS.IsZero() {
				return Result{}, fmt.Errorf("edgefactor: chain model requires timestamps for every factor (missing for %q)", f.FactorID)
			}
		}
	}

	// 解析每个激活因子的有效值：EffectiveFactor == 0 是「未提供」的哨兵，
	// 回落到配置权重；两者都缺即报错（否则会静默变成「该因子无惩罚」）。
	effs := make([]float64, len(in.Factors))
	for i, f := range in.Factors {
		eff, err := resolveEffective(p, f)
		if err != nil {
			return Result{}, err
		}
		effs[i] = eff
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
		// effs 已在 resolveEffective 中统一校验为有限的 (0,1]，故这里直接连乘。
		// 原 plan 的 `if eff > 0 && eff < 1 { mult *= eff }` 门控会把越界值静默跳过
		// （等于按「无惩罚」处理），那正是裁定 A 要清除的同类静默路径 —— 本包按主控
		// 裁定覆盖该 plan 文字：越界一律在 resolveEffective 处报错，绝不静默跳过。
		mult := 1.0
		for i := range in.Factors {
			mult *= effs[i]
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
		id string
		a  map[string]float64
		ts time.Time
	}
	contribs := make([]contribution, 0, len(in.Factors))
	for i, f := range in.Factors {
		eff := effs[i]
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
		// 非 legacy 的每个请求域都已在入口处校验 λ 存在，legacy 也已提前返回，
		// 故这里直接取值 —— 不再保留 λ = 1.0 的兜底（那条分支已不可达，
		// 留着只会误导读者并给未来重构重新打开静默兜底的抓手）。
		lambda := p.Lambda[d]
		P := p.PFloor + (1-p.PFloor)*math.Exp(-lambda*L)
		res.L[d] = L
		res.P[d] = P
		res.DomainScores[d] = in.DomainScores[d] * P
	}
	return res, nil
}

// resolveEffective 解析一个激活因子的有效值（spec §3.1）。
// f.EffectiveFactor == 0 表示调用方未提供该值：回落到配置权重 p.Factors[f.FactorID]；
// 两者都缺即报错 —— 绝不静默按「无惩罚」处理，那会低估惩罚且无人察觉。
//
// 最终采用的 eff 值（含从 p.Factors 回落的那条路径）统一在此校验：Input 侧的值不经过
// Validate（Validate 只覆盖 Params），故必须自查。若放任越界值直通：eff > 1 会让
// a = (1−eff)·v 变负 → L < 0 → P > 1（域分被抬到基线之上，反向违反 P1）；
// NaN 则因「NaN != 0」为真而原样直通，把 L/P/DomainScores 全污染成 NaN 且无任何报错。
func resolveEffective(p Params, f FactorActivation) (float64, error) {
	eff := f.EffectiveFactor
	if eff == 0 {
		w, ok := p.Factors[f.FactorID]
		if !ok {
			return 0, fmt.Errorf("edgefactor: factor %q has neither an effective value nor a configured weight", f.FactorID)
		}
		eff = w
	}
	if nonFinite(eff) {
		return 0, fmt.Errorf("edgefactor: factor %q effective value %v must be finite", f.FactorID, eff)
	}
	if eff <= 0 || eff > 1 {
		return 0, fmt.Errorf("edgefactor: factor %q effective value %v out of (0,1]", f.FactorID, eff)
	}
	return eff, nil
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
