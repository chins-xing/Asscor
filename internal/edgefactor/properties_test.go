package edgefactor

import (
	"math"
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
	prevGap := math.Inf(1)
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

		// 收敛断言：a = (1−0.5)·0.5 = 0.25 → L = 0.25n（0.25 二进制可表示，故精确），
		// P − P_floor = 0.6·e^{−2L} 随 n **严格递减**。
		if wantL := 0.25 * float64(n); !approx(res.L["attack_surface"], wantL, 1e-12) {
			t.Fatalf("L at n=%d = %v, want %v", n, res.L["attack_surface"], wantL)
		}
		gap := res.P["attack_surface"] - p.PFloor
		if wantGap := 0.6 * math.Exp(-2*res.L["attack_surface"]); !approx(gap, wantGap, 1e-12) {
			t.Fatalf("P − P_floor at n=%d = %v, want analytic %v", n, gap, wantGap)
		}
		if gap >= prevGap {
			t.Fatalf("P − P_floor must strictly decrease at n=%d: %v >= %v", n, gap, prevGap)
		}
		prevGap = gap
	}
	// n = 20：L = 5，P − P_floor = 0.6·e^{−10} ≈ 2.7e-5 —— 已收敛，但仍严格为正。
	if !approx(prevL, 5.0, 1e-12) {
		t.Errorf("L at n=20 = %v, want 5", prevL)
	}
	if prevGap >= 1e-3 {
		t.Errorf("P − P_floor at n=20 = %v, want < 1e-3", prevGap)
	}
	if prevGap <= 0 {
		t.Errorf("P − P_floor must stay strictly positive at n=20, got %v", prevGap)
	}
}

// P3: L(A) − Σ_i L({i}) 必须**等于**解析的成对耦合和 Σ_{i<j} c_ij·a_i·a_j。
// 只断言 ≥ 0 是弱断言；断言解析值能区分乘积耦合与和式耦合，也能抓住漏乘 a_j、
// 漏掉系数一类的实现错误。
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

		// 解析值：a_i = (1−eff_i)·v_i[d]，再对每一对**不同**因子取 c
		// （取向与实现一致：按 id 字典序传 (from, to)，graph 先查正向再回查反向）。
		a := make(map[string]float64, len(in.Factors))
		for _, f := range in.Factors {
			eff := f.EffectiveFactor
			if eff == 0 {
				eff = p.Factors[f.FactorID]
			}
			a[f.FactorID] = (1 - eff) * p.Vectors[f.FactorID]["attack_surface"]
		}
		want := 0.0
		for x := 0; x < len(in.Factors); x++ {
			for y := x + 1; y < len(in.Factors); y++ {
				fx, fy := in.Factors[x].FactorID, in.Factors[y].FactorID
				if fx == fy {
					continue // 同一因子的自耦合在实现中被跳过
				}
				from, to := fx, fy
				if to < from {
					from, to = to, from
				}
				want += couplingValue(p, from, to) * a[from] * a[to]
			}
		}
		if got := joint - sumSingle; !approx(got, want, 1e-12) {
			t.Fatalf("joint − Σ L({i}) = %v, want analytic Σ c_ij·a_i·a_j = %v", got, want)
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
