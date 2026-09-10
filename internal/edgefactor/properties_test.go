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
