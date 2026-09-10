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
