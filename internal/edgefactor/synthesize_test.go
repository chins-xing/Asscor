package edgefactor

import (
	"math"
	"strings"
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

// 裁定 A：EffectiveFactor == 0 是「未提供」的哨兵，回落到配置权重 p.Factors[id]。
func TestSynthesizeZeroEffectiveFallsBackToConfiguredWeight(t *testing.T) {
	p := vectorParams()
	res, err := Synthesize(p, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors:      []FactorActivation{{FactorID: "EF-A", CTrigger: 1}}, // EffectiveFactor 缺省为 0
	})
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	// 回落到 p.Factors["EF-A"] = 0.8 → a = 0.1，与显式传 0.8 完全一致。
	wantP := 0.5 + 0.5*math.Exp(-0.1)
	if !approx(res.P["attack_surface"], wantP, 1e-9) {
		t.Errorf("P = %v, want %v (fallback to configured weight)", res.P["attack_surface"], wantP)
	}
}

// 裁定 A：既没有 effective 值、配置里也没有该权重 → 必须报错，绝不静默按「无惩罚」处理。
func TestSynthesizeRejectsFactorWithoutEffectiveValueOrWeight(t *testing.T) {
	const want = "edgefactor: factor"
	p := vectorParams()
	_, err := Synthesize(p, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 100},
		Factors:      []FactorActivation{{FactorID: "EF-UNKNOWN", CTrigger: 1}},
	})
	if err == nil {
		t.Fatal("V/G/C: an unresolved factor must be rejected instead of silently applying no penalty")
	}
	if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "EF-UNKNOWN") {
		t.Errorf("error must name the offending factor, got %q", err)
	}

	// legacy 分支同理：不得静默按「乘 1」放行。
	lp := Params{Model: ModelLegacy, PFloor: 0.5, Factors: map[string]float64{"A": 0.8}}
	_, err = Synthesize(lp, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 90},
		Factors:      []FactorActivation{{FactorID: "B", CTrigger: 1}},
	})
	if err == nil {
		t.Fatal("legacy: an unresolved factor must be rejected instead of silently ignoring it")
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("legacy error must name the offending factor, got %q", err)
	}
}

// 裁定 B：chain 模型的零值时间戳必须 fail-fast，不得静默退化成 vector。
func TestSynthesizeChainRejectsZeroTimestamp(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	chainParams := func() Params {
		p := vectorParams()
		p.Model = ModelChain
		p.ChainWindowSeconds = 300
		p.Coupling = map[string]map[string]float64{"EF-B": {"EF-A": 0.5}}
		p.Vectors["EF-B"] = map[string]float64{"attack_surface": 0.5}
		p.Factors["EF-B"] = 0.8
		return p
	}
	both := func(tsB, tsA time.Time) Input {
		return Input{DomainScores: map[string]float64{"attack_surface": 100}, Factors: []FactorActivation{
			{FactorID: "EF-B", CTrigger: 1, EffectiveFactor: 0.8, TS: tsB},
			{FactorID: "EF-A", CTrigger: 1, EffectiveFactor: 0.8, TS: tsA},
		}}
	}

	cases := map[string]Input{
		"cascade source without timestamp": both(time.Time{}, base.Add(60*time.Second)),
		"cascade target without timestamp": both(base, time.Time{}),
	}
	for name, in := range cases {
		if _, err := Synthesize(chainParams(), []string{"attack_surface"}, in); err == nil {
			t.Errorf("%s: chain must reject a zero timestamp instead of silently degrading to vector", name)
		} else if !strings.Contains(err.Error(), "edgefactor: chain model requires timestamps for every factor") {
			t.Errorf("%s: unexpected error %q", name, err)
		}
	}

	// 该 fail-fast 只属于 chain：graph 不读 TS，零值时间戳仍须被接受。
	gp := vectorParams()
	gp.Model = ModelGraph
	if _, err := Synthesize(gp, []string{"attack_surface"}, both(time.Time{}, time.Time{})); err != nil {
		t.Errorf("graph must not require timestamps, got %v", err)
	}
}

// 裁定 C：请求域缺 λ 必须报错，不得静默取 λ = 1.0。
func TestSynthesizeRejectsMissingLambdaForRequestedDomain(t *testing.T) {
	const want = "edgefactor: no lambda configured for domain"
	in := Input{DomainScores: map[string]float64{"attack_surface": 100}}

	for _, m := range []ModelID{ModelVector, ModelGraph, ModelChain} {
		p := vectorParams()
		p.Model = m
		if m == ModelChain {
			p.ChainWindowSeconds = 300
		}
		p.Lambda = map[string]float64{} // 请求域 attack_surface 没有 λ
		_, err := Synthesize(p, []string{"attack_surface"}, in)
		if err == nil {
			t.Errorf("model %q: a requested domain without lambda must be rejected", m)
			continue
		}
		if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "attack_surface") {
			t.Errorf("model %q: error must name the domain, got %q", m, err)
		}
	}

	// 只校验**请求**域：未请求的域缺 λ 不影响单域合成（vectorParams 只配了 attack_surface）。
	p := vectorParams()
	if _, err := Synthesize(p, []string{"attack_surface"}, in); err != nil {
		t.Errorf("unrequested domains must not be required to carry a lambda: %v", err)
	}

	// legacy 不读 λ（惩罚完全由 GlobalMultiplier 表达），因此豁免。
	lp := Params{Model: ModelLegacy, PFloor: 0.5, Factors: map[string]float64{"A": 0.8}}
	if _, err := Synthesize(lp, []string{"attack_surface"}, Input{
		DomainScores: map[string]float64{"attack_surface": 90},
		Factors:      []FactorActivation{{FactorID: "A", CTrigger: 1, EffectiveFactor: 0.8}},
	}); err != nil {
		t.Errorf("legacy must not require lambda, got %v", err)
	}
}
