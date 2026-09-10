package edgefactor

import (
	"math"
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

// 非有限值必须被 Validate 拒绝：NaN 与任何比较均为 false，会绕过所有范围检查。
func TestValidateRejectsNonFiniteValues(t *testing.T) {
	domains := []string{"attack_surface", "operation_trust"}
	cases := []struct {
		name   string
		mutate func(*Params)
		field  string // 错误信息必须指明的字段
	}{
		{"NaN p_floor", func(p *Params) { p.PFloor = math.NaN() }, "p_floor"},
		{"+Inf p_floor", func(p *Params) { p.PFloor = math.Inf(1) }, "p_floor"},
		{"NaN lambda", func(p *Params) { p.Lambda["attack_surface"] = math.NaN() }, "lambda"},
		{"+Inf lambda", func(p *Params) { p.Lambda["operation_trust"] = math.Inf(1) }, "lambda"},
		{"NaN factor", func(p *Params) { p.Factors["EF-SELINUX"] = math.NaN() }, "factor"},
		{"-Inf factor", func(p *Params) { p.Factors["EF-SELINUX"] = math.Inf(-1) }, "factor"},
		{"NaN vector component", func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"attack_surface": math.NaN()}
		}, "vector"},
		{"+Inf vector component", func(p *Params) {
			p.Vectors["EF-SELINUX"] = map[string]float64{"operation_trust": math.Inf(1)}
		}, "vector"},
		{"NaN coupling", func(p *Params) {
			p.Coupling = map[string]map[string]float64{"EF-A": {"EF-B": math.NaN()}}
		}, "coupling"},
		{"+Inf coupling", func(p *Params) {
			p.Coupling = map[string]map[string]float64{"EF-A": {"EF-B": math.Inf(1)}}
		}, "coupling"},
	}
	for _, tc := range cases {
		p := baseParams()
		tc.mutate(&p)
		err := p.Validate(domains)
		if err == nil {
			t.Errorf("%s: Validate must fail", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: error must name field %q, got %q", tc.name, tc.field, err)
		}
	}
}

// Hash 对非有限参数（绕过 Validate 直接构造）必须返回 16 位哨兵，绝不返回空串。
func TestHashReturnsSentinelForNonFiniteParams(t *testing.T) {
	const sentinel = "0000000000000000"
	p := baseParams()
	p.Factors["EF-SELINUX"] = math.NaN()
	if got := p.Hash(); got != sentinel {
		t.Errorf("Hash with NaN factor must return sentinel %q, got %q (len %d)", sentinel, got, len(got))
	}
	q := baseParams()
	q.PFloor = math.Inf(1)
	if got := q.Hash(); got != sentinel {
		t.Errorf("Hash with +Inf p_floor must return sentinel %q, got %q (len %d)", sentinel, got, len(got))
	}
}
