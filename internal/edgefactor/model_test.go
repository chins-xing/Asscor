//go:build edgefactor

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
