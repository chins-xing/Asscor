package config

import (
	"strings"
	"testing"
)

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
			"model":                           "graph",
			"p_floor":                         "0.4",
			"lambda.attack_surface":           "1.5",
			"vector.EF-SELINUX":               "0.5,0.2,0.1,0.1,0.1",
			"coupling.EF-SELINUX.EF-APPARMOR": "0.35",
			"chain.window_seconds":            "300",
			"trigger.EF-SELINUX":              "OT-005",
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
	// Domain order (design §4 rule 4): attack_surface, business_continuity,
	// operation_trust, resilience, kernel_security. Both positions are pinned
	// so a reordering of the mapping cannot pass silently.
	if got := cfg.Vectors["EF-SELINUX"]["business_continuity"]; got != 0.2 {
		t.Errorf("vector[1] (business_continuity) = %v, want 0.2", got)
	}
	if got := cfg.Vectors["EF-SELINUX"]["operation_trust"]; got != 0.1 {
		t.Errorf("vector[2] (operation_trust) = %v, want 0.1", got)
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
		{"model": "chain", "p_floor": "0.5"}, // chain 缺窗口
		{"model": "graph", "p_floor": "0.5", "p_floor_extra": "x"},
	}
	for i, kv := range cases {
		if _, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": kv}); err == nil {
			t.Errorf("case %d must fail: %v", i, kv)
		}
	}
}

// TestParseEdgeFactorModelRejectsNonFiniteValues pins the fail-fast rule for
// non-finite numbers: strconv.ParseFloat accepts "NaN"/"Inf"/"-Inf", and a
// non-finite value would silently poison the penalty formula (a NaN penalty is
// neither bounded nor monotone, defeating P1/P2 of the design). Every numeric
// key — p_floor, lambda.*, each of the five vector components, coupling.* —
// must reject it, and the error must name the key and echo the raw value.
func TestParseEdgeFactorModelRejectsNonFiniteValues(t *testing.T) {
	nonFinite := []string{"NaN", "nan", "Inf", "+Inf", "-Inf"}

	vectorOf := func(parts ...string) string { return strings.Join(parts, ",") }

	for _, bad := range nonFinite {
		cases := []struct {
			name string
			key  string // key whose name must appear in the error
			kv   map[string]string
		}{
			{
				name: "p_floor",
				key:  "p_floor",
				kv:   map[string]string{"model": "graph", "p_floor": bad},
			},
			{
				name: "lambda",
				key:  "lambda.attack_surface",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "lambda.attack_surface": bad},
			},
			{
				name: "vector_component_0",
				key:  "vector.EF-A[0]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf(bad, "0.1", "0.1", "0.1", "0.1")},
			},
			{
				name: "vector_component_1",
				key:  "vector.EF-A[1]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", bad, "0.1", "0.1", "0.1")},
			},
			{
				name: "vector_component_2",
				key:  "vector.EF-A[2]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", bad, "0.1", "0.1")},
			},
			{
				name: "vector_component_3",
				key:  "vector.EF-A[3]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", "0.1", bad, "0.1")},
			},
			{
				name: "vector_component_4",
				key:  "vector.EF-A[4]",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "vector.EF-A": vectorOf("0.1", "0.1", "0.1", "0.1", bad)},
			},
			{
				name: "coupling",
				key:  "coupling.A.B",
				kv:   map[string]string{"model": "graph", "p_floor": "0.5", "coupling.A.B": bad},
			},
		}
		for _, tc := range cases {
			_, _, err := ParseEdgeFactorModel(map[string]map[string]string{"edge_factors.model": tc.kv})
			if err == nil {
				t.Errorf("%s=%q must be rejected (%s)", tc.name, bad, tc.name)
				continue
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("%s=%q: error %q must name the key %q", tc.name, bad, err.Error(), tc.key)
			}
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("%s=%q: error %q must echo the raw value", tc.name, bad, err.Error())
			}
		}
	}
}

// TestParsePopulatesEdgeFactorModelSection pins the wiring into Config: the
// parsed section lands in Config.EdgeFactorModel, and an absent section leaves
// the zero value (Model == "" ⇒ the caller keeps the legacy path).
func TestParsePopulatesEdgeFactorModelSection(t *testing.T) {
	content := `
[edge_factors.model]
model = graph
p_floor = 0.4
lambda.attack_surface = 1.5
vector.ef-selinux = 0.5,0.2,0.1,0.1,0.1
coupling.ef-selinux.ef-apparmor = 0.35
trigger.ef-selinux = OT-005
`
	cfg, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.EdgeFactorModel.Model != "graph" {
		t.Fatalf("model = %q, want graph", cfg.EdgeFactorModel.Model)
	}
	if cfg.EdgeFactorModel.PFloor != 0.4 {
		t.Errorf("p_floor = %v, want 0.4", cfg.EdgeFactorModel.PFloor)
	}
	if got := cfg.EdgeFactorModel.Vectors["ef-selinux"]["business_continuity"]; got != 0.2 {
		t.Errorf("vector[1] (business_continuity) = %v, want 0.2", got)
	}
	if got := cfg.EdgeFactorModel.Vectors["ef-selinux"]["resilience"]; got != 0.1 {
		t.Errorf("vector[3] (resilience) = %v, want 0.1", got)
	}
	if cfg.EdgeFactorModel.TriggerMap["ef-selinux"] != "OT-005" {
		t.Errorf("trigger map = %v", cfg.EdgeFactorModel.TriggerMap)
	}

	absent, err := Parse("[weights]\nattack_surface = 35\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if absent.EdgeFactorModel.Model != "" {
		t.Errorf("absent section must leave the zero value, got %+v", absent.EdgeFactorModel)
	}
}

// TestParseRejectsBadEdgeFactorModelSection pins that Parse propagates the
// parse error instead of silently ignoring a misconfigured section.
func TestParseRejectsBadEdgeFactorModelSection(t *testing.T) {
	if _, err := Parse("[edge_factors.model]\nmodel = oracle\n"); err == nil {
		t.Error("Parse must fail on an unknown edge factor model")
	}
}
