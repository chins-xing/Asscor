//go:build adapter

package adapterhub

import "testing"

// newTestFinding builds a minimal finding for rule-engine tests.
func newTestFinding() *NormalizedFinding {
	return &NormalizedFinding{
		ID:       "f-1",
		Source:   "trivy",
		CheckID:  "TR-001",
		Severity: "CRITICAL",
		Result:   ResultFail,
		Metadata: map[string]string{},
	}
}

func TestSeverityRuleNormalize(t *testing.T) {
	r := SeverityRule{
		Name: "trivy-sev",
		Mappings: map[string]Severity{
			"critical": "critical",
			"high":     "high",
			"medium":   "medium",
			"low":      "low",
		},
	}
	cases := []struct {
		in   string
		want Severity
	}{
		{"CRITICAL", "critical"}, // case-insensitive
		{"High", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"unknown-level", SeverityNone}, // unmapped → SeverityNone ("none")
		{"", SeverityNone},
	}
	for _, tc := range cases {
		if got := r.Normalize(tc.in); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRuleEngineApplySeverityFallsThroughToDefault(t *testing.T) {
	// No matching severity rule → the finding's severity is left untouched
	// (the engine only rewrites it when a rule matches).
	e := NewRuleEngine(&RuleSet{})
	f := newTestFinding()
	f.Severity = "high"
	e.ApplySeverity(f)
	if f.Severity != "high" {
		t.Errorf("severity must be left as-is when no rule matches, got %q", f.Severity)
	}
}

func TestRuleEngineApplyDomainByCheckID(t *testing.T) {
	rs := &RuleSet{
		DomainRules: []DomainRule{
			{Name: "map-tr", Tool: "trivy", CheckID: "TR-001", Domain: "operation_trust"},
		},
	}
	e := NewRuleEngine(rs)
	f := newTestFinding()
	f.Domain = "" // force mapping
	e.ApplyDomain(f)
	if f.Domain != "operation_trust" {
		t.Errorf("Domain = %q, want operation_trust", f.Domain)
	}

	// Non-matching CheckID stays empty.
	f2 := newTestFinding()
	f2.CheckID = "OTHER-99"
	e.ApplyDomain(f2)
	if f2.Domain != "" {
		t.Errorf("Domain = %q, want empty for unmapped check", f2.Domain)
	}

	// Already-set Domain is never overwritten.
	f3 := newTestFinding()
	f3.Domain = "resilience"
	e.ApplyDomain(f3)
	if f3.Domain != "resilience" {
		t.Errorf("existing Domain must be preserved, got %q", f3.Domain)
	}
}

func TestRuleEngineApplyDeltaBySeverity(t *testing.T) {
	rs := &RuleSet{
		DeltaRules: []DeltaRule{
			{Name: "delta-critical", Tool: "trivy", Severity: "critical", BaseDelta: -15},
			{Name: "delta-high", Tool: "trivy", Severity: "high", BaseDelta: -10},
		},
	}
	e := NewRuleEngine(rs)

	f := newTestFinding()
	f.Severity = "critical"
	e.ApplyDelta(f)
	if f.Delta != -15 {
		t.Errorf("Delta = %v, want -15 for critical", f.Delta)
	}

	// Passed findings always get Delta 0 regardless of severity.
	f2 := newTestFinding()
	f2.Result = ResultPass
	f2.Severity = "critical"
	e.ApplyDelta(f2)
	if f2.Delta != 0 {
		t.Errorf("passed finding Delta = %v, want 0", f2.Delta)
	}
}

func TestRuleEngineApplyDeltaDefaultProfile(t *testing.T) {
	// No delta rule matches → falls back to the default profile's mapping.
	e := NewRuleEngine(&RuleSet{})
	f := newTestFinding()
	f.Severity = "high"
	e.ApplyDelta(f)
	if f.Delta != -10 {
		t.Errorf("default profile Delta = %v, want -10 for high", f.Delta)
	}

	f2 := newTestFinding()
	f2.Severity = "info"
	e.ApplyDelta(f2)
	if f2.Delta != 0 {
		t.Errorf("info Delta = %v, want 0", f2.Delta)
	}
}

func TestRuleEngineEvaluateCondition(t *testing.T) {
	e := NewRuleEngine(&RuleSet{})
	f := newTestFinding()
	f.Domain = "attack_surface"
	f.Category = "config"
	f.CVE = "CVE-2024-1234"
	f.Metadata["region"] = "eu-west"

	cases := []struct {
		name string
		cond DeltaCondition
		want bool
	}{
		{"severity eq", DeltaCondition{Field: "severity", Operator: "==", Value: "CRITICAL"}, true},
		{"severity neq", DeltaCondition{Field: "severity", Operator: "!=", Value: "high"}, true},
		{"domain eq", DeltaCondition{Field: "domain", Operator: "==", Value: "attack_surface"}, true},
		{"domain neq", DeltaCondition{Field: "domain", Operator: "==", Value: "resilience"}, false},
		{"metadata eq", DeltaCondition{Field: "region", Operator: "==", Value: "eu-west"}, true},
		{"metadata missing", DeltaCondition{Field: "nonexistent", Operator: "exists"}, false},
		{"metadata exists", DeltaCondition{Field: "region", Operator: "exists"}, true},
		{"has_cve true", DeltaCondition{Field: "has_cve", Operator: "==", Value: true}, true},
		{"unknown op", DeltaCondition{Field: "domain", Operator: "regex", Value: "x"}, false},
		{"unknown field", DeltaCondition{Field: "zzz", Operator: "==", Value: "1"}, false},
	}
	for _, tc := range cases {
		if got := e.evaluateCondition(f, tc.cond); got != tc.want {
			t.Errorf("%s: evaluateCondition(%+v) = %v, want %v", tc.name, tc.cond, got, tc.want)
		}
	}
}

func TestRuleEngineApplyFilter(t *testing.T) {
	rs := &RuleSet{
		FilterRules: []FilterRule{
			{Name: "drop-info", Tool: "trivy", Action: FilterActionExclude, Conditions: []FilterCondition{
				{Field: "severity", Operator: "==", Value: "info"},
			}},
			{Name: "tag-critical", Tool: "trivy", Action: FilterActionTag, Conditions: []FilterCondition{
				{Field: "severity", Operator: "==", Value: "critical"},
			}},
		},
	}
	e := NewRuleEngine(rs)

	info := newTestFinding()
	info.Severity = "info"
	crit := newTestFinding()
	crit.Severity = "critical"

	out := e.ApplyFilter([]*NormalizedFinding{info, crit}, "trivy")
	if len(out) != 1 {
		t.Fatalf("filtered length = %d, want 1 (info excluded)", len(out))
	}
	if out[0].Severity != "critical" {
		t.Errorf("surviving finding = %q, want critical", out[0].Severity)
	}
	if out[0].Metadata["filtered_by"] != "tag-critical" {
		t.Errorf("critical finding should be tagged, metadata = %v", out[0].Metadata)
	}
}

func TestRuleEngineApplyAllOrder(t *testing.T) {
	// Transform → Severity → Domain → Delta via ApplyAll.
	rs := &RuleSet{
		SeverityRules: []SeverityRule{
			{Name: "sev", Tool: "tool-x", Mappings: map[string]Severity{"critical": "critical"}},
		},
		DomainRules: []DomainRule{
			{Name: "dom", Tool: "tool-x", CheckID: "CX-1", Domain: "resilience"},
		},
		DeltaRules: []DeltaRule{
			{Name: "del", Tool: "tool-x", Severity: "critical", BaseDelta: -15},
		},
	}
	e := NewRuleEngine(rs)
	f := &NormalizedFinding{
		ID: "x", Source: "tool-x", CheckID: "CX-1",
		Severity: "critical", Result: ResultFail,
	}
	e.ApplyAll(f)
	if f.Severity != "critical" || f.Domain != "resilience" || f.Delta != -15 {
		t.Errorf("ApplyAll result = sev:%q dom:%q delta:%v, want critical/resilience/-15",
			f.Severity, f.Domain, f.Delta)
	}
}

func TestDefaultGenericProfileDelta(t *testing.T) {
	p := DefaultGenericProfile()
	cases := []struct {
		sev  string
		want float64
	}{
		{"critical", -15}, {"high", -10}, {"medium", -7.5}, {"low", -5},
		{"info", 0}, {"none", 0}, {"unknown-thing", -7.5},
	}
	for _, tc := range cases {
		if got := p.DeltaFromSeverity(tc.sev); got != tc.want {
			t.Errorf("DeltaFromSeverity(%q) = %v, want %v", tc.sev, got, tc.want)
		}
	}
}
