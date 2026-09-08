package config

import (
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/model"
)

const confidenceIni = `
[confidence]
enabled = true
algorithm = weighted_evidence
accept_by_lower_bound = true
default = 0.85
floor = 0.1

[confidence.check]
as-001 = 0.99
ot-005 = 0.7

[confidence.checkrx]
^rs- = 0.92

[confidence.source]
user = 0.9
cti = 0.5

[confidence.domain]
attack_surface = 0.95
`

func TestParseConfidenceSection(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	cc := cfg.Confidence
	if !cc.Enabled {
		t.Error("enabled must be true")
	}
	if cc.Algorithm != "weighted_evidence" {
		t.Errorf("algorithm = %q", cc.Algorithm)
	}
	if !cc.AcceptByLowerBound {
		t.Error("accept_by_lower_bound must be true")
	}
	if cc.Default != 0.85 || cc.Floor != 0.1 {
		t.Errorf("default/floor = %v/%v", cc.Default, cc.Floor)
	}
	if cc.ByCheckID["as-001"] != 0.99 || cc.ByCheckID["ot-005"] != 0.7 {
		t.Errorf("ByCheckID = %v", cc.ByCheckID)
	}
	if cc.BySource["user"] != 0.9 || cc.BySource["cti"] != 0.5 {
		t.Errorf("BySource = %v", cc.BySource)
	}
	if cc.ByDomain["attack_surface"] != 0.95 {
		t.Errorf("ByDomain = %v", cc.ByDomain)
	}
	if len(cc.CheckPatterns) != 1 {
		t.Fatalf("CheckPatterns = %d, want 1", len(cc.CheckPatterns))
	}
}

// TestConfidenceResolveRulePriority exercises the exact precedence:
// check-id > checkrx > source > domain > default.
func TestConfidenceResolveRulePriority(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	cc := cfg.Confidence

	cases := []struct {
		name                       string
		checkID, sourceKey, domain string
		want                       float64
	}{
		{"exact check wins", "AS-001", "builtin", "attack_surface", 0.99},
		{"regex after exact miss", "RS-777", "builtin", "resilience", 0.92},
		{"source after regex miss", "XY-1", "cti", "operation_trust", 0.5},
		{"domain after source miss", "XY-1", "unknown-key", "attack_surface", 0.95},
		{"default fallback", "XY-1", "unknown-key", "unknown-domain", 0.85},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cc.Resolve(tc.checkID, tc.sourceKey, tc.domain)
			if got != tc.want {
				t.Errorf("Resolve(%q,%q,%q) = %v, want %v", tc.checkID, tc.sourceKey, tc.domain, got, tc.want)
			}
		})
	}
}

// TestConfidenceDisabledReturnsOne: when [confidence] is absent, every
// resolution is 1.0 — the backward-compatible default.
func TestConfidenceDisabledReturnsOne(t *testing.T) {
	cfg, err := Parse("[weights]\nattack_surface = 35\n")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Confidence.Enabled {
		t.Error("confidence must default to disabled")
	}
	if got := cfg.Confidence.Resolve("AS-001", "cti", "attack_surface"); got != 1.0 {
		t.Errorf("disabled resolve = %v, want 1.0", got)
	}
}

// TestConfidenceBadRegexFailsParse: an invalid checkrx pattern must fail the
// whole config load (fail-fast, never silently ignore a typo'd rule).
func TestConfidenceBadRegexFailsParse(t *testing.T) {
	ini := "[confidence]\nenabled = true\n\n[confidence.checkrx]\n[unclosed = 0.5\n"
	if _, err := Parse(ini); err == nil {
		t.Error("invalid regex must fail Parse")
	} else if !strings.Contains(err.Error(), "checkrx") {
		t.Errorf("error should mention checkrx, got %v", err)
	}
}

// TestConfidenceValueClamping: out-of-range confidences are clamped.
func TestConfidenceValueClamping(t *testing.T) {
	ini := "[confidence]\nenabled = true\n\n[confidence.source]\ncti = 2.0\nuser = -1\n"
	cfg, err := Parse(ini)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Confidence.BySource["cti"] != 1.0 {
		t.Errorf("cti should clamp to 1.0, got %v", cfg.Confidence.BySource["cti"])
	}
	if _, ok := cfg.Confidence.BySource["user"]; ok {
		t.Error("non-positive user confidence must be dropped")
	}
}

// TestConfigResolveChecks: the shared per-result resolver (used by both the
// ssam plugin engine and the legacy DynamicScoringEngine) fills confidences
// from the rule table and preserves upstream-set ones.
func TestConfigResolveChecks(t *testing.T) {
	cfg, err := Parse(confidenceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Source: model.CheckSourceBuiltin}, // exact rule 0.99
		{CheckID: "CU-1", Domain: "operation_trust", Source: model.CheckSourceUser},     // source user 0.9
		{CheckID: "XY-9", Domain: "resilience", Source: model.CheckSourceUser},          // source user 0.9 (no exact/regex hit)
		{CheckID: "NOPE-1", Domain: "resilience", Source: model.CheckSourceBuiltin},     // domain miss → default 0.85
		{CheckID: "Y-9", Domain: "attack_surface", Confidence: 0.77},                    // upstream preserved
	}
	cfg.ResolveChecks(checks)

	want := []float64{0.99, 0.9, 0.9, 0.85, 0.77}
	for i := range checks {
		if checks[i].Confidence != want[i] {
			t.Errorf("check %s confidence = %v, want %v", checks[i].CheckID, checks[i].Confidence, want[i])
		}
	}

	// Disabled config is a no-op.
	disabled, _ := Parse("[weights]\nattack_surface = 35\n")
	checks2 := []model.CheckResult{{CheckID: "AS-001", Domain: "attack_surface"}}
	disabled.ResolveChecks(checks2)
	if checks2[0].Confidence != 0 {
		t.Error("disabled config must not touch confidences")
	}
}
