//go:build engine

package ssam

import (
	"context"
	"math"
	"testing"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
)

// confPolicyCfg builds a kernel config with confidence enabled and a rule
// table whose layers are distinguishable:
//
//	[confidence.check]    as-777 → 0.3   (exact-id beats everything)
//	[confidence.checkrx]  ^ot-   → 0.55  (regex beats source/domain)
//	[confidence.source]   user   → 0.9   (source beats domain)
//	[confidence.domain]   attack_surface → 0.9, business_continuity → 0.95
//	default → 0.5
func confPolicyCfg() *config.Config {
	cfg := config.Default()
	cc := config.DefaultConfidenceConfig()
	cc.Enabled = true
	cc.Default = 0.5
	cc.Floor = 0.1
	cc.ByCheckID["as-777"] = 0.3
	cc.BySource["user"] = 0.9
	cc.ByDomain["attack_surface"] = 0.9
	cc.ByDomain["business_continuity"] = 0.95
	cfg.Confidence = cc
	return cfg
}

func assessmentWithChecks(checks []model.CheckResult) *model.AssessmentResult {
	return &model.AssessmentResult{
		HostID:    "h1",
		Threshold: 80,
		Checks:    checks,
		SPCScore:  1.0,
		ThreatCoeff: 1.0,
	}
}

// TestEngineAdapterConfidenceResolve: per-check confidences are filled from
// the config rule table before scoring (design §3 rule priority: exact check
// id > source > domain > default).
func TestEngineAdapterConfidenceResolve(t *testing.T) {
	a := NewEngineAdapter(confPolicyCfg())
	result := assessmentWithChecks([]model.CheckResult{
		{CheckID: "AS-777", Domain: "attack_surface", Passed: false, Delta: -10, Source: model.CheckSourceBuiltin}, // exact rule 0.3 wins over domain
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -5, Source: model.CheckSourceBuiltin},  // domain 0.9 (no builtin source rule)
		{CheckID: "OT-001", Domain: "operation_trust", Passed: false, Delta: -5, Source: model.CheckSourceUser},    // source user 0.9
		{CheckID: "RS-001", Domain: "resilience", Passed: false, Delta: -5, Source: model.CheckSourceBuiltin},      // no rule → default 0.5
		{CheckID: "BC-001", Domain: "business_continuity", Passed: true, Delta: 0, Confidence: 0.8},                // upstream preserved
	})
	if err := a.ComputeScore(context.Background(), result); err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	want := map[string]float64{
		"AS-777": 0.3, "AS-001": 0.9, "OT-001": 0.9, "RS-001": 0.5, "BC-001": 0.8,
	}
	for i := range result.Checks {
		c := &result.Checks[i]
		if w := want[c.CheckID]; math.Abs(c.Confidence-w) > 1e-9 {
			t.Errorf("check %s confidence = %v, want %v", c.CheckID, c.Confidence, w)
		}
	}
}

// TestEngineAdapterConfidenceChangesScore: with confidence enabled, a
// half-trusted failure deducts half → a HIGHER score than the full-trust run;
// with the model disabled the two runs are identical.
func TestEngineAdapterConfidenceChangesScore(t *testing.T) {
	// attack_surface weight 35; one -40 failure.
	half := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -40, Source: model.CheckSourceBuiltin},
	}
	full := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -40, Source: model.CheckSourceBuiltin},
	}

	// Disabled policy: same score for both.
	disabledCfg := config.Default()
	da := NewEngineAdapter(disabledCfg)
	r1 := assessmentWithChecks(append([]model.CheckResult{}, half...))
	r2 := assessmentWithChecks(append([]model.CheckResult{}, full...))
	if err := da.ComputeScore(context.Background(), r1); err != nil {
		t.Fatal(err)
	}
	if err := da.ComputeScore(context.Background(), r2); err != nil {
		t.Fatal(err)
	}
	if r1.FinalScore != r2.FinalScore {
		t.Errorf("disabled policy must ignore confidence: %v != %v", r1.FinalScore, r2.FinalScore)
	}

	// Enabled policy with attack_surface domain→0.5: the half-trust run
	// deducts 20 instead of 40 → higher score AND non-zero posterior sigma.
	cfg := confPolicyCfg()
	cfg.Confidence.ByDomain["attack_surface"] = 0.5
	ea := NewEngineAdapter(cfg)
	// r3: the -40 failure resolved to domain 0.5 (half trust).
	r3 := assessmentWithChecks(append([]model.CheckResult{}, half...))
	// r4: the same failure explicitly fully trusted.
	r4 := assessmentWithChecks([]model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -40, Confidence: 1.0},
	})
	if err := ea.ComputeScore(context.Background(), r3); err != nil {
		t.Fatal(err)
	}
	if err := ea.ComputeScore(context.Background(), r4); err != nil {
		t.Fatal(err)
	}
	if r3.FinalScore <= r4.FinalScore {
		t.Errorf("half-trust run should score higher than full-trust: %v <= %v", r3.FinalScore, r4.FinalScore)
	}
	if r3.FinalSigma == 0 {
		t.Error("half-trust run must produce non-zero posterior sigma")
	}
	// Fully-trusted explicit confidence → sigma 0 (interval collapses).
	if r4.FinalSigma != 0 {
		t.Errorf("full-trust run must collapse sigma to 0, got %v", r4.FinalSigma)
	}
}

// TestEngineAdapterDisabledProducesZeroSigma: when [confidence] is absent the
// adapter must leave the posterior DEGENERATE (sigma 0, interval collapsed to
// the point estimate, evidence confidence 1) — the legacy output shape.
func TestEngineAdapterDisabledProducesZeroSigma(t *testing.T) {
	a := NewEngineAdapter(config.Default())
	result := assessmentWithChecks([]model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
	})
	if err := a.ComputeScore(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.FinalSigma != 0 {
		t.Errorf("disabled policy must collapse sigma to 0, got %v", result.FinalSigma)
	}
	if result.ScoreLower95 != result.ScoreUpper95 {
		t.Errorf("disabled policy interval must be degenerate, got [%v, %v]", result.ScoreLower95, result.ScoreUpper95)
	}
	if result.EvidenceConfidence != 1 {
		t.Errorf("disabled policy evidence confidence must be 1, got %v", result.EvidenceConfidence)
	}
	if result.ScoreLower95 != result.FinalScore {
		t.Errorf("disabled interval must equal the point estimate, got lo=%v score=%v", result.ScoreLower95, result.FinalScore)
	}
}
