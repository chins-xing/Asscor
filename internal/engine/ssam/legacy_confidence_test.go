//go:build engine

package ssam

import (
	"context"
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	"github.com/chins-xing/asscor/internal/model"
)

// The legacy DynamicScoringEngine path must consume the SAME confidence
// normalization and the SAME delta>=0 skip rule as the plugin path (audit
// I-4). These tests compare the two paths on identical inputs; before the fix
// the legacy path inlined its own `delta*conf` accumulation (no Enabled check,
// no Floor clamp, no delta>=0 skip).

func confidenceEnabledCfg() *config.Config {
	cfg := config.Default()
	cc := config.DefaultConfidenceConfig()
	cc.Enabled = true
	cc.Default = 1.0
	cc.Floor = 0.1
	cfg.Confidence = cc
	return cfg
}

// legacyScored runs the legacy DynamicScoringEngine end to end.
func legacyScored(t *testing.T, cfg *config.Config, host string, checks []model.CheckResult) *model.AssessmentResult {
	t.Helper()
	a := engine.NewAssessor(cfg)
	res := a.AssessFromResults(host, host, checks)
	if res == nil {
		t.Fatal("legacy assessment returned nil")
	}
	return res
}

// pluginScored runs the SSAM plugin path on the same inputs.
func pluginScored(t *testing.T, cfg *config.Config, checks []model.CheckResult) *model.AssessmentResult {
	t.Helper()
	a := NewEngineAdapter(cfg)
	res := &model.AssessmentResult{
		HostID:      "plugin-host",
		Threshold:   cfg.Threshold,
		Checks:      checks,
		SPCScore:    1.0,
		ThreatCoeff: cfg.ThreatCoeff,
	}
	if err := a.ComputeScore(context.Background(), res); err != nil {
		t.Fatalf("plugin ComputeScore: %v", err)
	}
	return res
}

// TestLegacyAndPluginFloorParity: an explicit confidence below the policy
// floor must clamp UP to the floor on BOTH paths. Before the fix legacy used
// the raw 0.01 (domain 99.6) while the plugin clamped to 0.1 (domain 96).
func TestLegacyAndPluginFloorParity(t *testing.T) {
	cfg := confidenceEnabledCfg()
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: 0.01},
	}
	legacy := legacyScored(t, cfg, "legacy-floor", checks)
	plugin := pluginScored(t, cfg, checks)

	if legacy.DomainScores.AttackSurface != 96 {
		t.Errorf("legacy attack_surface = %v, want 96 (floor 0.1 applies to raw 0.01)",
			legacy.DomainScores.AttackSurface)
	}
	if legacy.DomainScores.AttackSurface != plugin.DomainScores.AttackSurface {
		t.Errorf("legacy/plugin domain mismatch: %v vs %v",
			legacy.DomainScores.AttackSurface, plugin.DomainScores.AttackSurface)
	}
	if legacy.FinalScore != plugin.FinalScore {
		t.Errorf("legacy/plugin final mismatch: %v vs %v", legacy.FinalScore, plugin.FinalScore)
	}
}

// TestLegacyAndPluginHalfConfidenceParity: the ordinary normalization rule
// (explicit 0.5 → half deduction) must match across paths as well.
func TestLegacyAndPluginHalfConfidenceParity(t *testing.T) {
	cfg := confidenceEnabledCfg()
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: 0.5},
	}
	legacy := legacyScored(t, cfg, "legacy-half", checks)
	plugin := pluginScored(t, cfg, checks)

	if legacy.DomainScores.AttackSurface != 80 {
		t.Errorf("legacy attack_surface = %v, want 80", legacy.DomainScores.AttackSurface)
	}
	if legacy.DomainScores.AttackSurface != plugin.DomainScores.AttackSurface ||
		legacy.FinalScore != plugin.FinalScore {
		t.Errorf("legacy/plugin mismatch: domain %v/%v final %v/%v",
			legacy.DomainScores.AttackSurface, plugin.DomainScores.AttackSurface,
			legacy.FinalScore, plugin.FinalScore)
	}
}

// TestFailedCheckWithPositiveDeltaSkippedOnBothPaths locks the single
// delta>=0 semantics chosen for I-4: the library DomainBayes skips a failed
// check whose Delta is >= 0 (design §2.1 is stated in terms of delta<0), and
// the legacy path must do the same. Before the fix legacy added the positive
// delta (domain 65) while the plugin skipped it (domain 60).
func TestFailedCheckWithPositiveDeltaSkippedOnBothPaths(t *testing.T) {
	cfg := config.Default()
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40},
		{CheckID: "AS-002", Domain: model.DomainAttackSurface, Passed: false, Delta: +5},
	}
	legacy := legacyScored(t, cfg, "legacy-posdelta", checks)
	plugin := pluginScored(t, cfg, checks)

	if legacy.DomainScores.AttackSurface != 60 {
		t.Errorf("legacy attack_surface = %v, want 60 (failed delta>=0 is skipped)",
			legacy.DomainScores.AttackSurface)
	}
	if plugin.DomainScores.AttackSurface != 60 {
		t.Errorf("plugin attack_surface = %v, want 60", plugin.DomainScores.AttackSurface)
	}
	if legacy.FinalScore != plugin.FinalScore {
		t.Errorf("legacy/plugin final mismatch: %v vs %v", legacy.FinalScore, plugin.FinalScore)
	}
}

// TestLegacyDefaultConfigIgnoresExplicitConfidence: with the factory config
// (confidence disabled) an explicit per-check confidence must be ignored on
// the legacy path. This is the M4 mutation tooth: flipping the factory
// Enabled=true in internal/config/confidence.go makes these two runs differ
// (and therefore this test red).
func TestLegacyDefaultConfigIgnoresExplicitConfidence(t *testing.T) {
	cfg := config.Default()
	check := func(conf float64) *model.AssessmentResult {
		return legacyScored(t, cfg, "legacy-disabled", []model.CheckResult{
			{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: conf},
		})
	}
	// Independent assessors avoid the 5-minute result cache (which does not
	// include Confidence in its key — audit M-4).
	half := check(0.5)
	full := check(1.0)
	if half.DomainScores.AttackSurface != 60 || full.DomainScores.AttackSurface != 60 {
		t.Errorf("disabled policy must ignore explicit confidence: half=%v full=%v, want 60/60",
			half.DomainScores.AttackSurface, full.DomainScores.AttackSurface)
	}
	if half.FinalScore != full.FinalScore {
		t.Errorf("disabled policy finals differ: %v vs %v", half.FinalScore, full.FinalScore)
	}
}

// TestPluginDefaultConfigIgnoresExplicitConfidence is the plugin-path half of
// the M4 tooth (same reasoning as above).
func TestPluginDefaultConfigIgnoresExplicitConfidence(t *testing.T) {
	cfg := config.Default()
	half := pluginScored(t, cfg, []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: 0.5},
	})
	full := pluginScored(t, cfg, []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: 1.0},
	})
	if half.FinalScore != full.FinalScore || half.DomainScores.AttackSurface != full.DomainScores.AttackSurface {
		t.Errorf("disabled plugin policy must ignore explicit confidence: domain %v/%v final %v/%v",
			half.DomainScores.AttackSurface, full.DomainScores.AttackSurface,
			half.FinalScore, full.FinalScore)
	}
}

// TestLegacyScoringEmitsPosteriorStats locks I-1: the legacy path must write
// sigma / 95% interval / evidence confidence (they used to be all zero).
func TestLegacyScoringEmitsPosteriorStats(t *testing.T) {
	cfg := confidenceEnabledCfg()
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: 0.5},
	}
	res := legacyScored(t, cfg, "legacy-posterior", checks)

	if res.FinalSigma <= 0 {
		t.Errorf("legacy FinalSigma = %v, want > 0", res.FinalSigma)
	}
	if !(res.ScoreLower95 <= res.FinalScore && res.FinalScore <= res.ScoreUpper95) {
		t.Errorf("legacy interval [%v,%v] must contain FinalScore %v",
			res.ScoreLower95, res.ScoreUpper95, res.FinalScore)
	}
	if res.EvidenceConfidence <= 0 || res.EvidenceConfidence > 1 {
		t.Errorf("legacy EvidenceConfidence = %v, want in (0,1]", res.EvidenceConfidence)
	}
	// The same fixture on the plugin path must produce the same posterior.
	plugin := pluginScored(t, cfg, checks)
	if math.Abs(res.FinalSigma-plugin.FinalSigma) > 1e-9 {
		t.Errorf("legacy/plugin FinalSigma mismatch: %v vs %v", res.FinalSigma, plugin.FinalSigma)
	}
}

// TestLegacyDefaultScoresRemainBitIdentical pins the hard constraint: with the
// factory config (confidence disabled, no explicit confidence) every score is
// bit-identical to the pre-fix legacy accumulation. Values below were captured
// from the pre-fix implementation.
func TestLegacyDefaultScoresRemainBitIdentical(t *testing.T) {
	cfg := config.Default()
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40},
		{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: true, Delta: -10},
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -30},
		{CheckID: "RS-005", Domain: model.DomainResilience, Passed: false, Delta: -20},
	}
	res := legacyScored(t, cfg, "legacy-golden", checks)

	if res.DomainScores.AttackSurface != 60 ||
		res.DomainScores.BusinessContinuity != 100 ||
		res.DomainScores.OperationTrust != 70 ||
		res.DomainScores.Resilience != 80 {
		t.Errorf("domain scores changed: AS=%v BC=%v OT=%v RS=%v, want 60/100/70/80",
			res.DomainScores.AttackSurface, res.DomainScores.BusinessContinuity,
			res.DomainScores.OperationTrust, res.DomainScores.Resilience)
	}
	if res.FinalScore != 87.75 {
		t.Errorf("FinalScore = %v, want 87.75 (bit-identical default legacy score)", res.FinalScore)
	}
}
