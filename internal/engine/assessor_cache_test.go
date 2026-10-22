//go:build engine

package engine

import (
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// confidenceCacheCfg returns a config with confidence-aware scoring enabled
// and a uniform default confidence. Used by the audit M-4 cache tests below.
func confidenceCacheCfg(defaultConf float64) *config.Config {
	cfg := config.Default()
	cc := config.DefaultConfidenceConfig()
	cc.Enabled = true
	cc.Default = defaultConf
	cfg.Confidence = cc
	return cfg
}

// TestResultsCacheKeyIncludesConfidence is the red test for audit M-4:
// hashCheckResults must cover Confidence (and Source), otherwise two assessments
// that differ only in per-check confidence collide on the same cache key and the
// second call returns the first result object verbatim.
func TestResultsCacheKeyIncludesConfidence(t *testing.T) {
	cfg := confidenceCacheCfg(1.0)
	a := NewAssessor(cfg)

	run := func(conf float64) *model.AssessmentResult {
		return a.AssessFromResults("cache-conf-host", "cache-conf-host", []model.CheckResult{
			{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40, Confidence: conf},
		})
	}

	full := run(1.0)
	half := run(0.2)

	if full == half {
		t.Fatalf("second AssessFromResults returned the first cached object: only Confidence differs " +
			"(1.0 vs 0.2) but the cache key collides — hashCheckResults omits Confidence (audit M-4)")
	}
	if full.DomainScores.AttackSurface == half.DomainScores.AttackSurface {
		t.Fatalf("attack_surface identical across Confidence 1.0 vs 0.2: full=%v half=%v (want 60 vs 92)",
			full.DomainScores.AttackSurface, half.DomainScores.AttackSurface)
	}
	if full.DomainScores.AttackSurface != 60 || half.DomainScores.AttackSurface != 92 {
		t.Fatalf("attack_surface = %v / %v, want 60 / 92 (delta -40 scaled by confidence)",
			full.DomainScores.AttackSurface, half.DomainScores.AttackSurface)
	}
	if full.FinalScore == half.FinalScore {
		t.Fatalf("final score identical across Confidence 1.0 vs 0.2: %v", full.FinalScore)
	}
}

// TestResultsCacheClearedOnReloadWeights is the second red test for audit M-4:
// after a hot reload of the [confidence] section, the same raw check input
// (Confidence=0, resolved from config) must follow the NEW configuration. The
// resolved confidence is not part of the pre-resolution cache key, so only
// clearing resultsCache in ReloadWeights can make the second call recompute.
func TestResultsCacheClearedOnReloadWeights(t *testing.T) {
	a := NewAssessor(confidenceCacheCfg(0.5))

	// Fresh slice each call: AssessFromResults aliases the caller's slice into
	// result.Checks and resolveChecksConfidence mutates it, so reusing one slice
	// would carry the old resolved confidence into the second call.
	fixture := func() []model.CheckResult {
		return []model.CheckResult{
			{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -40},
		}
	}

	old := a.AssessFromResults("cache-reload-host", "cache-reload-host", fixture())
	if old.DomainScores.AttackSurface != 80 {
		t.Fatalf("attack_surface before reload = %v, want 80 (default confidence 0.5 × delta -40)",
			old.DomainScores.AttackSurface)
	}

	a.ReloadWeights(confidenceCacheCfg(1.0))

	fresh := a.AssessFromResults("cache-reload-host", "cache-reload-host", fixture())
	if fresh == old {
		t.Fatalf("after ReloadWeights the same raw input returned the pre-reload cached object: " +
			"resultsCache was not invalidated (audit M-4)")
	}
	if fresh.DomainScores.AttackSurface != 60 {
		t.Fatalf("attack_surface after reload = %v, want 60 (new default confidence 1.0 × delta -40); "+
			"the assessment kept the stale [confidence] configuration", fresh.DomainScores.AttackSurface)
	}
}
