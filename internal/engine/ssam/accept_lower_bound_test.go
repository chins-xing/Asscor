//go:build engine

package ssam

import (
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// lowerBoundDecisionCfg builds the B-2 fixture: threshold 60, one half-trusted
// -120 failure in attack_surface.
//
//	domain score = 100 − 120·0.5 = 40
//	domain σ     = 120·√(0.5·0.5) = 60
//	final σ      = 0.5·60 = 30
//	final score  = 0.5·40 + 0.3·100 + 0.2·100 = 70
//	lower95      = 70 − 1.96·30 = 11.2  (< threshold 60)
//
// With accept_by_lower_bound=false the point estimate 70 ≥ 60 accepts; with
// true the conservative lower bound 11.2 < 60 must reject.
func lowerBoundDecisionCfg(acceptByLowerBound bool) *config.Config {
	cfg := confidenceEnabledCfg()
	cfg.Threshold = 60
	cfg.Confidence.AcceptByLowerBound = acceptByLowerBound
	return cfg
}

func lowerBoundChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -120, Confidence: 0.5},
	}
}

// TestAcceptByLowerBoundPluginPath covers B-2 on the plugin (ssam) engine:
// the switch was parsed but never consumed, so both runs used to accept.
func TestAcceptByLowerBoundPluginPath(t *testing.T) {
	off := pluginScored(t, lowerBoundDecisionCfg(false), lowerBoundChecks())
	if off.ScoreLower95 >= off.Threshold {
		t.Fatalf("fixture precondition: lower95 %v must be below threshold %v", off.ScoreLower95, off.Threshold)
	}
	if !off.Acceptable {
		t.Errorf("accept_by_lower_bound=false must accept on the point estimate (score %v ≥ %v), got acceptable=false",
			off.FinalScore, off.Threshold)
	}

	on := pluginScored(t, lowerBoundDecisionCfg(true), lowerBoundChecks())
	if on.Acceptable {
		t.Errorf("accept_by_lower_bound=true must reject: lower95 %v < threshold %v (point estimate %v)",
			on.ScoreLower95, on.Threshold, on.FinalScore)
	}
}

// TestAcceptByLowerBoundLegacyPath covers B-2 on the legacy
// DynamicScoringEngine path (which only got a Lower95 in I-1).
func TestAcceptByLowerBoundLegacyPath(t *testing.T) {
	off := legacyScored(t, lowerBoundDecisionCfg(false), "legacy-accept-off", lowerBoundChecks())
	if off.ScoreLower95 >= off.Threshold {
		t.Fatalf("fixture precondition: lower95 %v must be below threshold %v", off.ScoreLower95, off.Threshold)
	}
	if !off.Acceptable {
		t.Errorf("accept_by_lower_bound=false must accept on the point estimate (score %v ≥ %v), got acceptable=false",
			off.FinalScore, off.Threshold)
	}

	on := legacyScored(t, lowerBoundDecisionCfg(true), "legacy-accept-on", lowerBoundChecks())
	if on.Acceptable {
		t.Errorf("accept_by_lower_bound=true must reject: lower95 %v < threshold %v (point estimate %v)",
			on.ScoreLower95, on.Threshold, on.FinalScore)
	}
}
