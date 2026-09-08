package prism

import (
	"math"
	"testing"
)

// TestDebtConfidenceWeighted: debt accumulates per-failure |delta|·confidence.
// With confidence 1.0 (or unspecified 0) it matches the legacy sum exactly.
func TestDebtConfidenceWeighted(t *testing.T) {
	now := int64(100 * 86400) // 100 days
	alpha := 1.0

	legacy := []CheckFailure{
		{CheckID: "A", Delta: -10, FailUnix: 0},
		{CheckID: "B", Delta: -20, FailUnix: 0},
	}
	fullDebt := computeDebtRaw(legacy, alpha, now)
	// legacy: 10*100 + 20*100 = 3000
	if math.Abs(fullDebt-3000) > 1e-9 {
		t.Errorf("full-confidence debt = %v, want 3000", fullDebt)
	}

	half := []CheckFailure{
		{CheckID: "A", Delta: -10, FailUnix: 0, Confidence: 1.0},
		{CheckID: "B", Delta: -20, FailUnix: 0, Confidence: 0.5},
	}
	halfDebt := computeDebtRaw(half, alpha, now)
	// 10*100 + 20*0.5*100 = 1000 + 1000 = 2000
	if math.Abs(halfDebt-2000) > 1e-9 {
		t.Errorf("half-confidence debt = %v, want 2000", halfDebt)
	}

	zeroConf := []CheckFailure{
		{CheckID: "A", Delta: -10, FailUnix: 0, Confidence: 0},
	}
	if d := computeDebtRaw(zeroConf, alpha, now); math.Abs(d-1000) > 1e-9 {
		t.Errorf("unspecified confidence must behave as 1.0, got %v", d)
	}
}

// TestEffectiveFailureCount: confidence-weighted failure count gates collapse;
// two half-trusted failures (eff 1.0) must NOT trigger the 2+ collapse.
func TestEffectiveFailureCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DebtNormDays = 1500
	cfg.DebtCap = 0.30
	cfg.CollapseBeta = 1.5
	now := int64(30 * 86400)

	failures := []CheckFailure{
		{CheckID: "A", Delta: -15, FailUnix: 0, Confidence: 0.5},
		{CheckID: "B", Delta: -15, FailUnix: 0, Confidence: 0.5},
	}
	eff := effectiveFailureCount(failures)
	if math.Abs(eff-1.0) > 1e-9 {
		t.Fatalf("effective failure count = %v, want 1.0", eff)
	}
	debt := computeDebtRaw(failures, cfg.DebtAlpha, now)
	mod := computeCollapseModifier(debt, eff, cfg)
	if mod != 0.0 {
		t.Errorf("collapse must stay 0 with effective failure count < 2, got %v", mod)
	}

	// Full-trust pair triggers collapse as before.
	full := []CheckFailure{
		{CheckID: "A", Delta: -15, FailUnix: 0},
		{CheckID: "B", Delta: -15, FailUnix: 0},
	}
	debtFull := computeDebtRaw(full, cfg.DebtAlpha, now)
	modFull := computeCollapseModifier(debtFull, effectiveFailureCount(full), cfg)
	if modFull <= 0 {
		t.Errorf("full-confidence pair should collapse, got %v", modFull)
	}
}

// TestNodeConfidenceCarriedThrough: ComputeDynamicScore echoes node confidence
// and reports effective failures.
func TestNodeConfidenceCarriedThrough(t *testing.T) {
	node := &NodeState{
		HostID:    "h1",
		SSAMScore: 60,
		FailedChecks: []CheckFailure{
			{CheckID: "A", Delta: -10, FailUnix: 0, Confidence: 0.5},
			{CheckID: "B", Delta: -10, FailUnix: 0},
		},
		Confidence: 0.75,
	}
	cfg := DefaultConfig()
	res := ComputeDynamicScore(node, nil, map[string]*NodeState{"h1": node}, cfg, 100*86400)

	if math.Abs(res.Confidence-0.75) > 1e-9 {
		t.Errorf("result confidence = %v, want 0.75", res.Confidence)
	}
	if math.Abs(res.EffectiveFailures-1.5) > 1e-9 {
		t.Errorf("effective failures = %v, want 1.5", res.EffectiveFailures)
	}

	// Default node confidence (unspecified) is 1.0.
	node2 := &NodeState{HostID: "h2", SSAMScore: 90}
	res2 := ComputeDynamicScore(node2, nil, map[string]*NodeState{"h2": node2}, cfg, 100*86400)
	if math.Abs(res2.Confidence-1.0) > 1e-9 {
		t.Errorf("default node confidence = %v, want 1.0", res2.Confidence)
	}
}
