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

// TestNodeConfidenceCapsInferenceConfidence locks I-7: NodeState.Confidence
// used to be only echoed into AssetRiskResult.Confidence. The inference
// confidence must consume it (design §2.5: inference confidence =
// f(model confidence, input trust)) WITHOUT touching any risk number.
func TestNodeConfidenceCapsInferenceConfidence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HorizonDays = 1
	now := int64(100 * 86400)

	makeCore := func(nodeConf float64) AssetRiskResult {
		node := &NodeState{
			HostID:     "h1",
			SSAMScore:  90,
			Confidence: nodeConf,
		}
		return ComputeDynamicScore(node, nil, map[string]*NodeState{"h1": node}, cfg, now)
	}

	full := makeCore(1.0)
	low := makeCore(0.5)

	semFull := ComputeSemanticState(&full, cfg)
	semLow := ComputeSemanticState(&low, cfg)

	futureFull := PredictFuture(semFull, nil, cfg)
	futureLow := PredictFuture(semLow, nil, cfg)
	if futureFull == nil || futureLow == nil {
		t.Fatal("PredictFuture returned nil")
	}

	if futureFull.Confidence <= 0.5 {
		t.Fatalf("fixture precondition: model confidence must exceed 0.5, got %v", futureFull.Confidence)
	}
	if futureLow.Confidence >= futureFull.Confidence {
		t.Errorf("inference confidence must drop with node confidence 0.5: full=%v low=%v",
			futureFull.Confidence, futureLow.Confidence)
	}
	want := math.Min(futureFull.Confidence, 0.5)
	if math.Abs(futureLow.Confidence-want) > 1e-9 {
		t.Errorf("inference confidence = %v, want min(model %v, node 0.5) = %v",
			futureLow.Confidence, futureFull.Confidence, want)
	}

	// Hard requirement: the risk values are unchanged (I-7 must not move
	// direction-② data).
	if futureLow.Trend != futureFull.Trend {
		t.Errorf("Trend changed: %q vs %q", futureLow.Trend, futureFull.Trend)
	}
	if futureLow.CollapseRisk != futureFull.CollapseRisk {
		t.Errorf("CollapseRisk changed: %v vs %v", futureLow.CollapseRisk, futureFull.CollapseRisk)
	}
	if futureLow.StableProb != futureFull.StableProb ||
		futureLow.DegradedProb != futureFull.DegradedProb ||
		futureLow.UntrustedProb != futureFull.UntrustedProb ||
		futureLow.CollapseProb != futureFull.CollapseProb {
		t.Errorf("future state distribution changed: %+v vs %+v", futureLow, futureFull)
	}
	if low.PrismScore != full.PrismScore || low.DebtPenalty != full.DebtPenalty ||
		low.PropPenalty != full.PropPenalty || low.CollapseModifier != full.CollapseModifier {
		t.Errorf("core risk values changed by node confidence: low=%+v full=%+v", low, full)
	}
}
