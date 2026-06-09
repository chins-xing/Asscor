package prism

import (
	"math"
	"testing"
)

// ============================================================
// Core Layer — Collapse + RiskVelocity
// ============================================================

func TestCollapseModifier_SingleFailure(t *testing.T) {
	cfg := DefaultConfig()

	// Single failure should NOT produce collapse
	mod := computeCollapseModifier(800.0, 1, cfg)
	if mod != 0.0 {
		t.Errorf("single-failure collapse = %.4f, want 0.0", mod)
	}
}

func TestCollapseModifier_MultiFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CollapseBeta = 1.5

	// 3 concurrent failures with moderate debt → should collapse
	nFailures := 3

	debtRaw := 800.0 // ~30 days with 3 Delta=-15 checks
	mod := computeCollapseModifier(debtRaw, nFailures, cfg)

	if mod <= 0.0 {
		t.Errorf("multi-failure collapse = %.4f, want > 0", mod)
	}
	if mod > 1.0 {
		t.Errorf("collapse modifier = %.4f, should be <= 1.0", mod)
	}
}

func TestCollapseModifier_Extreme(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CollapseBeta = 1.5

	// 10 failures with very high debt → should saturate at 1.0
	nFailures := 10
	debtRaw := 5000.0
	mod := computeCollapseModifier(debtRaw, nFailures, cfg)

	if mod != 1.0 {
		t.Errorf("extreme collapse = %.4f, want 1.0", mod)
	}
}

func TestCollapseModifier_ZeroFailures(t *testing.T) {
	cfg := DefaultConfig()
	mod := computeCollapseModifier(1000.0, 0, cfg)
	if mod != 0.0 {
		t.Errorf("zero-failure collapse = %.4f, want 0.0", mod)
	}
}

func TestCollapseModifier_ZeroDebt(t *testing.T) {
	cfg := DefaultConfig()
	mod := computeCollapseModifier(0.0, 5, cfg)
	if mod != 0.0 {
		t.Errorf("zero-debt collapse = %.4f, want 0.0", mod)
	}
}

func TestComputeRiskVelocity_NilPrior(t *testing.T) {
	v := ComputeRiskVelocity(80.0, nil, 10000)
	if v != 0.0 {
		t.Errorf("velocity with nil prior = %.4f, want 0.0", v)
	}
}

func TestComputeRiskVelocity_Normal(t *testing.T) {
	prior := &RiskSnapshot{
		HostID:     "host1",
		PrismScore: 90.0,
		Timestamp:  0,
	}
	// 1 day later, score dropped to 80
	v := ComputeRiskVelocity(80.0, prior, int64(86400))
	expected := -10.0
	if math.Abs(v-expected) > 1e-6 {
		t.Errorf("velocity = %.4f, want %.4f", v, expected)
	}
}

func TestComputeRiskVelocity_Improving(t *testing.T) {
	prior := &RiskSnapshot{
		HostID:     "host1",
		PrismScore: 70.0,
		Timestamp:  0,
	}
	// 2 days later, score improved to 80
	v := ComputeRiskVelocity(80.0, prior, int64(2*86400))
	expected := 5.0
	if math.Abs(v-expected) > 1e-6 {
		t.Errorf("velocity = %.4f, want %.4f", v, expected)
	}
}

func TestComputeRiskVelocity_StaleTimestamp(t *testing.T) {
	prior := &RiskSnapshot{
		HostID:     "host1",
		PrismScore: 90.0,
		Timestamp:  86400,
	}
	// current time is before prior → return 0
	v := ComputeRiskVelocity(80.0, prior, 0)
	if v != 0.0 {
		t.Errorf("stale velocity = %.4f, want 0.0", v)
	}
}

// ============================================================
// Semantic Layer
// ============================================================

func TestSemanticState_PerfectScore(t *testing.T) {
	cfg := DefaultConfig()
	core := &AssetRiskResult{
		HostID:    "perfect",
		PrismScore: 100.0,
	}
	report := ComputeSemanticState(core, cfg)
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.CurrentState != "Stable" {
		t.Errorf("CurrentState = %s, want Stable", report.CurrentState)
	}
	if report.StableMembership < 0.9 {
		t.Errorf("StableMembership = %.4f, want >= 0.9", report.StableMembership)
	}
	// Collapse membership should be near zero
	if report.CollapseMembership > 0.01 {
		t.Errorf("CollapseMembership = %.4f, want ~0", report.CollapseMembership)
	}
	// State vector should sum to ~1
	sum := 0.0
	for _, v := range report.StateVector {
		sum += v
	}
	if math.Abs(sum-1.0) > 1e-6 {
		t.Errorf("StateVector sum = %.4f, want 1.0", sum)
	}
}

func TestSemanticState_ZeroScore(t *testing.T) {
	cfg := DefaultConfig()
	core := &AssetRiskResult{
		HostID:    "broken",
		PrismScore: 0.0,
	}
	report := ComputeSemanticState(core, cfg)
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.CurrentState != "Collapse" {
		t.Errorf("CurrentState = %s, want Collapse", report.CurrentState)
	}
	if report.CollapseMembership < 0.9 {
		t.Errorf("CollapseMembership = %.4f, want >= 0.9", report.CollapseMembership)
	}
}

func TestSemanticState_DegradedTransition(t *testing.T) {
	cfg := DefaultConfig()

	// Score at threshold boundary: 70% → 70/100=0.70 → exactly at T_degraded
	core := &AssetRiskResult{
		HostID:    "degrading",
		PrismScore: 70.0,
	}
	report := ComputeSemanticState(core, cfg)
	if report == nil {
		t.Fatal("report is nil")
	}
	// At exactly T_degraded (0.70), Degraded membership should be dominant
	if report.CurrentState != "Degraded" {
		t.Errorf("CurrentState = %s, want Degraded (score=%.1f, DegradedThreshold=%.2f)",
			report.CurrentState, core.PrismScore, cfg.DegradedThreshold)
	}
}

func TestSemanticState_UntrustedTransition(t *testing.T) {
	cfg := DefaultConfig()

	core := &AssetRiskResult{
		HostID:    "untrusted",
		PrismScore: 50.0, // exactly at UntrustedThreshold
	}
	report := ComputeSemanticState(core, cfg)
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.UntrustedMembership < report.StableMembership {
		t.Errorf("at score=50, UntrustedMembership (%.4f) should >= StableMembership (%.4f)",
			report.UntrustedMembership, report.StableMembership)
	}
}

func TestSemanticState_FuzzyBoundaries(t *testing.T) {
	cfg := DefaultConfig()

	// Score 60 should be partly Degraded, partly Untrusted
	core := &AssetRiskResult{
		HostID:    "fuzzy",
		PrismScore: 60.0,
	}
	report := ComputeSemanticState(core, cfg)
	if report == nil {
		t.Fatal("report is nil")
	}
	// All memberships should be non-negative
	mems := []float64{report.StableMembership, report.DegradedMembership,
		report.UntrustedMembership, report.CollapseMembership}
	for i, m := range mems {
		if m < 0 {
			t.Errorf("membership[%d] = %.4f, should be >= 0", i, m)
		}
	}
}

func TestSemanticBatch(t *testing.T) {
	cfg := DefaultConfig()
	cores := []*AssetRiskResult{
		{HostID: "a", PrismScore: 95},
		{HostID: "b", PrismScore: 65},
		{HostID: "c", PrismScore: 30},
		nil, // should be skipped
	}
	reports := ComputeSemanticBatch(cores, cfg)
	if len(reports) != 3 {
		t.Errorf("batch len = %d, want 3", len(reports))
	}
	if reports[0].CurrentState != "Stable" {
		t.Errorf("host a state = %s, want Stable", reports[0].CurrentState)
	}
}

func TestSemanticState_DominantStateIsHighest(t *testing.T) {
	cfg := DefaultConfig()

	testCases := []struct {
		score    float64
		expected string
	}{
		{100.0, "Stable"},
		{85.0, "Stable"},
		{75.0, "Degraded"},
		{60.0, "Degraded"},
		{40.0, "Untrusted"},
		{25.0, "Untrusted"},
		{10.0, "Collapse"},
		{0.0, "Collapse"},
	}

	for _, tc := range testCases {
		core := &AssetRiskResult{HostID: "test-host", PrismScore: tc.score}
		report := ComputeSemanticState(core, cfg)
		if report.CurrentState != tc.expected {
			t.Errorf("score=%.0f → state=%s, want %s (vector=%v)",
				tc.score, report.CurrentState, tc.expected, report.StateVector)
		}
	}
}

// ============================================================
// Inference Layer
// ============================================================

func TestMarkovChain_Stationary(t *testing.T) {
	model := DefaultInferenceModel()
	if model.Name() != "MarkovChain" {
		t.Errorf("model name = %s, want MarkovChain", model.Name())
	}

	// Start from pure Stable → should stay mostly Stable
	current := [4]float64{1.0, 0.0, 0.0, 0.0}
	future, conf := model.Predict(current, 7)

	if future[0] < 0.6 {
		t.Errorf("from Stable, 7d StableProb = %.4f, want >= 0.6", future[0])
	}
	if conf <= 0.0 || conf > 1.0 {
		t.Errorf("confidence = %.4f, want (0, 1]", conf)
	}

	// Sum should be ~1
	sum := future[0] + future[1] + future[2] + future[3]
	if math.Abs(sum-1.0) > 1e-6 {
		t.Errorf("future vector sum = %.4f, want 1.0", sum)
	}
}

func TestMarkovChain_CollapseTrap(t *testing.T) {
	model := DefaultInferenceModel()

	// From pure Collapse → should remain mostly Collapse (absorbing state)
	current := [4]float64{0.0, 0.0, 0.0, 1.0}
	future, _ := model.Predict(current, 7)

	if future[3] < 0.7 {
		t.Errorf("from Collapse, 7d CollapseProb = %.4f, want >= 0.7", future[3])
	}
}

func TestMarkovChain_ZeroSteps(t *testing.T) {
	model := DefaultInferenceModel()
	current := [4]float64{0.5, 0.3, 0.15, 0.05}
	future, conf := model.Predict(current, 0)

	if future != current {
		t.Errorf("0-step prediction changed state: %v → %v", current, future)
	}
	if conf != 1.0 {
		t.Errorf("0-step confidence = %.4f, want 1.0", conf)
	}
}

func TestPredictFuture_NilSemantic(t *testing.T) {
	cfg := DefaultConfig()
	result := PredictFuture(nil, nil, cfg)
	if result != nil {
		t.Error("PredictFuture with nil semantic should return nil")
	}
}

func TestPredictFuture_DefaultModel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HorizonDays = 7

	semantic := &SemanticRiskReport{
		HostID:              "test-host",
		StateVector:         [4]float64{0.80, 0.15, 0.04, 0.01},
		CurrentState:        "Stable",
		StableMembership:    0.80,
		DegradedMembership:  0.15,
		UntrustedMembership: 0.04,
		CollapseMembership:  0.01,
	}

	result := PredictFuture(semantic, nil, cfg)
	if result == nil {
		t.Fatal("PredictFuture returned nil")
	}
	if result.HostID != "test-host" {
		t.Errorf("HostID = %s, want test-host", result.HostID)
	}
	if result.HorizonDays != 7 {
		t.Errorf("HorizonDays = %d, want 7", result.HorizonDays)
	}
	// Trend should be "stable" or "degrading" from a stable starting point
	validTrends := map[string]bool{"improving": true, "stable": true, "degrading": true, "collapsing": true}
	if !validTrends[result.Trend] {
		t.Errorf("invalid trend: %s", result.Trend)
	}
	// CollapseRisk should be between 0 and 1
	if result.CollapseRisk < 0 || result.CollapseRisk > 1 {
		t.Errorf("CollapseRisk = %.4f, should be in [0,1]", result.CollapseRisk)
	}
	// Confidence should be in [0,1]
	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("Confidence = %.4f, should be in [0,1]", result.Confidence)
	}
}

func TestPredictFuture_FromCollapse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HorizonDays = 7

	semantic := &SemanticRiskReport{
		HostID:              "collapsing",
		StateVector:         [4]float64{0.0, 0.0, 0.2, 0.8},
		CurrentState:        "Collapse",
		StableMembership:    0.0,
		DegradedMembership:  0.0,
		UntrustedMembership: 0.2,
		CollapseMembership:  0.8,
	}

	result := PredictFuture(semantic, nil, cfg)
	if result == nil {
		t.Fatal("PredictFuture returned nil")
	}
	if result.Trend != "collapsing" {
		t.Errorf("from Collapse, Trend = %s, want collapsing", result.Trend)
	}
	// CollapseRisk should be high
	if result.CollapseRisk < 0.5 {
		t.Errorf("CollapseRisk = %.4f, should be >= 0.5", result.CollapseRisk)
	}
}

func TestPredictFutureBatch(t *testing.T) {
	cfg := DefaultConfig()
	reports := []*SemanticRiskReport{
		{
			HostID:       "a",
			StateVector:  [4]float64{0.9, 0.08, 0.01, 0.01},
			CurrentState: "Stable",
		},
		{
			HostID:       "b",
			StateVector:  [4]float64{0.1, 0.1, 0.4, 0.4},
			CurrentState: "Untrusted",
		},
		nil,
	}

	results := PredictFutureBatch(reports, nil, cfg)
	if len(results) != 2 {
		t.Errorf("batch len = %d, want 2", len(results))
	}
	if results[0].HostID != "a" {
		t.Errorf("first result HostID = %s, want a", results[0].HostID)
	}
}

func TestPredictFuture_HorizonZero(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HorizonDays = 0 // should default to 7

	semantic := &SemanticRiskReport{
		HostID:       "test",
		StateVector:  [4]float64{0.5, 0.3, 0.15, 0.05},
		CurrentState: "Degraded",
	}

	result := PredictFuture(semantic, nil, cfg)
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.HorizonDays != 7 {
		t.Errorf("HorizonDays = %d, want 7 (default)", result.HorizonDays)
	}
}

func TestMatPow_Identity(t *testing.T) {
	mat := MarkovDefaultTransition()
	// T^0 should be identity
	pow := matPow(mat, 0)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i == j && pow[i][j] != 1.0 {
				t.Errorf("identity[%d][%d] = %.4f, want 1.0", i, j, pow[i][j])
			}
			if i != j && pow[i][j] != 0.0 {
				t.Errorf("identity[%d][%d] = %.4f, want 0.0", i, j, pow[i][j])
			}
		}
	}
}

func TestMatPow_One(t *testing.T) {
	mat := MarkovDefaultTransition()
	pow := matPow(mat, 1)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if pow[i][j] != mat[i][j] {
				t.Errorf("T^1[%d][%d] = %.4f, want %.4f", i, j, pow[i][j], mat[i][j])
			}
		}
	}
}

// ============================================================
// Full Pipeline (Core → Semantic → Inference)
// ============================================================

func TestFullPipeline_HealthyNode(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{
		HostID:    "healthy",
		SSAMScore: 95,
	}
	allNodes := map[string]*NodeState{"healthy": node}

	// Core
	core := ComputeDynamicScore(node, nil, allNodes, cfg, 0)
	if core.PrismScore < 90 {
		t.Errorf("healthy PrismScore = %.2f, want >= 90", core.PrismScore)
	}
	if core.CollapseModifier != 0.0 {
		t.Errorf("healthy CollapseModifier = %.4f, want 0.0", core.CollapseModifier)
	}

	// Semantic
	semantic := ComputeSemanticState(&core, cfg)
	if semantic.CurrentState != "Stable" {
		t.Errorf("healthy state = %s, want Stable", semantic.CurrentState)
	}

	// Inference
	future := PredictFuture(semantic, nil, cfg)
	if future.Trend == "collapsing" {
		t.Errorf("healthy trend = %s, should NOT be collapsing", future.Trend)
	}
}

func TestFullPipeline_DamagedNode(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{
		HostID:    "damaged",
		SSAMScore: 85,
		FailedChecks: []CheckFailure{
			{CheckID: "AS-001", Delta: -15, FailUnix: 0},
			{CheckID: "BC-001", Delta: -15, FailUnix: 0},
			{CheckID: "OT-001", Delta: -15, FailUnix: 0},
		},
	}
	allNodes := map[string]*NodeState{
		"damaged": node,
		"ups1":    {HostID: "ups1", SSAMScore: 20},
		"ups2":    {HostID: "ups2", SSAMScore: 30},
	}
	incoming := []EdgeState{
		{Source: "ups1", Target: "damaged", RiskTransmission: 1.0},
		{Source: "ups2", Target: "damaged", RiskTransmission: 1.0},
	}

	nowUnix := int64(30 * 86400) // 30 days of debt

	// Core
	core := ComputeDynamicScore(node, incoming, allNodes, cfg, nowUnix)
	if core.PrismScore >= core.SsamScore {
		t.Errorf("damaged PrismScore (%.2f) should be < SsamScore (%.2f)", core.PrismScore, core.SsamScore)
	}
	if core.CollapseModifier <= 0.0 {
		t.Errorf("damaged CollapseModifier = %.4f, should be > 0 (3 failures)", core.CollapseModifier)
	}
	if core.PropagatedRisk <= 0.0 {
		t.Errorf("damaged PropagatedRisk = %.4f, should be > 0", core.PropagatedRisk)
	}

	// Semantic
	semantic := ComputeSemanticState(&core, cfg)
	// Should NOT be Stable with 3 failures at 30 days + 2 bad upstreams
	if semantic.CurrentState == "Stable" {
		t.Errorf("damaged state should NOT be Stable (score=%.2f)", core.PrismScore)
	}

	// Inference
	future := PredictFuture(semantic, nil, cfg)
	if future.CollapseRisk <= 0.0 {
		t.Errorf("damaged CollapseRisk = %.4f, should be > 0", future.CollapseRisk)
	}
}