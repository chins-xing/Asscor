package prism

import (
	"math"
	"testing"
)

func TestExternalRisk(t *testing.T) {
	tests := []struct {
		ssamScore float64
		expected  float64
	}{
		{100, 0.0},
		{50, 0.5},
		{0, 1.0},
		{75, 0.25},
	}

	for _, tt := range tests {
		got := externalRisk(tt.ssamScore)
		if math.Abs(got-tt.expected) > 1e-9 {
			t.Errorf("externalRisk(%.0f) = %f, want %f", tt.ssamScore, got, tt.expected)
		}
	}
}

func TestComputeSpillover(t *testing.T) {
	got := computeSpillover(0.5, 0.5)
	if math.Abs(got-0.25) > 1e-9 {
		t.Errorf("computeSpillover(0.5, 0.5) = %f, want 0.25", got)
	}
}

func TestOrthogonality(t *testing.T) {
	cfg := DefaultConfig()

	upstream := &NodeState{HostID: "upstream", SSAMScore: 20}
	downstream := &NodeState{HostID: "downstream", SSAMScore: 80}
	allNodes := map[string]*NodeState{
		"upstream":   upstream,
		"downstream": downstream,
	}
	incoming := []EdgeState{
		{Source: "upstream", Target: "downstream", RiskTransmission: 1.0},
	}

	r1 := ComputeDynamicScore(downstream, incoming, allNodes, cfg, 0)

	sameSSAM := &NodeState{HostID: "upstream", SSAMScore: 20}
	r2 := ComputeDynamicScore(sameSSAM, incoming, allNodes, cfg, 0)

	if math.Abs(r2.PropPenalty-r1.PropPenalty) > 1e-9 {
		t.Error("orthogonality violation: PropPenalty is infected by this node's SSAM")
	}

	ratio1 := r1.PrismScore / r1.SsamScore
	ratio2 := r2.PrismScore / r2.SsamScore
	if math.Abs(ratio1-ratio2) > 1e-9 {
		t.Errorf("orthogonality: ratio1=%.4f, ratio2=%.4f — both should equal (1-PropPenalty)=%.4f",
			ratio1, ratio2, 1.0-r1.PropPenalty)
	}
}

func TestComputeDynamicScore_NoRisk(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{HostID: "perfect", SSAMScore: 100}
	allNodes := map[string]*NodeState{"perfect": node}

	result := ComputeDynamicScore(node, nil, allNodes, cfg, 0)

	if result.PrismScore != 100.0 {
		t.Errorf("PrismScore = %f, want 100.0", result.PrismScore)
	}
	if result.PropPenalty != 0.0 {
		t.Errorf("PropPenalty = %f, want 0.0", result.PropPenalty)
	}
	if result.DebtPenalty != 0.0 {
		t.Errorf("DebtPenalty = %f, want 0.0", result.DebtPenalty)
	}
}

func TestComputeDynamicScore_WithPropagation(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{HostID: "downstream", SSAMScore: 90}
	allNodes := map[string]*NodeState{
		"downstream": node,
		"upstream":   {HostID: "upstream", SSAMScore: 50},
	}
	incoming := []EdgeState{
		{Source: "upstream", Target: "downstream", RiskTransmission: 0.5},
	}

	result := ComputeDynamicScore(node, incoming, allNodes, cfg, 0)

	expectedSpill := 0.5 * 0.5
	if math.Abs(result.PropagatedRisk-expectedSpill) > 1e-9 {
		t.Errorf("PropagatedRisk = %f, want %f", result.PropagatedRisk, expectedSpill)
	}

	if result.PropPenalty > 0 {
		if result.PrismScore >= 90.0 {
			t.Errorf("PrismScore = %f, should be < 90 with propagation", result.PrismScore)
		}
	}
}

func TestComputeDynamicScore_WithDebt(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{
		HostID: "host",
		SSAMScore: 90,
		FailedChecks: []CheckFailure{
			{CheckID: "AS-001", Delta: -15, FailUnix: 0},
		},
	}
	allNodes := map[string]*NodeState{"host": node}

	nowUnix := int64(30 * 86400)
	result := ComputeDynamicScore(node, nil, allNodes, cfg, nowUnix)

	expectedDebtRaw := 15.0 * math.Pow(30.0, 1.2)
	if math.Abs(result.DebtRaw-expectedDebtRaw) > 1.0 {
		t.Errorf("DebtRaw = %f, want ~%f", result.DebtRaw, expectedDebtRaw)
	}
	if result.DebtPenalty <= 0 {
		t.Error("DebtPenalty should be > 0 for 30-day debt")
	}
	if result.PrismScore >= 90.0 {
		t.Errorf("PrismScore = %f, should be < 90 with debt", result.PrismScore)
	}
}

func TestComputeDynamicScore_FloorIsZero(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{HostID: "host", SSAMScore: 5}
	allNodes := map[string]*NodeState{
		"host":     node,
		"upstream": {HostID: "upstream", SSAMScore: 0},
	}
	incoming := []EdgeState{
		{Source: "upstream", Target: "host", RiskTransmission: 1.0},
	}

	result := ComputeDynamicScore(node, incoming, allNodes, cfg, 0)
	if result.PrismScore < 0.0 {
		t.Errorf("PrismScore = %f, should be >= 0", result.PrismScore)
	}
}

func TestDebtScaleIsReasonable(t *testing.T) {
	cfg := DefaultConfig()

	node7d := &NodeState{
		HostID:    "host",
		SSAMScore: 100,
		FailedChecks: []CheckFailure{
			{CheckID: "AS-001", Delta: -15, FailUnix: 0},
		},
	}
	allNodes := map[string]*NodeState{"host": node7d}

	r2d := ComputeDynamicScore(node7d, nil, allNodes, cfg, int64(2*86400))
	r7d := ComputeDynamicScore(node7d, nil, allNodes, cfg, int64(7*86400))
	r30d := ComputeDynamicScore(node7d, nil, allNodes, cfg, int64(30*86400))

	if r7d.PrismScore <= r30d.PrismScore {
		t.Errorf("7d PrismScore (%.2f) should be > 30d PrismScore (%.2f)", r7d.PrismScore, r30d.PrismScore)
	}
	if r2d.PrismScore <= r7d.PrismScore {
		t.Errorf("2d PrismScore (%.2f) should be > 7d PrismScore (%.2f)", r2d.PrismScore, r7d.PrismScore)
	}

	if r30d.PrismScore < 70 {
		t.Errorf("30d PrismScore = %.2f, expected >= 70 (debt capped at %.0f%%)", r30d.PrismScore, cfg.DebtCap*100)
	}
}

func TestPropagationPathDecay(t *testing.T) {
	nodes := map[string]*NodeState{
		"a": {HostID: "a", SSAMScore: 50},
		"b": {HostID: "b", SSAMScore: 50},
		"c": {HostID: "c", SSAMScore: 50},
		"d": {HostID: "d", SSAMScore: 50},
		"e": {HostID: "e", SSAMScore: 50},
	}

	edges := []EdgeState{
		{Source: "a", Target: "b", RiskTransmission: 1.0},
		{Source: "b", Target: "c", RiskTransmission: 1.0},
		{Source: "c", Target: "d", RiskTransmission: 1.0},
		{Source: "d", Target: "e", RiskTransmission: 1.0},
	}

	cfg := DefaultConfig()
	results := FindPropagationPaths("a", "e", nodes, edges, cfg, 0, 5, 1)

	if len(results) == 0 {
		t.Fatal("expected a path from a to e")
	}

	r := results[0]
	totalWithoutDecay := 0.5 * 1.0 * 4
	if r.CumulativeRisk >= totalWithoutDecay {
		t.Errorf("CumulativeRisk with decay = %f, should be < %f (no-decay total)", r.CumulativeRisk, totalWithoutDecay)
	}
}

func TestScoreFloor(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PropCap = 1.0
	cfg.DebtCap = 1.0
	cfg.ScoreFloor = 0.40

	node := &NodeState{
		HostID:    "host",
		SSAMScore: 100,
		FailedChecks: []CheckFailure{
			{CheckID: "AS-001", Delta: -90, FailUnix: 0},
		},
	}
	allNodes := map[string]*NodeState{
		"host":     node,
		"upstream": {HostID: "upstream", SSAMScore: 0},
	}
	incoming := []EdgeState{
		{Source: "upstream", Target: "host", RiskTransmission: 1.0},
	}

	nowUnix := int64(365 * 86400)
	result := ComputeDynamicScore(node, incoming, allNodes, cfg, nowUnix)

	minAllowed := 100.0 * cfg.ScoreFloor
	if result.PrismScore < minAllowed {
		t.Errorf("PrismScore = %.2f, should be >= floor %.2f", result.PrismScore, minAllowed)
	}
}

func TestScoreFloorDefaultDoesNotFloorHealthyNode(t *testing.T) {
	cfg := DefaultConfig()
	node := &NodeState{
		HostID:    "host",
		SSAMScore: 90,
		FailedChecks: []CheckFailure{
			{CheckID: "AS-001", Delta: -15, FailUnix: 0},
		},
	}
	allNodes := map[string]*NodeState{"host": node}

	result := ComputeDynamicScore(node, nil, allNodes, cfg, 0)

	if result.PrismScore < 0.85*result.SsamScore {
		t.Errorf("healthy node PrismScore = %.2f, expected >= %.2f", result.PrismScore, 0.85*result.SsamScore)
	}
}
