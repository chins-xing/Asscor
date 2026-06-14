package prism

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleIR() PrismIR {
	cfg := DefaultConfig()
	node := NodeState{
		HostID:    "prod-web-01",
		SSAMScore: 72.35,
		FailedChecks: []CheckFailure{
			{CheckID: "L3-CE-23", Delta: -15.0, FailUnix: 1717948800},
			{CheckID: "IAM-010", Delta: -8.0, FailUnix: 1717862400},
		},
	}

	edges := []EdgeState{
		{Source: "db-01", Target: "prod-web-01", RiskTransmission: 0.35},
	}

	core := AssetRiskResult{
		HostID:           "prod-web-01",
		SsamScore:        72.35,
		PrismScore:       58.40,
		ExternalRisk:     0.2765,
		PropagatedRisk:   0.35,
		PropPenalty:      0.0933,
		DebtRaw:          345.0,
		DebtPenalty:      0.1867,
		CollapseModifier: 0.0,
		RiskVelocity:     -2.10,
	}

	sem := SemanticRiskReport{
		HostID:              "prod-web-01",
		StableMembership:    0.15,
		DegradedMembership:  0.45,
		UntrustedMembership: 0.30,
		CollapseMembership:  0.10,
		CurrentState:        "Degraded",
		StateVector:         [4]float64{0.15, 0.45, 0.30, 0.10},
	}

	inf := FutureRiskReport{
		HostID:       "prod-web-01",
		HorizonDays:  30,
		StableProb:   0.08,
		DegradedProb: 0.35,
		UntrustedProb: 0.38,
		CollapseProb: 0.19,
		Confidence:   0.85,
		Trend:        "collapsing",
		CollapseRisk: 0.57,
	}

	return NewIR(node, edges, cfg, core, sem, inf, "MarkovChain")
}

func TestNewIR_AllFieldsSet(t *testing.T) {
	ir := sampleIR()

	if ir.PrismIRVersion != "1.0" {
		t.Errorf("prismir_version = %q, want 1.0", ir.PrismIRVersion)
	}
	if ir.Meta.Engine != "prism" {
		t.Errorf("meta.engine = %q, want prism", ir.Meta.Engine)
	}
	if ir.Meta.HorizonDays != 30 {
		t.Errorf("meta.horizon_days = %d, want 30", ir.Meta.HorizonDays)
	}
	if ir.Meta.Timestamp == "" {
		t.Error("meta.timestamp is empty")
	}
	if ir.Input.HostID != "prod-web-01" {
		t.Errorf("input.host_id = %q", ir.Input.HostID)
	}
	if ir.Input.SSAMScore != 72.35 {
		t.Errorf("input.ssam_score = %f", ir.Input.SSAMScore)
	}
	if len(ir.Input.FailedChecks) != 2 {
		t.Errorf("input.failed_checks len = %d, want 2", len(ir.Input.FailedChecks))
	}
	if ir.Input.FailedChecks[0].CheckID != "L3-CE-23" {
		t.Errorf("failed_checks[0].check_id = %q", ir.Input.FailedChecks[0].CheckID)
	}
	if len(ir.Input.PropagationEdges) != 1 {
		t.Errorf("input.propagation_edges len = %d, want 1", len(ir.Input.PropagationEdges))
	}
	if ir.Output.Core.PrismScore != 58.40 {
		t.Errorf("output.core.prism_score = %f", ir.Output.Core.PrismScore)
	}
	if ir.Output.Semantic.DominantState != "Degraded" {
		t.Errorf("output.semantic.dominant_state = %q", ir.Output.Semantic.DominantState)
	}
	if ir.Output.Inference.Trend != "collapsing" {
		t.Errorf("output.inference.trend = %q", ir.Output.Inference.Trend)
	}
	if ir.Output.Inference.Model != "MarkovChain" {
		t.Errorf("output.inference.model = %q", ir.Output.Inference.Model)
	}
}

func TestMarshalJSON_ProducesValidJSON(t *testing.T) {
	ir := sampleIR()

	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("MarshalJSON output is not valid JSON: %v", err)
	}

	// Verify top-level keys
	expectedKeys := []string{"prismir_version", "meta", "input", "output"}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing top-level key: %q", key)
		}
	}

	// Verify output sub-sections
	output, ok := raw["output"].(map[string]interface{})
	if !ok {
		t.Fatal("output is not an object")
	}
	outputKeys := []string{"core", "semantic", "inference"}
	for _, key := range outputKeys {
		if _, ok := output[key]; !ok {
			t.Errorf("missing output key: %q", key)
		}
	}
}

func TestMarshalJSON_IsIndented(t *testing.T) {
	ir := sampleIR()
	data, err := ir.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, "\n") {
		t.Error("MarshalJSON should produce indented output with newlines")
	}
	if !strings.Contains(jsonStr, "  ") {
		t.Error("MarshalJSON should produce indented output with spaces")
	}
}

func TestRoundTrip(t *testing.T) {
	original := sampleIR()

	data, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	restored, err := UnmarshalIR(data)
	if err != nil {
		t.Fatalf("UnmarshalIR failed: %v", err)
	}

	if restored.PrismIRVersion != original.PrismIRVersion {
		t.Errorf("prismir_version mismatch: %q vs %q", restored.PrismIRVersion, original.PrismIRVersion)
	}
	if restored.Input.HostID != original.Input.HostID {
		t.Errorf("host_id mismatch: %q vs %q", restored.Input.HostID, original.Input.HostID)
	}
	if restored.Output.Core.PrismScore != original.Output.Core.PrismScore {
		t.Errorf("prism_score mismatch: %f vs %f", restored.Output.Core.PrismScore, original.Output.Core.PrismScore)
	}
	if restored.Output.Semantic.DominantState != original.Output.Semantic.DominantState {
		t.Errorf("dominant_state mismatch: %q vs %q", restored.Output.Semantic.DominantState, original.Output.Semantic.DominantState)
	}
	if restored.Output.Inference.Trend != original.Output.Inference.Trend {
		t.Errorf("trend mismatch: %q vs %q", restored.Output.Inference.Trend, original.Output.Inference.Trend)
	}
	// Check propagation edges
	if len(restored.Input.PropagationEdges) != len(original.Input.PropagationEdges) {
		t.Errorf("propagation_edges count mismatch: %d vs %d", len(restored.Input.PropagationEdges), len(original.Input.PropagationEdges))
	}
}

func TestValidate_ValidIR(t *testing.T) {
	ir := sampleIR()
	if err := ir.Validate(); err != nil {
		t.Errorf("Validate() should pass for valid IR, got: %v", err)
	}
}

func TestValidate_MissingVersion(t *testing.T) {
	ir := sampleIR()
	ir.PrismIRVersion = ""
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for empty prismir_version")
	}
}

func TestValidate_MissingHostID(t *testing.T) {
	ir := sampleIR()
	ir.Input.HostID = ""
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for empty host_id")
	}
}

func TestValidate_InvalidSSAMScore(t *testing.T) {
	ir := sampleIR()
	ir.Input.SSAMScore = 150.0
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for ssam_score > 100")
	}

	ir.Input.SSAMScore = -10.0
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for ssam_score < 0")
	}
}

func TestValidate_InvalidPrismScore(t *testing.T) {
	ir := sampleIR()
	ir.Output.Core.PrismScore = 150.0
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for prism_score > 100")
	}

	ir.Output.Core.PrismScore = -10.0
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for prism_score < 0")
	}
}

func TestValidate_InvalidDominantState(t *testing.T) {
	ir := sampleIR()
	ir.Output.Semantic.DominantState = "Unknown"
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for invalid dominant_state")
	}
}

func TestValidate_InvalidTrend(t *testing.T) {
	ir := sampleIR()
	ir.Output.Inference.Trend = "unknown"
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for invalid trend")
	}
}

func TestValidate_MissingModel(t *testing.T) {
	ir := sampleIR()
	ir.Output.Inference.Model = ""
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for empty model")
	}
}

func TestValidate_ZeroHorizonDays(t *testing.T) {
	ir := sampleIR()
	ir.Meta.HorizonDays = 0
	if err := ir.Validate(); err == nil {
		t.Error("Validate() should fail for horizon_days = 0")
	}
}

func TestNewIR_NoFailedChecks(t *testing.T) {
	cfg := DefaultConfig()
	node := NodeState{
		HostID:       "clean-node",
		SSAMScore:    90.0,
		FailedChecks: nil,
	}

	core := AssetRiskResult{
		HostID:     "clean-node",
		PrismScore: 90.0,
	}

	sem := SemanticRiskReport{
		HostID:       "clean-node",
		CurrentState: "Stable",
		StateVector:  [4]float64{0.9, 0.07, 0.02, 0.01},
	}

	inf := FutureRiskReport{
		HostID:      "clean-node",
		HorizonDays: 30,
		Trend:       "stable",
		Confidence:  0.95,
	}

	ir := NewIR(node, nil, cfg, core, sem, inf, "MarkovChain")

	if ir.Input.FailedChecks == nil {
		t.Error("failed_checks should be nil slice, not nil")
	}
	if len(ir.Input.FailedChecks) != 0 {
		t.Errorf("failed_checks len = %d, want 0", len(ir.Input.FailedChecks))
	}
	if ir.Input.PropagationEdges == nil {
		t.Error("propagation_edges should be nil slice, not nil")
	}
}

func TestNewIR_NoEdges(t *testing.T) {
	cfg := DefaultConfig()
	node := NodeState{HostID: "solo", SSAMScore: 80.0}
	core := AssetRiskResult{HostID: "solo", PrismScore: 80.0}
	sem := SemanticRiskReport{HostID: "solo", CurrentState: "Stable", StateVector: [4]float64{0.8, 0.1, 0.07, 0.03}}
	inf := FutureRiskReport{HostID: "solo", HorizonDays: 30, Trend: "improving", Confidence: 0.9}

	ir := NewIR(node, nil, cfg, core, sem, inf, "MarkovChain")

	if ir.Input.PropagationEdges == nil {
		t.Error("propagation_edges should be nil slice")
	}
	if len(ir.Input.PropagationEdges) != 0 {
		t.Errorf("propagation_edges len = %d, want 0", len(ir.Input.PropagationEdges))
	}
}

func TestUnmarshalIR_InvalidJSON(t *testing.T) {
	_, err := UnmarshalIR([]byte(`{invalid`))
	if err == nil {
		t.Error("UnmarshalIR should fail for invalid JSON")
	}
}

func TestUnmarshalIR_EmptyJSON(t *testing.T) {
	_, err := UnmarshalIR([]byte(`{}`))
	if err != nil {
		t.Errorf("UnmarshalIR should succeed for empty object, got: %v", err)
	}
}

func TestOutputContainsAllStates(t *testing.T) {
	ir := sampleIR()

	// Verify all four states are present in semantic
	states := map[string]float64{
		"Stable":    ir.Output.Semantic.Membership.Stable,
		"Degraded":  ir.Output.Semantic.Membership.Degraded,
		"Untrusted": ir.Output.Semantic.Membership.Untrusted,
		"Collapse":  ir.Output.Semantic.Membership.Collapse,
	}

	for name, val := range states {
		if val < 0 || val > 1 {
			t.Errorf("membership.%s = %f, must be in [0,1]", name, val)
		}
	}
}

func TestFutureVectorMatchesHorizon(t *testing.T) {
	ir := sampleIR()

	if ir.Meta.HorizonDays != ir.Output.Inference.HorizonDays {
		t.Errorf("meta.horizon_days = %d, but output.inference.horizon_days = %d",
			ir.Meta.HorizonDays, ir.Output.Inference.HorizonDays)
	}
}

func TestCollapseRiskComputation(t *testing.T) {
	ir := sampleIR()

	expected := ir.Output.Inference.FutureVector[2] + ir.Output.Inference.FutureVector[3] // Untrusted + Collapse
	diff := ir.Output.Inference.CollapseRisk - expected
	if diff < 0 {
		diff = -diff
	}
	if diff > 0.0001 {
		t.Errorf("collapse_risk = %f, but future_vector[2]+[3] = %f (diff=%f)", ir.Output.Inference.CollapseRisk, expected, diff)
	}
}