package ssam

import (
	"math"
	"testing"
)

func TestSSAMV20Formula_FullPassage(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "business_continuity", Score: 100},
		{Domain: "operation_trust", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := DefaultWeights
	riskCtx := RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 1.0}
	result := SSAMV20Formula(scores, weights, riskCtx, nil)

	if result.Total != 100 {
		t.Errorf("full passage: expected 100, got %.2f", result.Total)
	}
	if result.Layers.Intrinsic.Coeff != 1.0 {
		t.Errorf("intrinsic layer: expected 1.0, got %.2f", result.Layers.Intrinsic.Coeff)
	}
	if result.Layers.Exposure.Coeff != 1.0 {
		t.Errorf("exposure layer: expected 1.0, got %.2f", result.Layers.Exposure.Coeff)
	}
	if result.Layers.Threat.Coeff != 1.0 {
		t.Errorf("threat layer: expected 1.0, got %.2f", result.Layers.Threat.Coeff)
	}
}

func TestSSAMV20Formula_LayerSeparation(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	riskCtx := RiskContext{Intrinsic: 1.0, Exposure: 0.70, Threat: 0.90}
	result := SSAMV20Formula(scores, weights, riskCtx, nil)

	if result.Layers.Exposure.Coeff != 0.70 {
		t.Errorf("exposure layer: expected 0.70, got %.2f", result.Layers.Exposure.Coeff)
	}
	if result.Layers.Threat.Coeff != 0.90 {
		t.Errorf("threat layer: expected 0.90, got %.2f", result.Layers.Threat.Coeff)
	}

	weightedSum := (80*35 + 90*25 + 70*25 + 85*15) / 100.0
	intrinsicRaw := weightedSum
	expectedTotal := math.Round(intrinsicRaw*0.70*0.90*100) / 100

	if math.Abs(result.Total-expectedTotal) > 0.02 {
		t.Errorf("total: expected %.2f, got %.2f", expectedTotal, result.Total)
	}
}

func TestSSAMV20Formula_DefaultedRiskContext(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 50},
		{Domain: "resilience", Weight: 50},
	}
	riskCtx := RiskContext{Intrinsic: 0, Exposure: 0, Threat: 0}
	result := SSAMV20Formula(scores, weights, riskCtx, nil)

	if result.Total != 100 {
		t.Errorf("defaulted risk: expected 100, got %.2f", result.Total)
	}
	if result.Layers.Exposure.Coeff != 1.0 {
		t.Errorf("defaulted exposure: expected 1.0, got %.2f", result.Layers.Exposure.Coeff)
	}
	if result.Layers.Threat.Coeff != 1.0 {
		t.Errorf("defaulted threat: expected 1.0, got %.2f", result.Layers.Threat.Coeff)
	}
}

func TestSSAMV20Formula_WithEdgeFactors(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 50},
		{Domain: "resilience", Weight: 50},
	}
	riskCtx := RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 1.0}
	factors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SELINUX", Factor: 0.80, Active: false},
	}
	result := SSAMV20Formula(scores, weights, riskCtx, factors)

	expectedTotal := math.Round(100*0.85*100) / 100
	if result.Total != expectedTotal {
		t.Errorf("edge factors: expected %.2f, got %.2f", expectedTotal, result.Total)
	}

	hasFactorContributor := false
	for _, c := range result.Layers.Intrinsic.Contributors {
		if c == "edge_factor:EF-002FA" {
			hasFactorContributor = true
		}
	}
	if !hasFactorContributor {
		t.Error("Intrinsic layer should list EF-002FA as contributor")
	}
}

func TestSSAMV20Formula_Contributors(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "resilience", Score: 90},
	}
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 50},
		{Domain: "resilience", Weight: 50},
	}
	riskCtx := RiskContext{Intrinsic: 1.0, Exposure: 0.70, Threat: 0.90}
	result := SSAMV20Formula(scores, weights, riskCtx, nil)

	if result.Layers.Exposure.Contributors[0] != "exposure_coefficient" {
		t.Errorf("exposure contributors: expected [exposure_coefficient], got %v", result.Layers.Exposure.Contributors)
	}
	if result.Layers.Threat.Contributors[0] != "threat_coefficient" {
		t.Errorf("threat contributors: expected [threat_coefficient], got %v", result.Layers.Threat.Contributors)
	}
}

func TestComputeScoreV2_FullPipeline(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "test-v2",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.70,
			Threat:    0.90,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -10},
			{CheckID: "OT-001", Domain: "operation_trust", Passed: true, Delta: 0},
			{CheckID: "RS-001", Domain: "resilience", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.HostID != "test-v2" {
		t.Errorf("host_id: expected test-v2, got %s", output.HostID)
	}
	if output.FinalScore.Total <= 0 || output.FinalScore.Total > 100 {
		t.Errorf("final score out of range: %.2f", output.FinalScore.Total)
	}
	if output.FormulaID != "ssam_v2.0" {
		t.Errorf("formula: expected ssam_v2.0, got %s", output.FormulaID)
	}
	if len(output.DomainScores) != 4 {
		t.Errorf("expected 4 domain scores, got %d", len(output.DomainScores))
	}
}

func TestComputeScoreV2_DefaultRiskContext(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:      "test-v2-default",
		Threshold:   80,
		RiskContext: RiskContext{},
		Checks:      []CheckInput{},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.FinalScore.Total != 100 {
		t.Errorf("default risk: expected 100, got %.2f", output.FinalScore.Total)
	}
	if output.FinalScore.Layers.Exposure.Coeff != 1.0 {
		t.Errorf("defaulted exposure should be 1.0, got %.2f", output.FinalScore.Layers.Exposure.Coeff)
	}
}

func TestComputeScoreV2_EdgeFactorTriggering(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "test-v2-edge",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  1.0,
			Threat:    1.0,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
			{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	edgeActive := false
	for _, ef := range output.EdgeFactors {
		if ef.ID == "EF-002FA" && ef.Active {
			edgeActive = true
		}
	}
	if !edgeActive {
		t.Error("EF-002FA should be active since EF-001 check failed")
	}
}

func TestComputeScore_BackwardCompat_V1_2(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v1.2"
	input := AssessmentInput{
		HostID:      "compat-test",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -10},
			{CheckID: "OT-001", Domain: "operation_trust", Passed: true, Delta: 0},
			{CheckID: "RS-001", Domain: "resilience", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScore(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("score out of range: %.2f", output.FinalScore)
	}
	if output.FormulaID != "ssam_v1.2" {
		t.Errorf("formula: expected ssam_v1.2, got %s", output.FormulaID)
	}
}

func TestComputeScore_BackwardCompat_V2_via_V1API(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInput{
		HostID:      "compat-v2-via-v1",
		Threshold:   80,
		ThreatCoeff: 0.95,
		SPCScore:    0.88,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
		},
	}

	output, err := ComputeScore(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("score out of range: %.2f", output.FinalScore)
	}
	if output.FormulaID != "ssam_v2.0" {
		t.Errorf("formula: expected ssam_v2.0, got %s", output.FormulaID)
	}
}

func TestComputeScoreV2_SPCCoeffFloored(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "test-spc-floor",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.30,
			Threat:    0.45,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: true, Delta: 0},
		},
	}

	output, err := ComputeScoreV2(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.FinalScore.Layers.Exposure.Coeff != 0.60 {
		t.Errorf("exposure should be floored at 0.60, got %.2f", output.FinalScore.Layers.Exposure.Coeff)
	}
	if output.FinalScore.Layers.Threat.Coeff != 0.60 {
		t.Errorf("threat should be floored at 0.60, got %.2f", output.FinalScore.Layers.Threat.Coeff)
	}
}

func TestComputeScoreV2_Deterministic(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "det-v2",
		Threshold: 80,
		RiskContext: RiskContext{
			Intrinsic: 1.0,
			Exposure:  0.75,
			Threat:    0.85,
		},
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -10},
		},
	}

	output1, _ := ComputeScoreV2(config, input)
	output2, _ := ComputeScoreV2(config, input)

	if output1.FinalScore.Total != output2.FinalScore.Total {
		t.Errorf("non-deterministic: %.2f vs %.2f", output1.FinalScore.Total, output2.FinalScore.Total)
	}
}

func TestComputeScoreV2_ValidateInput_EmptyHostID(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInputV2{HostID: "", Threshold: 80}
	_, err := ComputeScoreV2(config, input)
	if err == nil {
		t.Error("expected error for empty host_id")
	}
}

func TestComputeScoreV2_ValidateInput_BadThreshold(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInputV2{HostID: "test", Threshold: 0}
	_, err := ComputeScoreV2(config, input)
	if err == nil {
		t.Error("expected error for threshold=0")
	}
}

func TestComputeScoreV2_Acceptable(t *testing.T) {
	config := DefaultScoringConfig
	config.FormulaID = "ssam_v2.0"
	input := AssessmentInputV2{
		HostID:    "test-v2-accept",
		Threshold: 80,
		Checks:    []CheckInput{},
	}

	output, _ := ComputeScoreV2(config, input)
	if !output.Acceptable {
		t.Error("empty checks should be acceptable (score=100 >= threshold=80)")
	}
}
