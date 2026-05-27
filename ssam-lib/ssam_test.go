package ssam

import (
	"math"
	"testing"
)

func TestComputeDomainScores(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "business_continuity", Weight: 25},
	}

	checks := []CheckInput{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
		{CheckID: "AS-002", Domain: "attack_surface", Passed: true, Delta: 0},
		{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -20},
	}

	scores := ComputeDomainScores(weights, checks)

	scoreMap := make(map[string]float64)
	for _, s := range scores {
		scoreMap[s.Domain] = s.Score
	}

	if scoreMap["attack_surface"] != 90 {
		t.Errorf("attack_surface: expected 90, got %.0f", scoreMap["attack_surface"])
	}
	if scoreMap["business_continuity"] != 80 {
		t.Errorf("business_continuity: expected 80, got %.0f", scoreMap["business_continuity"])
	}
}

func TestComputeDomainScores_EmptyChecks(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "resilience", Weight: 15},
	}
	scores := ComputeDomainScores(weights, nil)
	if len(scores) != 2 {
		t.Fatalf("expected 2 domain scores for empty checks, got %d", len(scores))
	}
	for _, s := range scores {
		if s.Score != 100 {
			t.Errorf("domain %s: expected 100, got %.0f", s.Domain, s.Score)
		}
	}
}

func TestComputeDomainScores_BelowZero(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 100},
	}
	checks := []CheckInput{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -200},
	}
	scores := ComputeDomainScores(weights, checks)
	if scores[0].Score != 0 {
		t.Errorf("score should floor at 0, got %.0f", scores[0].Score)
	}
}

func TestComputeWeightedSum(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "business_continuity", Weight: 25},
		{Domain: "operation_trust", Weight: 25},
		{Domain: "resilience", Weight: 15},
	}

	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}

	result := ComputeWeightedSum(weights, scores)
	expected := (80*35 + 90*25 + 70*25 + 85*15) / 100.0
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("weighted sum: expected %.2f, got %.2f", expected, result)
	}
}

func TestComputeWeightedSum_ZeroWeight(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 0},
	}
	scores := []DomainScore{{Domain: "attack_surface", Score: 100}}
	result := ComputeWeightedSum(weights, scores)
	if result != 0 {
		t.Errorf("zero weights: expected 0, got %.2f", result)
	}
}

func TestComputeWeightedSum_ExtensionDomain(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "kernel_security", Weight: 10},
	}
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "kernel_security", Score: 50},
	}
	result := ComputeWeightedSum(weights, scores)
	expected := (80*35 + 50*10) / 45.0
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("extension domain: expected %.2f, got %.2f", expected, result)
	}
}

func TestApplyEdgeFactors(t *testing.T) {
	factors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		{ID: "EF-SELINUX", Factor: 0.80, Active: false},
	}

	result := ApplyEdgeFactors(100, factors)
	expected := 100 * 0.85 * 0.75
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("edge factors: expected %.2f, got %.2f", expected, result)
	}
}

func TestApplyEdgeFactors_None(t *testing.T) {
	result := ApplyEdgeFactors(100, nil)
	if result != 100 {
		t.Errorf("no factors: expected 100, got %.2f", result)
	}
}

func TestApplyEdgeFactorsToChecks(t *testing.T) {
	factors := []EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "EF-SYNCOOKIE", Name: "SYN Cookie", Factor: 0.75, TriggerCheck: "RS-005"},
	}

	checks := []CheckInput{
		{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
	}

	result := ApplyEdgeFactorsToChecks(factors, checks, nil)

	factorMap := make(map[string]EdgeFactorResult)
	for _, f := range result {
		factorMap[f.ID] = f
	}

	if !factorMap["EF-002FA"].Active {
		t.Error("EF-002FA should be active when EF-001 fails")
	}
	if factorMap["EF-SYNCOOKIE"].Active {
		t.Error("EF-SYNCOOKIE should not be active when RS-005 passes")
	}
}

func TestApplyEdgeFactorsToChecks_Cascade(t *testing.T) {
	factors := []EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "EF-3FA", Name: "3FA Not Met", Factor: 0.82, TriggerCheck: "EF-002", CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true},
	}

	checks := []CheckInput{
		{CheckID: "EF-001", Domain: "attack_surface", Passed: true, Delta: 0},
		{CheckID: "EF-002", Domain: "attack_surface", Passed: false, Delta: -5},
	}

	result := ApplyEdgeFactorsToChecks(factors, checks, nil)

	factorMap := make(map[string]EdgeFactorResult)
	for _, f := range result {
		factorMap[f.ID] = f
	}

	if !factorMap["EF-002FA"].Active {
		t.Error("EF-002FA should be active via cascade from EF-3FA even when EF-001 passes")
	}
	if factorMap["EF-002FA"].Factor != 0.82 {
		t.Errorf("EF-002FA factor should be 0.82 from cascade, got %.2f", factorMap["EF-002FA"].Factor)
	}
	if factorMap["EF-3FA"].Active {
		t.Error("EF-3FA should not be active in result (CascadeOnly)")
	}
}

func TestApplyEdgeFactorsToChecks_CascadeOnly(t *testing.T) {
	factors := []EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "EF-3FA", Name: "3FA Not Met", Factor: 0.82, TriggerCheck: "EF-002", CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true},
	}

	checks := []CheckInput{
		{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
		{CheckID: "EF-002", Domain: "attack_surface", Passed: false, Delta: -5},
	}

	result := ApplyEdgeFactorsToChecks(factors, checks, nil)

	for _, f := range result {
		switch f.ID {
		case "EF-002FA":
			if !f.Active {
				t.Error("EF-002FA should be active (direct + cascade)")
			}
			if f.Factor != 0.82 {
				t.Errorf("EF-002FA should be overridden to 0.82, got %.2f", f.Factor)
			}
		case "EF-3FA":
			if f.Active {
				t.Error("EF-3FA CascadeOnly should not appear active")
			}
		}
	}
}

func TestSSAMV12Formula_FullPassage(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "business_continuity", Score: 100},
		{Domain: "operation_trust", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := DefaultWeights
	result := SSAMV12Formula(scores, weights, 1.0, 1.0, nil)
	if result != 100 {
		t.Errorf("full passage: expected 100, got %.2f", result)
	}
}

func TestSSAMV12Formula_WithThreatAndSPC(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "business_continuity", Score: 100},
		{Domain: "operation_trust", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := DefaultWeights
	result := SSAMV12Formula(scores, weights, 0.90, 0.80, nil)
	expected := 100 * 0.90 * 0.80
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("threat+spc: expected %.2f, got %.2f", expected, result)
	}
}

func TestSSAMV12Formula_PartialScores(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	factors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
	}
	result := SSAMV12Formula(scores, weights, 1.0, 1.0, factors)
	if result <= 0 || result > 100 {
		t.Errorf("partial: score out of range: %.2f", result)
	}
	expectedRaw := ((80*35 + 90*25 + 70*25 + 85*15) / 100.0) * 0.85
	if math.Abs(result-expectedRaw) > 0.01 {
		t.Errorf("partial: expected %.2f, got %.2f", expectedRaw, result)
	}
}

func TestSimpleWeightedFormula(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
	}
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 50},
		{Domain: "business_continuity", Weight: 50},
	}
	result := SimpleWeightedFormula(scores, weights, 0.5, 2.0, nil)
	expected := (80*50 + 90*50) / 100.0
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("simple_weighted: expected %.2f, got %.2f", expected, result)
	}
}

func TestComputeScore_FullPipeline(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:      "test-host",
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

	if output.HostID != "test-host" {
		t.Errorf("host_id: expected test-host, got %s", output.HostID)
	}
	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("final score out of range: %.2f", output.FinalScore)
	}
	if output.FormulaID != "ssam_v1.2" {
		t.Errorf("formula: expected ssam_v1.2, got %s", output.FormulaID)
	}
	if len(output.DomainScores) != 4 {
		t.Errorf("expected 4 domain scores, got %d", len(output.DomainScores))
	}
}

func TestComputeScore_EdgeFactorTriggering(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:      "test-edge",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
			{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
		},
	}

	output, err := ComputeScore(config, input)
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

func TestComputeScore_CustomFormula(t *testing.T) {
	config := ScoringConfig{
		Weights: []WeightConfig{
			{Domain: "attack_surface", Weight: 100},
		},
		FormulaID: "custom_42",
	}

	_ = RegisterBuiltinFormulas()

	input := AssessmentInput{
		HostID:      "test",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks:      []CheckInput{},
	}

	output, err := ComputeScore(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.FormulaID != "custom_42" {
		t.Errorf("formula: expected custom_42, got %s", output.FormulaID)
	}
}

func TestComputeScore_DefaultedCoeffs(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:    "test-default",
		Threshold: 80,
		Checks:    []CheckInput{},
	}

	output, err := ComputeScore(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.ThreatCoeff != 1.0 {
		t.Errorf("threat_coeff: expected 1.0 default, got %.2f", output.ThreatCoeff)
	}
	if output.SPCScore != 1.0 {
		t.Errorf("spc_score: expected 1.0 default, got %.2f", output.SPCScore)
	}
}

func TestComputeScore_SPCBelowMin(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:    "test-spc-min",
		Threshold: 80,
		SPCScore:  0.30,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: true, Delta: 0},
		},
	}

	output, err := ComputeScore(config, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.SPCScore != 0.60 {
		t.Errorf("spc_score should be floored at 0.60, got %.2f", output.SPCScore)
	}
}

func TestComputeScore_Acceptable(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:    "test-accept",
		Threshold: 80,
		Checks:    []CheckInput{},
	}

	output, _ := ComputeScore(config, input)
	if !output.Acceptable {
		t.Error("empty checks should be acceptable (score=100 >= threshold=80)")
	}
}

func TestValidateInput_EmptyHostID(t *testing.T) {
	err := ValidateInput(AssessmentInput{HostID: "", Threshold: 80})
	if err == nil {
		t.Error("expected error for empty host_id")
	}
}

func TestValidateInput_BadThreshold(t *testing.T) {
	err := ValidateInput(AssessmentInput{HostID: "test", Threshold: 0})
	if err == nil {
		t.Error("expected error for threshold=0")
	}
	err = ValidateInput(AssessmentInput{HostID: "test", Threshold: 101})
	if err == nil {
		t.Error("expected error for threshold=101")
	}
}

func TestValidateInput_EmptyDomain(t *testing.T) {
	input := AssessmentInput{
		HostID:    "test",
		Threshold: 80,
		Checks: []CheckInput{
			{CheckID: "X-001", Domain: "", Passed: true},
		},
	}
	err := ValidateInput(input)
	if err == nil {
		t.Error("expected error for empty domain in checks")
	}
}

func TestValidateInput_Valid(t *testing.T) {
	input := AssessmentInput{
		HostID:    "test",
		Threshold: 80,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: true, Delta: 0},
		},
	}
	err := ValidateInput(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateOutput_BadScore(t *testing.T) {
	err := ValidateOutput(AssessmentOutput{FinalScore: -1})
	if err == nil {
		t.Error("expected error for negative final score")
	}
	err = ValidateOutput(AssessmentOutput{FinalScore: 101})
	if err == nil {
		t.Error("expected error for score > 100")
	}
}

func TestValidateOutput_OK(t *testing.T) {
	err := ValidateOutput(AssessmentOutput{FinalScore: 85})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildWeightMap(t *testing.T) {
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "resilience", Weight: 15},
	}
	wMap := BuildWeightMap(weights)
	if wMap["attack_surface"] != 35 {
		t.Errorf("attack_surface: expected 35, got %.0f", wMap["attack_surface"])
	}
	if wMap["resilience"] != 15 {
		t.Errorf("resilience: expected 15, got %.0f", wMap["resilience"])
	}
}

func TestBuildCustomFactorMap(t *testing.T) {
	factors := []EdgeFactorConfig{
		{ID: "EF-002FA", Factor: 0.85},
		{ID: "EF-SELINUX", Factor: 0.80},
	}
	fMap := BuildCustomFactorMap(factors)
	if fMap["EF-002FA"] != 0.85 {
		t.Errorf("EF-002FA: expected 0.85, got %.2f", fMap["EF-002FA"])
	}
}

func TestRegisterBuiltinFormulas(t *testing.T) {
	formulas := RegisterBuiltinFormulas()
	if _, ok := formulas["ssam_v1.2"]; !ok {
		t.Error("ssam_v1.2 formula not registered")
	}
	if _, ok := formulas["simple_weighted"]; !ok {
		t.Error("simple_weighted formula not registered")
	}
}

func TestSSAMIndependence(t *testing.T) {
	config := DefaultScoringConfig

	input := AssessmentInput{
		HostID:      "standalone-test",
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
		t.Fatalf("standalone ssam compute failed: %v", err)
	}

	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("final score out of valid range: %.2f", output.FinalScore)
	}
	if output.Acceptable == (output.FinalScore >= output.Threshold) {
	} else {
		t.Error("acceptable flag inconsistent with score and threshold")
	}
	if len(output.DomainScores) != 4 {
		t.Errorf("expected 4 domain scores, got %d", len(output.DomainScores))
	}
}

func TestComputeScore_Deterministic(t *testing.T) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:    "test-det",
		Threshold: 80,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -10},
		},
	}

	output1, _ := ComputeScore(config, input)
	output2, _ := ComputeScore(config, input)

	if output1.FinalScore != output2.FinalScore {
		t.Errorf("non-deterministic: %.2f vs %.2f", output1.FinalScore, output2.FinalScore)
	}
}

func BenchmarkComputeScore(b *testing.B) {
	config := DefaultScoringConfig
	input := AssessmentInput{
		HostID:      "bench",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -15},
			{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -10},
			{CheckID: "OT-001", Domain: "operation_trust", Passed: true, Delta: 0},
			{CheckID: "RS-001", Domain: "resilience", Passed: false, Delta: -5},
			{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
		},
	}

	for i := 0; i < b.N; i++ {
		ComputeScore(config, input)
	}
}
