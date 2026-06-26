package ssam

import (
	"context"
	"math"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("engine must not be nil")
	}
	if e.GetFormula() != "ssam_v1.2" {
		t.Fatalf("expected default formula ssam_v1.2, got %s", e.GetFormula())
	}
}

func TestComputeDomainScores(t *testing.T) {
	e := NewEngine()
	e.SetWeights([]WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "business_continuity", Weight: 25},
	})

	checks := []CheckInput{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
		{CheckID: "AS-002", Domain: "attack_surface", Passed: true, Delta: 0},
		{CheckID: "BC-001", Domain: "business_continuity", Passed: false, Delta: -20},
	}

	scores := e.ComputeDomainScores(checks)

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

func TestComputeWeightedSum(t *testing.T) {
	e := NewEngine()
	e.SetWeights([]WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "business_continuity", Weight: 25},
		{Domain: "operation_trust", Weight: 25},
		{Domain: "resilience", Weight: 15},
	})

	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}

	result := e.ComputeWeightedSum(scores)
	expected := (80*35 + 90*25 + 70*25 + 85*15) / 100.0
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("weighted sum: expected %.2f, got %.2f", expected, result)
	}
}

func TestApplyEdgeFactors(t *testing.T) {
	e := NewEngine()

	factors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		{ID: "EF-SELINUX", Factor: 0.80, Active: false},
	}

	result := e.ApplyEdgeFactors(100, factors)
	expected := 100 * 0.85 * 0.75
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("edge factors: expected %.2f, got %.2f", expected, result)
	}
}

func TestComputeScore_SSAMV12(t *testing.T) {
	e := NewEngine()
	e.SetWeights([]WeightConfig{
		{Domain: "attack_surface", Weight: 35},
		{Domain: "business_continuity", Weight: 25},
		{Domain: "operation_trust", Weight: 25},
		{Domain: "resilience", Weight: 15},
	})
	e.SetEdgeFactors([]EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
	})

	input := &AssessmentInput{
		HostID:      "host-001",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks: []CheckInput{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
			{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
		},
	}

	output, err := e.ComputeScore(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.HostID != "host-001" {
		t.Errorf("host_id: expected host-001, got %s", output.HostID)
	}
	if output.FormulaID != "ssam_v1.2" {
		t.Errorf("formula: expected ssam_v1.2, got %s", output.FormulaID)
	}
	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("final score out of range: %.2f", output.FinalScore)
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

func TestComputeScore_NilInput(t *testing.T) {
	e := NewEngine()
	_, err := e.ComputeScore(context.Background(), nil)
	if err != ErrNilInput {
		t.Errorf("expected ErrNilInput, got %v", err)
	}
}

func TestSetWeights(t *testing.T) {
	e := NewEngine()
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 40},
		{Domain: "resilience", Weight: 60},
	}
	e.SetWeights(weights)

	got := e.GetWeights()
	if len(got) != 2 {
		t.Fatalf("expected 2 weights, got %d", len(got))
	}

	wMap := make(map[string]float64)
	for _, w := range got {
		wMap[w.Domain] = w.Weight
	}
	if wMap["attack_surface"] != 40 {
		t.Errorf("attack_surface weight: expected 40, got %.0f", wMap["attack_surface"])
	}
	if wMap["resilience"] != 60 {
		t.Errorf("resilience weight: expected 60, got %.0f", wMap["resilience"])
	}
}

func TestSetFormula(t *testing.T) {
	e := NewEngine()
	e.SetFormula("simple_weighted")
	if e.GetFormula() != "simple_weighted" {
		t.Errorf("expected simple_weighted, got %s", e.GetFormula())
	}

	e.SetFormula("nonexistent")
	if e.GetFormula() != "nonexistent" {
		t.Error("SetFormula should accept any string")
	}
}

func TestRegisterCustomFormula(t *testing.T) {
	e := NewEngine()
	e.SetWeights([]WeightConfig{
		{Domain: "attack_surface", Weight: 100},
	})

	e.RegisterFormula("custom_test", e.custom42Formula)
	e.SetFormula("custom_test")

	input := &AssessmentInput{
		HostID:      "test",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks:      []CheckInput{},
	}

	output, err := e.ComputeScore(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.FinalScore != 42.0 {
		t.Errorf("custom formula: expected 42.0, got %.2f", output.FinalScore)
	}
}

func TestHooks(t *testing.T) {
	e := NewEngine()
	e.SetWeights([]WeightConfig{
		{Domain: "attack_surface", Weight: 100},
	})

	called := false
	e.RegisterHook(HookPreScore, "test-hook", func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error {
		called = true
		return nil
	}, 10)

	input := &AssessmentInput{
		HostID:      "test",
		Threshold:   80,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks:      []CheckInput{},
	}

	_, err := e.ComputeScore(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !called {
		t.Error("hook was not called")
	}

	e.UnregisterHook("test-hook")
}

func TestDefaultEngine(t *testing.T) {
	e := NewDefaultEngine()
	weights := e.GetWeights()
	if len(weights) == 0 {
		t.Fatal("default engine should have weights")
	}

	found := false
	for _, w := range weights {
		if w.Domain == "attack_surface" && w.Weight == 35 {
			found = true
		}
	}
	if !found {
		t.Error("default attack_surface weight should be 35")
	}
}

func TestValidation(t *testing.T) {
	err := ValidateInput(AssessmentInput{HostID: "", Threshold: 80})
	if err == nil {
		t.Error("empty host_id: expected error")
	}

	err = ValidateInput(AssessmentInput{HostID: "test", Threshold: 0})
	if err == nil {
		t.Error("zero threshold: expected error")
	}

	err = ValidateInput(AssessmentInput{HostID: "test", Threshold: 80})
	if err != nil {
		t.Errorf("valid input: expected nil, got %v", err)
	}
}

func TestEdgeFactorTriggering(t *testing.T) {
	e := NewEngine()
	e.SetEdgeFactors([]EdgeFactorConfig{
		{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
		{ID: "EF-SYNCOOKIE", Name: "SYN Cookie", Factor: 0.75, TriggerCheck: "RS-005"},
	})

	checks := []CheckInput{
		{CheckID: "EF-001", Domain: "attack_surface", Passed: false, Delta: -5},
	}

	factors := e.ApplyEdgeFactorsToChecks(checks, nil)

	factorMap := make(map[string]EdgeFactorResult)
	for _, f := range factors {
		factorMap[f.ID] = f
	}

	if !factorMap["EF-002FA"].Active {
		t.Error("EF-002FA should be active when EF-001 fails")
	}
	if factorMap["EF-SYNCOOKIE"].Active {
		t.Error("EF-SYNCOOKIE should not be active when RS-005 passes")
	}
}

func TestSSAMIndependence(t *testing.T) {
	e := NewDefaultEngine()

	input := &AssessmentInput{
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

	output, err := e.ComputeScore(context.Background(), input)
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
