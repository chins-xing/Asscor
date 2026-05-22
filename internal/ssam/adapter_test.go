package ssam

import (
	"context"
	"testing"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/model"
)

func TestConfigToWeights(t *testing.T) {
	cfg := &config.Config{
		Weights: model.Weights{
			AttackSurface:      35,
			BusinessContinuity: 25,
			OperationTrust:     25,
			Resilience:         15,
		},
	}

	weights := ConfigToWeights(cfg)
	if len(weights) < 4 {
		t.Fatalf("expected at least 4 weights, got %d", len(weights))
	}

	wMap := make(map[string]float64)
	for _, w := range weights {
		wMap[w.Domain] = w.Weight
	}
	if wMap[model.DomainAttackSurface] != 35 {
		t.Errorf("attack_surface: expected 35, got %.0f", wMap[model.DomainAttackSurface])
	}
	if wMap[model.DomainBusinessContinuity] != 25 {
		t.Errorf("business_continuity: expected 25, got %.0f", wMap[model.DomainBusinessContinuity])
	}
}

func TestConfigToWeights_Nil(t *testing.T) {
	weights := ConfigToWeights(nil)
	if weights != nil {
		t.Error("nil config should return nil weights")
	}
}

func TestConfigToEdgeFactors(t *testing.T) {
	cfg := config.Default()
	factors := ConfigToEdgeFactors(cfg)
	if len(factors) == 0 {
		t.Fatal("default config should produce edge factors")
	}

	found := false
	for _, f := range factors {
		if f.ID == "EF-002FA" {
			found = true
			if f.TriggerCheck != "EF-001" {
				t.Errorf("EF-002FA trigger: expected EF-001, got %s", f.TriggerCheck)
			}
		}
	}
	if !found {
		t.Error("EF-002FA not found in edge factors")
	}
}

func TestCheckResultsToInputs(t *testing.T) {
	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Name: "Test", Passed: false, Delta: -10, Detail: "failed"},
		{CheckID: "BC-001", Domain: "business_continuity", Name: "Test2", Passed: true, Delta: 0, Detail: "ok"},
	}

	inputs := CheckResultsToInputs(checks)
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}
	if inputs[0].CheckID != "AS-001" {
		t.Errorf("check_id: expected AS-001, got %s", inputs[0].CheckID)
	}
	if inputs[0].Passed {
		t.Error("first check should not be passed")
	}
	if !inputs[1].Passed {
		t.Error("second check should be passed")
	}
}

func TestDomainScoresRoundTrip(t *testing.T) {
	ssamScores := []DomainScore{
		{Domain: model.DomainAttackSurface, Score: 85},
		{Domain: model.DomainBusinessContinuity, Score: 90},
		{Domain: model.DomainOperationTrust, Score: 75},
		{Domain: model.DomainResilience, Score: 80},
	}

	modelScores := DomainScoresToOutput(ssamScores)

	if modelScores.AttackSurface != 85 {
		t.Errorf("attack_surface: expected 85, got %.0f", modelScores.AttackSurface)
	}
	if modelScores.BusinessContinuity != 90 {
		t.Errorf("business_continuity: expected 90, got %.0f", modelScores.BusinessContinuity)
	}
	if modelScores.OperationTrust != 75 {
		t.Errorf("operation_trust: expected 75, got %.0f", modelScores.OperationTrust)
	}
	if modelScores.Resilience != 80 {
		t.Errorf("resilience: expected 80, got %.0f", modelScores.Resilience)
	}
}

func TestEdgeFactorsRoundTrip(t *testing.T) {
	ssamFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		{ID: "EF-SELINUX", Factor: 0.80, Active: false},
	}

	modelFactors := EdgeFactorsToModel(ssamFactors)

	if modelFactors.TwoFactorFailure != 0.85 {
		t.Errorf("two_factor_failure: expected 0.85, got %.2f", modelFactors.TwoFactorFailure)
	}
	if modelFactors.SYNCookieDisabled != 0.75 {
		t.Errorf("syn_cookie_disabled: expected 0.75, got %.2f", modelFactors.SYNCookieDisabled)
	}
	if modelFactors.SELinuxDisabled != 0 {
		t.Errorf("selinux_disabled: expected 0 (inactive), got %.2f", modelFactors.SELinuxDisabled)
	}
}

func TestModelToInput(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:     "host-001",
		Hostname:   "server1",
		Threshold:  80,
		ThreatCoeff: 0.95,
		SPCScore:   0.88,
		Checks: []model.CheckResult{
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10},
		},
	}

	input := ModelToInput(result)
	if input.HostID != "host-001" {
		t.Errorf("host_id: expected host-001, got %s", input.HostID)
	}
	if input.Threshold != 80 {
		t.Errorf("threshold: expected 80, got %.0f", input.Threshold)
	}
	if input.ThreatCoeff != 0.95 {
		t.Errorf("threat_coeff: expected 0.95, got %.2f", input.ThreatCoeff)
	}
	if len(input.Checks) != 1 {
		t.Errorf("checks: expected 1, got %d", len(input.Checks))
	}
}

func TestModelToInput_Nil(t *testing.T) {
	input := ModelToInput(nil)
	if input != nil {
		t.Error("nil model should return nil input")
	}
}

func TestOutputToModel(t *testing.T) {
	output := &AssessmentOutput{
		FinalScore: 72.5,
		Acceptable: false,
		Threshold:  80,
		DomainScores: []DomainScore{
			{Domain: model.DomainAttackSurface, Score: 65},
			{Domain: model.DomainResilience, Score: 80},
		},
		EdgeFactors: []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
		},
		ThreatCoeff: 0.95,
		SPCScore:    0.88,
	}

	result := &model.AssessmentResult{}
	OutputToModel(output, result)

	if result.FinalScore != 72.5 {
		t.Errorf("final_score: expected 72.5, got %.2f", result.FinalScore)
	}
	if result.Acceptable {
		t.Error("should not be acceptable")
	}
	if result.DomainScores.AttackSurface != 65 {
		t.Errorf("attack_surface: expected 65, got %.0f", result.DomainScores.AttackSurface)
	}
	if result.EdgeFactors.TwoFactorFailure != 0.85 {
		t.Errorf("two_factor_failure: expected 0.85, got %.2f", result.EdgeFactors.TwoFactorFailure)
	}
	if result.ThreatCoeff != 0.95 {
		t.Errorf("threat_coeff: expected 0.95, got %.2f", result.ThreatCoeff)
	}
}

func TestOutputToModel_Nil(t *testing.T) {
	OutputToModel(nil, nil)
	OutputToModel(nil, &model.AssessmentResult{})
	OutputToModel(&AssessmentOutput{}, nil)
}

func TestFullIntegrationPipeline(t *testing.T) {
	cfg := config.Default()
	weights := ConfigToWeights(cfg)
	factors := ConfigToEdgeFactors(cfg)

	e := NewEngine()
	e.SetWeights(weights)
	e.SetEdgeFactors(factors)

	modelChecks := []model.CheckResult{
		{CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Root Login", Passed: false, Delta: -15},
		{CheckID: "BC-001", Domain: "business_continuity", Name: "Backup Status", Passed: false, Delta: -10},
		{CheckID: "OT-001", Domain: "operation_trust", Name: "File Permissions", Passed: true, Delta: 0},
		{CheckID: "RS-001", Domain: "resilience", Name: "Fail2ban", Passed: true, Delta: 0},
	}

	input := &AssessmentInput{
		HostID:      "integration-test",
		Threshold:   cfg.Threshold,
		ThreatCoeff: cfg.ThreatCoeff,
		SPCScore:    1.0,
		Checks:      CheckResultsToInputs(modelChecks),
	}

	output, err := e.ComputeScore(context.Background(), input)
	if err != nil {
		t.Fatalf("integration compute failed: %v", err)
	}

	if output.FinalScore <= 0 || output.FinalScore > 100 {
		t.Errorf("final score out of range: %.2f", output.FinalScore)
	}

	modelResult := &model.AssessmentResult{}
	OutputToModel(output, modelResult)

	if modelResult.FinalScore != output.FinalScore {
		t.Errorf("round-trip score mismatch: ssam=%.2f model=%.2f", output.FinalScore, modelResult.FinalScore)
	}
}
