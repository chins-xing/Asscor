package engine

import (
	"math"
	"testing"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/model"
)

func TestAssess_AllPassed(t *testing.T) {
	cfg := config.Default()
	a := NewAssessor(cfg)

	result := a.Assess()

	if result.FinalScore != 100.0 {
		t.Errorf("expected FinalScore=100, got %.2f", result.FinalScore)
	}
	if !result.Acceptable {
		t.Error("expected Acceptable=true")
	}
	if result.DomainScores.AttackSurface != 100 {
		t.Errorf("expected AttackSurface=100, got %.2f", result.DomainScores.AttackSurface)
	}
	if result.DomainScores.BusinessContinuity != 100 {
		t.Errorf("expected BusinessContinuity=100, got %.2f", result.DomainScores.BusinessContinuity)
	}
	if result.DomainScores.OperationTrust != 100 {
		t.Errorf("expected OperationTrust=100, got %.2f", result.DomainScores.OperationTrust)
	}
	if result.DomainScores.Resilience != 100 {
		t.Errorf("expected Resilience=100, got %.2f", result.DomainScores.Resilience)
	}
}

func TestAssessFromResults_Empty(t *testing.T) {
	cfg := config.Default()
	a := NewAssessor(cfg)

	result := a.AssessFromResults("host-01", "host-01.example.com", nil)

	if result.FinalScore != 100.0 {
		t.Errorf("expected FinalScore=100, got %.2f", result.FinalScore)
	}
	if !result.Acceptable {
		t.Error("expected Acceptable=true")
	}
}

func TestComputeDynamicFinalScore_Formula(t *testing.T) {
	tests := []struct {
		name        string
		domainScores model.DomainScores
		weights     model.Weights
		edgeFactor  float64
		threatCoeff float64
		spcScore    float64
		expected    float64
	}{
		{
			name: "all perfect",
			domainScores: model.DomainScores{
				AttackSurface: 100, BusinessContinuity: 100,
				OperationTrust: 100, Resilience: 100,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  1.0,
			threatCoeff: 1.0,
			spcScore:    1.0,
			expected:    100.0,
		},
		{
			name: "all zero",
			domainScores: model.DomainScores{
				AttackSurface: 0, BusinessContinuity: 0,
				OperationTrust: 0, Resilience: 0,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  1.0,
			threatCoeff: 1.0,
			spcScore:    1.0,
			expected:    0.0,
		},
		{
			name: "half scores",
			domainScores: model.DomainScores{
				AttackSurface: 50, BusinessContinuity: 50,
				OperationTrust: 50, Resilience: 50,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  1.0,
			threatCoeff: 1.0,
			spcScore:    1.0,
			expected:    50.0,
		},
		{
			name: "with edge factor penalty",
			domainScores: model.DomainScores{
				AttackSurface: 100, BusinessContinuity: 100,
				OperationTrust: 100, Resilience: 100,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  0.85,
			threatCoeff: 1.0,
			spcScore:    1.0,
			expected:    85.0,
		},
		{
			name: "with threat coefficient",
			domainScores: model.DomainScores{
				AttackSurface: 100, BusinessContinuity: 100,
				OperationTrust: 100, Resilience: 100,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  1.0,
			threatCoeff: 0.9,
			spcScore:    1.0,
			expected:    90.0,
		},
		{
			name: "with SPC penalty",
			domainScores: model.DomainScores{
				AttackSurface: 100, BusinessContinuity: 100,
				OperationTrust: 100, Resilience: 100,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  1.0,
			threatCoeff: 1.0,
			spcScore:    0.85,
			expected:    85.0,
		},
		{
			name: "all penalties combined",
			domainScores: model.DomainScores{
				AttackSurface: 80, BusinessContinuity: 70,
				OperationTrust: 60, Resilience: 50,
			},
			weights:     model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15},
			edgeFactor:  0.85,
			threatCoeff: 0.9,
			spcScore:    0.85,
			expected:    math.Round((80*35+70*25+60*25+50*15)/100*0.85*0.9*0.85*100) / 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model.ResetAllEdgeFactors()
			cfg := config.Default()
			cfg.Weights = tt.weights
			cfg.ThreatCoeff = tt.threatCoeff
			a := NewAssessor(cfg)

			scores := model.NewDynamicDomainScores()
			scores.FillFromLegacy(tt.domainScores)

			if tt.edgeFactor < 1.0 {
				model.SetEdgeFactorValue("EF-002FA", tt.edgeFactor)
			}

			result := &model.AssessmentResult{
				DomainScores: tt.domainScores,
				EdgeFactors:  model.EdgeFactors{TwoFactorFailure: tt.edgeFactor},
				ThreatCoeff:  tt.threatCoeff,
				SPCScore:     tt.spcScore,
			}

			got := a.computeDynamicFinalScore(scores, result)
			if math.Abs(got-tt.expected) > 0.01 {
				t.Errorf("computeDynamicFinalScore = %.4f, want %.4f", got, tt.expected)
			}
		})
	}
}

func TestComputeDynamicDomainScores(t *testing.T) {
	tests := []struct {
		name     string
		checks   []model.CheckResult
		expectedMap map[string]float64
	}{
		{
			name: "no failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true, Delta: -8},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: true, Delta: -10},
			},
			expectedMap: map[string]float64{
				model.DomainAttackSurface: 100, model.DomainBusinessContinuity: 100,
				model.DomainOperationTrust: 100, model.DomainResilience: 100,
			},
		},
		{
			name: "single domain failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -8},
				{CheckID: "AS-002", Domain: model.DomainAttackSurface, Passed: false, Delta: -5},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: true, Delta: -10},
			},
			expectedMap: map[string]float64{
				model.DomainAttackSurface: 87, model.DomainBusinessContinuity: 100,
				model.DomainOperationTrust: 100, model.DomainResilience: 100,
			},
		},
		{
			name: "all domains with failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -20},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: false, Delta: -30},
				{CheckID: "OT-001", Domain: model.DomainOperationTrust, Passed: false, Delta: -15},
				{CheckID: "RS-001", Domain: model.DomainResilience, Passed: false, Delta: -25},
			},
			expectedMap: map[string]float64{
				model.DomainAttackSurface: 80, model.DomainBusinessContinuity: 70,
				model.DomainOperationTrust: 85, model.DomainResilience: 75,
			},
		},
		{
			name: "domain score floor at zero",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -150},
			},
			expectedMap: map[string]float64{
				model.DomainAttackSurface: 0, model.DomainBusinessContinuity: 100,
				model.DomainOperationTrust: 100, model.DomainResilience: 100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			a := NewAssessor(cfg)

			result := &model.AssessmentResult{Checks: tt.checks}
			dynScores := a.computeDynamicDomainScores(result)

			for domain, expected := range tt.expectedMap {
				got := dynScores.Get(domain)
				if got != expected {
					t.Errorf("%s = %.2f, want %.2f", domain, got, expected)
				}
			}
		})
	}
}

func TestEvaluateEdgeFactorChain(t *testing.T) {
	tests := []struct {
		name     string
		checks   []model.CheckResult
		expected float64
	}{
		{
			name: "no edge factor failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true},
			},
			expected: 1.0,
		},
		{
			name: "EF-001 two factor failure",
			checks: []model.CheckResult{
				{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false},
			},
			expected: 0.85,
		},
		{
			name: "EF-002 additional two factor failure",
			checks: []model.CheckResult{
				{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false},
			},
			expected: 0.697,
		},
		{
			name: "both EF-001 and EF-002",
			checks: []model.CheckResult{
				{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false},
				{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false},
			},
			expected: 0.697,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.EdgeFactors.TwoFactorFailure = 0.85
			a := NewAssessor(cfg)

			result := &model.AssessmentResult{Checks: tt.checks}
			a.evaluateEdgeFactorChain(result)

			got := result.EdgeFactors.TwoFactorFailure
			if math.Abs(got-tt.expected) > 0.01 {
				t.Errorf("TwoFactorFailure = %.4f, want %.4f", got, tt.expected)
			}
		})
	}
}

func TestAssessFromResults_EndToEnd(t *testing.T) {
	cfg := config.Default()
	cfg.Threshold = 80.0
	cfg.Weights = model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15}
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.ThreatCoeff = 0.9

	a := NewAssessor(cfg)

	checks := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Name: "unused service", Passed: false, Delta: -8, Detail: "telnet running"},
		{CheckID: "AS-002", Domain: model.DomainAttackSurface, Name: "open port", Passed: true, Delta: -5},
		{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Name: "critical service", Passed: true, Delta: -10},
		{CheckID: "OT-001", Domain: model.DomainOperationTrust, Name: "file permission", Passed: false, Delta: -12, Detail: "/etc/shadow 0644"},
		{CheckID: "RS-001", Domain: model.DomainResilience, Name: "auto block", Passed: true, Delta: -8},
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Name: "2FA", Passed: false, Delta: 0, Detail: "2FA not enabled"},
	}

	result := a.AssessFromResults("host-01", "host-01.example.com", checks)

	if result.HostID != "host-01" {
		t.Errorf("expected HostID=host-01, got %s", result.HostID)
	}
	if result.Hostname != "host-01.example.com" {
		t.Errorf("expected Hostname=host-01.example.com, got %s", result.Hostname)
	}

	expectedAS := 100.0 - 8.0
	if result.DomainScores.AttackSurface != expectedAS {
		t.Errorf("AttackSurface = %.2f, want %.2f", result.DomainScores.AttackSurface, expectedAS)
	}

	expectedOT := 100.0 - 12.0
	if result.DomainScores.OperationTrust != expectedOT {
		t.Errorf("OperationTrust = %.2f, want %.2f", result.DomainScores.OperationTrust, expectedOT)
	}

	if math.Abs(result.EdgeFactors.TwoFactorFailure-0.85) > 0.01 {
		t.Errorf("TwoFactorFailure = %.2f, want 0.85", result.EdgeFactors.TwoFactorFailure)
	}

	weightedSum := (expectedAS*35 + 100*25 + expectedOT*25 + 100*15) / 100
	expectedFinal := math.Round(weightedSum*0.85*0.9*1.0*100) / 100
	if math.Abs(result.FinalScore-expectedFinal) > 0.01 {
		t.Errorf("FinalScore = %.4f, want %.4f (weightedSum=%.4f)", result.FinalScore, expectedFinal, weightedSum)
	}

	if result.Acceptable != (result.FinalScore >= 80.0) {
		t.Errorf("Acceptable=%v inconsistent with FinalScore=%.2f >= Threshold=%.0f",
			result.Acceptable, result.FinalScore, cfg.Threshold)
	}
}
