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

func TestComputeFinalScore_Formula(t *testing.T) {
	tests := []struct {
		name       string
		domainScores model.DomainScores
		weights    model.Weights
		edgeFactor float64
		threatCoeff float64
		spcScore   float64
		expected   float64
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
			cfg := config.Default()
			cfg.Weights = tt.weights
			a := NewAssessor(cfg)

			result := &model.AssessmentResult{
				DomainScores: tt.domainScores,
				EdgeFactors:  model.EdgeFactors{TwoFactorFailure: tt.edgeFactor},
				ThreatCoeff:  tt.threatCoeff,
				SPCScore:     tt.spcScore,
			}

			got := a.computeFinalScore(result)
			if got != tt.expected {
				t.Errorf("computeFinalScore = %.4f, want %.4f", got, tt.expected)
			}
		})
	}
}

func TestComputeDomainScores(t *testing.T) {
	tests := []struct {
		name     string
		checks   []model.CheckResult
		expected model.DomainScores
	}{
		{
			name: "no failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true, Delta: -8},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: true, Delta: -10},
			},
			expected: model.DomainScores{AttackSurface: 100, BusinessContinuity: 100, OperationTrust: 100, Resilience: 100},
		},
		{
			name: "single domain failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -8},
				{CheckID: "AS-002", Domain: model.DomainAttackSurface, Passed: false, Delta: -5},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: true, Delta: -10},
			},
			expected: model.DomainScores{AttackSurface: 87, BusinessContinuity: 100, OperationTrust: 100, Resilience: 100},
		},
		{
			name: "all domains with failures",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -20},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: false, Delta: -30},
				{CheckID: "OT-001", Domain: model.DomainOperationTrust, Passed: false, Delta: -15},
				{CheckID: "RS-001", Domain: model.DomainResilience, Passed: false, Delta: -25},
			},
			expected: model.DomainScores{AttackSurface: 80, BusinessContinuity: 70, OperationTrust: 85, Resilience: 75},
		},
		{
			name: "domain score floor at zero",
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -150},
			},
			expected: model.DomainScores{AttackSurface: 0, BusinessContinuity: 100, OperationTrust: 100, Resilience: 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			a := NewAssessor(cfg)

			result := &model.AssessmentResult{Checks: tt.checks}
			a.computeDomainScores(result)

			if result.DomainScores.AttackSurface != tt.expected.AttackSurface {
				t.Errorf("AttackSurface = %.2f, want %.2f", result.DomainScores.AttackSurface, tt.expected.AttackSurface)
			}
			if result.DomainScores.BusinessContinuity != tt.expected.BusinessContinuity {
				t.Errorf("BusinessContinuity = %.2f, want %.2f", result.DomainScores.BusinessContinuity, tt.expected.BusinessContinuity)
			}
			if result.DomainScores.OperationTrust != tt.expected.OperationTrust {
				t.Errorf("OperationTrust = %.2f, want %.2f", result.DomainScores.OperationTrust, tt.expected.OperationTrust)
			}
			if result.DomainScores.Resilience != tt.expected.Resilience {
				t.Errorf("Resilience = %.2f, want %.2f", result.DomainScores.Resilience, tt.expected.Resilience)
			}
		})
	}
}

func TestEvaluateEdgeFactors(t *testing.T) {
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
			expected: 0.85 * 0.82,
		},
		{
			name: "both EF-001 and EF-002",
			checks: []model.CheckResult{
				{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false},
				{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false},
			},
			expected: 0.85 * 0.82,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.EdgeFactors.TwoFactorFailure = 0.85
			a := NewAssessor(cfg)

			result := &model.AssessmentResult{Checks: tt.checks}
			a.evaluateEdgeFactors(result)

			got := result.EdgeFactors.TwoFactorFailure
			if math.Abs(got-tt.expected) > 0.001 {
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
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Name: "无用服务", Passed: false, Delta: -8, Detail: "telnet running"},
		{CheckID: "AS-002", Domain: model.DomainAttackSurface, Name: "开放端口", Passed: true, Delta: -5},
		{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Name: "关键服务", Passed: true, Delta: -10},
		{CheckID: "OT-001", Domain: model.DomainOperationTrust, Name: "文件权限", Passed: false, Delta: -12, Detail: "/etc/shadow 0644"},
		{CheckID: "RS-001", Domain: model.DomainResilience, Name: "自动封禁", Passed: true, Delta: -8},
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Name: "双因素认证", Passed: false, Delta: 0, Detail: "2FA not enabled"},
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

	if result.EdgeFactors.TwoFactorFailure != 0.85 {
		t.Errorf("TwoFactorFailure = %.2f, want 0.85", result.EdgeFactors.TwoFactorFailure)
	}

	weightedSum := (expectedAS*35 + 100*25 + expectedOT*25 + 100*15) / 100
	expectedFinal := math.Round(weightedSum*0.85*0.9*1.0*100) / 100
	if result.FinalScore != expectedFinal {
		t.Errorf("FinalScore = %.4f, want %.4f (weightedSum=%.4f)", result.FinalScore, expectedFinal, weightedSum)
	}

	if result.Acceptable != (result.FinalScore >= 80.0) {
		t.Errorf("Acceptable=%v inconsistent with FinalScore=%.2f >= Threshold=%.0f",
			result.Acceptable, result.FinalScore, cfg.Threshold)
	}
}

func TestAssessFromResults_ThresholdBoundary(t *testing.T) {
	tests := []struct {
		name      string
		threshold float64
		checks    []model.CheckResult
		acceptable bool
	}{
		{
			name:      "above threshold",
			threshold: 80.0,
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -5},
			},
			acceptable: true,
		},
		{
			name:      "below threshold",
			threshold: 80.0,
			checks: []model.CheckResult{
				{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -50},
				{CheckID: "BC-001", Domain: model.DomainBusinessContinuity, Passed: false, Delta: -50},
				{CheckID: "OT-001", Domain: model.DomainOperationTrust, Passed: false, Delta: -50},
				{CheckID: "RS-001", Domain: model.DomainResilience, Passed: false, Delta: -50},
			},
			acceptable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Threshold = tt.threshold
			a := NewAssessor(cfg)

			result := a.AssessFromResults("host-01", "host-01", tt.checks)
			if result.Acceptable != tt.acceptable {
				t.Errorf("Acceptable=%v, want %v (FinalScore=%.2f, Threshold=%.0f)",
					result.Acceptable, tt.acceptable, result.FinalScore, tt.threshold)
			}
		})
	}
}

func TestValidateEdgeFactors(t *testing.T) {
	a := NewAssessor(config.Default())

	checks := []model.CheckItem{
		{ID: "AS-001", Domain: model.DomainAttackSurface},
		{ID: "RS-005", Domain: model.DomainResilience},
		{ID: "OT-004", Domain: model.DomainOperationTrust},
	}

	warnings := a.ValidateEdgeFactors(checks)

	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings for RS-005 and OT-004, got %d: %v", len(warnings), warnings)
	}
}

func TestEF001_EF002_FullChain(t *testing.T) {
	cfg := config.Default()
	cfg.Weights = model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15}
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.ThreatCoeff = 1.0

	tests := []struct {
		name          string
		ef001Passed   bool
		ef002Passed   bool
		wantFactor    float64
		wantFinalDiff bool // true if FinalScore should differ from 100
	}{
		{
			name:       "Both 2FA and 3FA pass → no penalty",
			ef001Passed: true,
			ef002Passed: true,
			wantFactor:  1.0,
			wantFinalDiff: false,
		},
		{
			name:       "2FA missing → ×0.85 penalty",
			ef001Passed: false,
			ef002Passed: true,
			wantFactor:  0.85,
			wantFinalDiff: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssessor(cfg)

			checks := []model.CheckResult{
				{CheckID: "EF-001", Domain: "attack_surface", Name: "双因素认证", Passed: tt.ef001Passed, Delta: 0},
				{CheckID: "EF-002", Domain: "attack_surface", Name: "三因素认证", Passed: tt.ef002Passed, Delta: 0},
			}

			result := a.AssessFromResults("host-01", "host-01", checks)

			gotFactor := result.EdgeFactors.TwoFactorFailure
			if gotFactor != tt.wantFactor {
				t.Errorf("TwoFactorFailure = %.3f, want %.3f", gotFactor, tt.wantFactor)
			}

			if tt.wantFinalDiff {
				if result.FinalScore >= 100 {
					t.Errorf("expected FinalScore < 100 (edge factor penalty), got %.2f", result.FinalScore)
				}
			} else {
				if result.FinalScore != 100 {
					t.Errorf("expected FinalScore = 100 (no penalty), got %.2f", result.FinalScore)
				}
			}

			t.Logf("EF-001 passed=%v EF-002 passed=%v → TwoFactorFailure=%.3f FinalScore=%.2f",
				tt.ef001Passed, tt.ef002Passed, gotFactor, result.FinalScore)
		})
	}
}

func TestEF001_ImpactsFinalScore(t *testing.T) {
	cfg := config.Default()
	cfg.Weights = model.Weights{AttackSurface: 35, BusinessContinuity: 25, OperationTrust: 25, Resilience: 15}
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.ThreatCoeff = 1.0

	a := NewAssessor(cfg)

	checksNoEF := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Name: "检查1", Passed: true, Delta: 0},
	}
	checksWithEF := []model.CheckResult{
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Name: "检查1", Passed: true, Delta: 0},
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Name: "双因素认证", Passed: false, Delta: 0},
	}

	resultNoEF := a.AssessFromResults("host-01", "host-01", checksNoEF)
	resultWithEF := a.AssessFromResults("host-01", "host-01", checksWithEF)

	if resultNoEF.FinalScore != 100 {
		t.Fatalf("baseline FinalScore should be 100, got %.2f", resultNoEF.FinalScore)
	}

	expectedWithEF := math.Round(100.0 * 0.85 * 100) / 100
	if resultWithEF.FinalScore != expectedWithEF {
		t.Errorf("EF-001 failure should reduce FinalScore from 100 to %.2f, got %.2f", expectedWithEF, resultWithEF.FinalScore)
	}

	if resultWithEF.EdgeFactors.TwoFactorFailure != 0.85 {
		t.Errorf("EF-001 failure should set TwoFactorFailure=0.85, got %.3f", resultWithEF.EdgeFactors.TwoFactorFailure)
	}

	t.Logf("Baseline=%.2f, EF-001 failed → FinalScore=%.2f, TwoFactorFailure=%.3f",
		resultNoEF.FinalScore, resultWithEF.FinalScore, resultWithEF.EdgeFactors.TwoFactorFailure)
}