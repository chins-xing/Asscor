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

	result := a.Assess("", "")

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
			expected: 0.82,
		},
		{
			name: "both EF-001 and EF-002",
			checks: []model.CheckResult{
				{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false},
				{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false},
			},
			expected: 0.82,
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

func TestAssessFromResults_RealWorldScenario(t *testing.T) {
	cfg := config.Default()
	cfg.Threshold = 80.0
	cfg.Weights = model.Weights{
		AttackSurface:      35,
		BusinessContinuity: 25,
		OperationTrust:     25,
		Resilience:         15,
	}
	cfg.ExtensionWeights = map[string]float64{
		"kernel_security": 10,
	}
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.ThreatCoeff = 1.0

	cfg.CheckDeltas = map[string]float64{
		"AS-004": -8, "AS-008": -3, "AS-012": -6, "AS-013": -5, "AS-016": -10, "AS-017": -5,
		"EF-001": 0, "EF-002": 0,
		"OT-004": -5, "OT-005": -15, "OT-007": -4, "OT-009": -8, "OT-012": -3,
		"OT-013": -10, "OT-014": -10, "OT-016": -5, "OT-019": -6, "OT-020": -10, "OT-022": -15,
		"RS-007": -6, "RS-008": -8, "RS-009": -6, "RS-010": -4, "RS-011": -15, "RS-012": -10,
		"AC-001": -15, "AC-002": -20, "AC-003": -10, "AC-004": -10, "AC-005": -10,
		"BC-005": -10, "BC-006": -10, "BC-007": -20,
		"KS-003": -15, "KS-004": -8, "KS-007": -10, "KS-009": -8, "KS-011": -5, "KS-012": -15,
	}

	a := NewAssessor(cfg)

	checks := []model.CheckResult{
		{CheckID: "AS-004", Domain: model.DomainAttackSurface, Name: "SSH Config", Passed: false, Delta: -8},
		{CheckID: "AS-008", Domain: model.DomainAttackSurface, Name: "Open Ports", Passed: false, Delta: -3},
		{CheckID: "AS-012", Domain: model.DomainAttackSurface, Name: "Ghost Account", Passed: false, Delta: -6},
		{CheckID: "AS-013", Domain: model.DomainAttackSurface, Name: "File ACL", Passed: false, Delta: -5},
		{CheckID: "AS-016", Domain: model.DomainAttackSurface, Name: "Login Source", Passed: false, Delta: -10},
		{CheckID: "AS-017", Domain: model.DomainAttackSurface, Name: "Access Time", Passed: false, Delta: -5},
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Name: "2FA Check", Passed: false, Delta: 0},
		{CheckID: "EF-002", Domain: model.DomainAttackSurface, Name: "2FA Verify", Passed: false, Delta: 0},
		{CheckID: "OT-004", Domain: model.DomainOperationTrust, Name: "File Perm", Passed: false, Delta: -5},
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Name: "SELinux", Passed: false, Delta: -15},
		{CheckID: "OT-007", Domain: model.DomainOperationTrust, Name: "Audit Log", Passed: false, Delta: -4},
		{CheckID: "OT-009", Domain: model.DomainOperationTrust, Name: "Cmd History", Passed: false, Delta: -8},
		{CheckID: "OT-012", Domain: model.DomainOperationTrust, Name: "Supply Chain", Passed: false, Delta: -3},
		{CheckID: "OT-013", Domain: model.DomainOperationTrust, Name: "Pkg Integrity", Passed: false, Delta: -10},
		{CheckID: "OT-014", Domain: model.DomainOperationTrust, Name: "Repo Trust", Passed: false, Delta: -10},
		{CheckID: "OT-016", Domain: model.DomainOperationTrust, Name: "Cron Perm", Passed: false, Delta: -5},
		{CheckID: "OT-019", Domain: model.DomainOperationTrust, Name: "SUID Check", Passed: false, Delta: -6},
		{CheckID: "OT-020", Domain: model.DomainOperationTrust, Name: "SGID Check", Passed: false, Delta: -10},
		{CheckID: "OT-022", Domain: model.DomainOperationTrust, Name: "Immutable", Passed: false, Delta: -15},
		{CheckID: "RS-007", Domain: model.DomainResilience, Name: "Fail2ban", Passed: false, Delta: -6},
		{CheckID: "RS-008", Domain: model.DomainResilience, Name: "SYN Cookie", Passed: false, Delta: -8},
		{CheckID: "RS-009", Domain: model.DomainResilience, Name: "Conn Limit", Passed: false, Delta: -6},
		{CheckID: "RS-010", Domain: model.DomainResilience, Name: "Rate Limit", Passed: false, Delta: -4},
		{CheckID: "RS-011", Domain: model.DomainResilience, Name: "ACI Network", Passed: false, Delta: -15},
		{CheckID: "RS-012", Domain: model.DomainResilience, Name: "ACI LAPS", Passed: false, Delta: -10},
		{CheckID: "AC-001", Domain: model.DomainResilience, Name: "ACI Backup", Passed: false, Delta: -15},
		{CheckID: "AC-002", Domain: model.DomainResilience, Name: "ACI EDR", Passed: false, Delta: -20},
		{CheckID: "AC-003", Domain: model.DomainResilience, Name: "ACI RemoteLog", Passed: false, Delta: -10},
		{CheckID: "AC-004", Domain: model.DomainResilience, Name: "ACI AppWhitelist", Passed: false, Delta: -10},
		{CheckID: "AC-005", Domain: model.DomainResilience, Name: "ACI DLP", Passed: false, Delta: -10},
		{CheckID: "BC-005", Domain: model.DomainBusinessContinuity, Name: "Critical Svc", Passed: false, Delta: -10},
		{CheckID: "BC-006", Domain: model.DomainBusinessContinuity, Name: "Backup", Passed: false, Delta: -10},
		{CheckID: "BC-007", Domain: model.DomainBusinessContinuity, Name: "Resource", Passed: false, Delta: -20},
		{CheckID: "KS-003", Domain: model.DomainKernelSecurity, Name: "Module Sig", Passed: false, Delta: -15},
		{CheckID: "KS-004", Domain: model.DomainKernelSecurity, Name: "Info Leak", Passed: false, Delta: -8},
		{CheckID: "KS-007", Domain: model.DomainKernelSecurity, Name: "Sysctl", Passed: false, Delta: -10},
		{CheckID: "KS-009", Domain: model.DomainKernelSecurity, Name: "Debug IF", Passed: false, Delta: -8},
		{CheckID: "KS-011", Domain: model.DomainKernelSecurity, Name: "dmesg", Passed: false, Delta: -5},
		{CheckID: "KS-012", Domain: model.DomainKernelSecurity, Name: "LSMs", Passed: false, Delta: -15},
	}

	result := a.AssessFromResults("host-01", "host-01.example.com", checks)

	t.Logf("FinalScore: %.2f", result.FinalScore)
	t.Logf("DomainScores: AS=%.2f BC=%.2f OT=%.2f RS=%.2f KS=%.2f",
		result.DomainScores.AttackSurface,
		result.DomainScores.BusinessContinuity,
		result.DomainScores.OperationTrust,
		result.DomainScores.Resilience,
		result.DomainScores.KernelSecurity)
	t.Logf("EdgeFactors.TwoFactorFailure: %.4f", result.EdgeFactors.TwoFactorFailure)

	expectedAS := 100.0 - 8 - 3 - 6 - 5 - 10 - 5
	if result.DomainScores.AttackSurface != expectedAS {
		t.Errorf("AttackSurface = %.2f, want %.2f", result.DomainScores.AttackSurface, expectedAS)
	}

	expectedBC := 100.0 - 10 - 10 - 20
	if result.DomainScores.BusinessContinuity != expectedBC {
		t.Errorf("BusinessContinuity = %.2f, want %.2f", result.DomainScores.BusinessContinuity, expectedBC)
	}

	expectedOT := 100.0 - 5 - 15 - 4 - 8 - 3 - 10 - 10 - 5 - 6 - 10 - 15
	if result.DomainScores.OperationTrust != expectedOT {
		t.Errorf("OperationTrust = %.2f, want %.2f", result.DomainScores.OperationTrust, expectedOT)
	}

	expectedRS := math.Max(0, 100.0-6-8-6-4-15-10-15-20-10-10-10)
	if result.DomainScores.Resilience != expectedRS {
		t.Errorf("Resilience = %.2f, want %.2f", result.DomainScores.Resilience, expectedRS)
	}

	expectedKS := 100.0 - 15 - 8 - 10 - 8 - 5 - 15
	if result.DomainScores.KernelSecurity != expectedKS {
		t.Errorf("KernelSecurity = %.2f, want %.2f", result.DomainScores.KernelSecurity, expectedKS)
	}

	if math.Abs(result.EdgeFactors.TwoFactorFailure-0.82) > 0.01 {
		t.Errorf("TwoFactorFailure = %.4f, want 0.82", result.EdgeFactors.TwoFactorFailure)
	}

	weightedSum := (expectedAS*31.818181 + expectedBC*22.727272 + expectedOT*22.727272 +
		expectedRS*13.636363 + expectedKS*9.090909) / 100.0
	expectedFinal := math.Round(weightedSum*0.82*100) / 100
	if math.Abs(result.FinalScore-expectedFinal) > 0.02 {
		t.Errorf("FinalScore = %.4f, want %.4f (weightedSum=%.4f)", result.FinalScore, expectedFinal, weightedSum)
	}
}
