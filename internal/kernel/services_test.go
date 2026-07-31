package kernel

import (
	"testing"

	"github.com/asscor/asscor/internal/model"
)

func TestConvertAssessmentResultNil(t *testing.T) {
	if got := convertAssessmentResult(nil); got != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestConvertAssessmentResultBasic(t *testing.T) {
	r := &model.AssessmentResult{
		FinalScore: 85.5,
		Acceptable: true,
		ThreatCoeff: 0.92,
		SPCScore:   0.85,
		DomainScores: model.DomainScores{
			AttackSurface:      80,
			BusinessContinuity: 90,
			OperationTrust:     85,
			Resilience:         88,
		},
		Checks: []model.CheckResult{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "SSH Config", Passed: true, Delta: -5, Detail: "OK"},
			{CheckID: "OT-001", Domain: "operation_trust", Name: "File Perms", Passed: false, Delta: -10, Detail: "FAIL"},
		},
		SPCCVEs: []model.SPCCVEInfo{
			{CVEID: "CVE-2024-0001", CVSS: 9.8, EPSS: 0.95, InKEV: true, HasPoC: true, Penalty: 0.1, Product: "openssl"},
		},
	}

	got := convertAssessmentResult(r)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.FinalScore != 85.5 {
		t.Errorf("FinalScore = %v, want 85.5", got.FinalScore)
	}
	if !got.Acceptable {
		t.Error("expected acceptable=true")
	}
	if got.ThreatCoeff != 0.92 {
		t.Errorf("ThreatCoeff = %v, want 0.92", got.ThreatCoeff)
	}
	if got.SpcScore != 0.85 {
		t.Errorf("SpcScore = %v, want 0.85", got.SpcScore)
	}
	if len(got.Checks) != 2 {
		t.Errorf("Checks count = %d, want 2", len(got.Checks))
	}
	if len(got.SpcCVEs) != 1 {
		t.Errorf("SpcCVEs count = %d, want 1", len(got.SpcCVEs))
	}

	if got.DomainScores["attack_surface"] != 80 {
		t.Errorf("attack_surface = %v, want 80", got.DomainScores["attack_surface"])
	}
}

func TestConvertATTACKCoverage(t *testing.T) {
	src := []model.ATTACKCoverageInfo{
		{TacticID: "TA0001", TacticName: "Initial Access", TotalTechniques: 10, CoveredDet: 5, CoverageDet: 50, CoveragePrev: 60, CoverageComp: 0.55, RiskLevel: "medium"},
		{TacticID: "TA0002", TacticName: "Execution", TotalTechniques: 12, CoveredDet: 8, CoverageDet: 66.7, CoveragePrev: 70, CoverageComp: 0.68, RiskLevel: "low"},
	}

	got := convertATTACKCoverage(src)
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
	if got[0].TacticID != "TA0001" {
		t.Errorf("TacticID = %v, want TA0001", got[0].TacticID)
	}
}

func TestConvertATTACKKillChain(t *testing.T) {
	src := &model.ATTACKKillChainInfo{
		OverallScore: 0.72,
		WeakestStage: "Execution",
		Stages: []model.ATTACKKillChainStage{
			{Name: "Recon", Score: 0.9, Status: "strong", ChecksPassed: 5, ChecksTotal: 5},
			{Name: "Execution", Score: 0.5, Status: "weak", ChecksPassed: 2, ChecksTotal: 4},
		},
	}

	got := convertATTACKKillChain(src)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.OverallScore != 0.72 {
		t.Errorf("OverallScore = %v, want 0.72", got.OverallScore)
	}
	if got.WeakestStage != "Execution" {
		t.Errorf("WeakestStage = %v, want Execution", got.WeakestStage)
	}
	if len(got.Stages) != 2 {
		t.Fatalf("Stages count = %d, want 2", len(got.Stages))
	}
}

func TestConvertATTACKKillChainNil(t *testing.T) {
	if got := convertATTACKKillChain(nil); got != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestConvertATTACKAPTMatch(t *testing.T) {
	src := []model.ATTACKAPTMatchInfo{
		{GroupID: "G0007", GroupName: "APT28", Similarity: 0.85, Confidence: "high", OverlapTech: []string{"T1190", "T1059"}},
	}

	got := convertATTACKAPTMatch(src)
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d", len(got))
	}
	if got[0].GroupID != "G0007" {
		t.Errorf("GroupID = %v, want G0007", got[0].GroupID)
	}
}

func TestConvertATTACKPredictedRisk(t *testing.T) {
	src := &model.ATTACKPredictedRiskInfo{
		MaxRiskScore: 0.88, EnhancedThreat: 0.75, PredictedPaths: 3,
		Recommendations: []string{"Patch CVE-2024-0001", "Enable MFA"},
	}

	got := convertATTACKPredictedRisk(src)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.MaxRiskScore != 0.88 {
		t.Errorf("MaxRiskScore = %v, want 0.88", got.MaxRiskScore)
	}
	if got.EnhancedThreat != 0.75 {
		t.Errorf("EnhancedThreat = %v, want 0.75", got.EnhancedThreat)
	}
	if got.PredictedPaths != 3 {
		t.Errorf("PredictedPaths = %v, want 3", got.PredictedPaths)
	}
}

func TestRandomSessionSuffix(t *testing.T) {
	s1 := randomSessionSuffix()
	s2 := randomSessionSuffix()

	if len(s1) == 0 {
		t.Error("session suffix should not be empty")
	}
	if s1 == s2 {
		t.Error("two random suffixes should differ")
	}
}
