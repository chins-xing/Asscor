//go:build attck_ext

package kernel

import "testing"

func TestATTACKCoverage(t *testing.T) {
	k := NewKernel()
	attck := NewATTACKModule()

	if err := attck.Init(k.Context(), KernelContext(k)); err != nil {
		t.Fatalf("init attck: %v", err)
	}

	allTactics := attck.GetAllTactics()
	if len(allTactics) != 14 {
		t.Fatalf("expected 14 tactics, got %d", len(allTactics))
	}

	coverage := attck.CalculateCoverage(nil)
	if len(coverage) != 14 {
		t.Fatalf("expected 14 coverage entries, got %d", len(coverage))
	}

	for _, c := range coverage {
		if c.CoverageComp < 0 || c.CoverageComp > 1.0 {
			t.Errorf("coverage out of range for %s: %.3f", c.TacticName, c.CoverageComp)
		}
	}

	summary := attck.GetCoverageSummary(nil)
	avgDet, ok := summary["avg_detection_coverage"].(float64)
	if !ok {
		t.Fatal("expected avg_detection_coverage in summary")
	}
	t.Logf("Avg Detection Coverage: %.3f", avgDet)
	t.Logf("Tactics: %v", summary["total_tactics"])
}

func TestAPTGroupMatch(t *testing.T) {
	k := NewKernel()
	attck := NewATTACKModule()
	if err := attck.Init(k.Context(), KernelContext(k)); err != nil {
		t.Fatalf("init attck: %v", err)
	}

	detected := []string{"T1190", "T1059", "T1021", "T1003", "T1505"}
	matches := attck.MatchAPTGroup(detected)

	if len(matches) == 0 {
		t.Fatal("expected at least 1 APT group match")
	}

	t.Logf("Found %d APT group matches:", len(matches))
	for _, m := range matches {
		t.Logf("  %s (%s): similarity=%.3f, confidence=%s, overlap=%v",
			m.GroupName, m.GroupID, m.Similarity, m.Confidence, m.OverlapTech)
	}
}

func TestPredictiveRisk(t *testing.T) {
	k := NewKernel()
	attck := NewATTACKModule()
	if err := attck.Init(k.Context(), KernelContext(k)); err != nil {
		t.Fatalf("init attck: %v", err)
	}

	detected := []string{"T1190", "T1059"}
	prediction := attck.PredictRisk("test-host", detected, 2)

	if len(prediction.PredictedPaths) == 0 {
		t.Fatal("expected at least 1 predicted path")
	}

	t.Logf("Max Risk: %.3f", prediction.MaxRiskScore)
	t.Logf("Enhanced Threat Coeff: %.3f", prediction.EnhancedThreat)
	t.Logf("Recommendations: %v", prediction.Recommendations)

	if prediction.EnhancedThreat < 0.75 {
		t.Errorf("enhanced threat below minimum: %.3f", prediction.EnhancedThreat)
	}
}

func TestKillChainAssessment(t *testing.T) {
	attck := NewATTACKModule()

	checkResults := map[string]bool{
		"AS-001": true, "AS-002": true, "AS-003": true,
		"OT-001": true, "OT-002": true, "OT-004": true,
		"OT-005": false, "OT-006": false,
		"RS-001": true, "RS-006": false, "RS-010": true,
		"BC-005": true, "BC-006": true,
	}

	assessment := attck.AssessKillChain("test-host", checkResults)

	if len(assessment.Stages) != 9 {
		t.Fatalf("expected 9 kill chain stages, got %d", len(assessment.Stages))
	}

	t.Logf("Overall Kill Chain Score: %.2f", assessment.OverallScore)
	t.Logf("Weakest Stage: %s", assessment.WeakestStage)

	for _, stage := range assessment.Stages {
		t.Logf("  %s: score=%.2f, status=%s, checks=%d/%d",
			stage.Name, stage.Score, stage.Status, stage.ChecksPassed, stage.ChecksTotal)
	}
}
