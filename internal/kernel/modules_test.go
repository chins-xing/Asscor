package kernel

import (
	"testing"
	"time"

	"github.com/argus-security/argus/internal/model"
)

func TestWorkerPool(t *testing.T) {
	pool := NewWorkerPool(3)
	if got := pool.MaxConcurrency(); got != 3 {
		t.Fatalf("expected max 3, got %d", got)
	}

	completed := 0
	for i := 0; i < 10; i++ {
		pool.Submit(func() error {
			time.Sleep(10 * time.Millisecond)
			return nil
		})
	}
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalSubmitted != 10 {
		t.Fatalf("expected 10 submitted, got %d", metrics.totalSubmitted)
	}
	if metrics.totalCompleted != 10 {
		t.Fatalf("expected 10 completed, got %d", metrics.totalCompleted)
	}

	_ = completed
}

func TestWorkerPoolTimeout(t *testing.T) {
	pool := NewWorkerPool(2)

	pool.SubmitWithTimeout(func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}, 50*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalTimeout == 0 {
		t.Error("expected at least 1 timeout")
	}
}

func TestSPCModule(t *testing.T) {
	k := NewKernel()
	spc := NewSPCModule()
	spc.enabled = true

	if err := spc.Init(k.Context(), KernelContext(k)); err != nil {
		t.Fatalf("init spc: %v", err)
	}

	spc.FetchFromAllSources()

	if got := spc.GetCVECount(); got < 3 {
		t.Fatalf("expected at least 3 sample CVEs, got %d", got)
	}

	if got := spc.GetKEVCount(); got < 1 {
		t.Fatalf("expected at least 1 KEV CVE, got %d", got)
	}

	asset := LocalAsset{
		HostID:        "web-prod-01",
		Hostname:      "web-prod-01.example.com",
		Role:          "web-server",
		NetworkZone:   "dmz",
		InstalledCPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}
	asset.Compensations.WAFRules = true

	spc.UpsertAsset(asset)

	correction := spc.Calculate("web-prod-01", []string{"openssl", "nginx", "php"})

	t.Logf("P_score: %.3f", correction.Score)
	t.Logf("Action: %s", correction.Action)
	t.Logf("Top CVE: %s", correction.TopCVEImpact)
	t.Logf("Total Penalty: %.3f", correction.TotalPenalty)
	t.Logf("Affected CVEs: %v", correction.AffectedCVE)
	t.Logf("Weights: %v", correction.Weights)

	if correction.Score < 0.60 || correction.Score > 1.0 {
		t.Errorf("P_score out of range: %.3f", correction.Score)
	}

	if len(correction.AffectedCVE) == 0 {
		t.Error("expected at least 1 affected CVE")
	}

	if correction.TopCVEImpact == "" {
		t.Error("expected a top impact CVE")
	}
}

func TestSPCExactVersionMatch(t *testing.T) {
	spc := NewSPCModule()
	spc.enabled = true

	cve := SPCCVEScore{
		CVEID:         "CVE-2024-TEST",
		CVSS:          9.8,
		EPSS:          0.72,
		InKEV:         true,
		DatePublished: time.Now().AddDate(0, 0, -14),
		AffectedCPEs:  []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}
	spc.AddCVE(cve)

	asset := LocalAsset{
		HostID:        "test-host",
		NetworkZone:   "internal",
		InstalledCPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}

	matchType, matched := spc.matchCPE(&cve, &asset, nil)
	if !matched {
		t.Fatal("expected exact CPE match")
	}
	if matchType != MatchExactVersion {
		t.Fatalf("expected MatchExactVersion, got %d", matchType)
	}
}

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

func TestPersistenceModule(t *testing.T) {
	pm := NewPersistenceModule(t.TempDir())

	if pm.Info().Name != "persistence" {
		t.Fatalf("expected name 'persistence', got '%s'", pm.Info().Name)
	}

	rec := AssessmentRecord{
		Timestamp:  time.Now(),
		HostID:     "test-01",
		FinalScore: 85.5,
		Acceptable: true,
	}
	err := pm.Append("test_assessments", rec)
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}

	audit := AuditEntry{
		Timestamp: time.Now(),
		Actor:     "test",
		Action:    "write",
		Target:    "test",
		Success:   true,
	}
	err = pm.WriteAudit(audit)
	if err != nil {
		t.Fatalf("write audit failed: %v", err)
	}

	pm.mu.Lock()
	for _, w := range pm.writers {
		w.sync()
		w.close()
	}
	pm.mu.Unlock()
}

func TestSPCWeightShift(t *testing.T) {
	spc := NewSPCModule()
	spc.enabled = true

	cves := []SPCCVEScore{
		{
			CVEID:   "CVE-A", CVSS: 9.0, EPSS: 0.5,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposurePublic,
		},
		{
			CVEID:   "CVE-B", CVSS: 8.0, EPSS: 0.3,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposurePublic,
		},
		{
			CVEID:   "CVE-C", CVSS: 7.0, EPSS: 0.2,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched: true, Exposure: ExposureDMZ,
		},
	}

	shift := spc.generateWeightShift([]string{"CVE-A", "CVE-B", "CVE-C"}, cves)

	if shift[model.DomainAttackSurface] != 5 {
		t.Errorf("expected attack_surface shift +5, got %.0f", shift[model.DomainAttackSurface])
	}
	if shift[model.DomainBusinessContinuity] != -3 {
		t.Errorf("expected business_continuity shift -3, got %.0f", shift[model.DomainBusinessContinuity])
	}
	if shift[model.DomainResilience] != -2 {
		t.Errorf("expected resilience shift -2, got %.0f", shift[model.DomainResilience])
	}

	var sum float64
	for _, v := range shift {
		sum += v
	}
	if sum != 0 {
		t.Errorf("weight shift sum should be 0, got %.0f", sum)
	}
}