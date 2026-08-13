package oscal

import (
	"github.com/asscor/asscor/internal/kernel"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/model"
)

func TestOSCALExport_JSON(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:     "host-001",
		Hostname:   "web-server-01",
		Timestamp:  time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		FinalScore: 85.5,
		Acceptable: true,
		Threshold:  80.0,
		DomainScores: model.DomainScores{
			AttackSurface:      90.0,
			BusinessContinuity: 85.0,
			OperationTrust:     80.0,
			Resilience:         87.0,
		},
		ThreatCoeff: 1.0,
		SPCScore:    0.92,
		PrismScore:  82.0,
		PrismSemanticState:  "stable",
		PrismStableMem:      0.75,
		PrismDegradedMem:    0.15,
		PrismUntrustedMem:   0.07,
		PrismCollapseMem:    0.03,
		PrismInferenceTrend:        "stable",
		PrismInferenceConfidence:   0.85,
		PrismInferenceCollapseRisk: 0.05,
		PrismInferenceModel:        "MarkovChain",
		PrismInferenceHorizonDays:  30,
		PrismRiskVelocity:          0.5,
		PrismExternalRisk:          0.18,
		Checks: []model.CheckResult{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "Unnecessary Services", Passed: true, Delta: 5.0, Detail: "All services are necessary"},
			{CheckID: "BC-001", Domain: "business_continuity", Name: "Backup Verification", Passed: false, Delta: -10.0, Detail: "No backup found"},
			{CheckID: "OT-001", Domain: "operation_trust", Name: "File Permissions", Passed: true, Delta: 5.0, Detail: "Permissions correct"},
			{CheckID: "RS-001", Domain: "resilience", Name: "SYN Cookie", Passed: true, Delta: 5.0, Detail: "SYN cookies enabled"},
		},
	}

	data, err := ExportOSCAL(result, "json")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal JSON failed: %v", err)
	}

	// Validate metadata
	if doc.Metadata.Title == "" {
		t.Error("expected non-empty metadata title")
	}
	if doc.Metadata.OSCALVersion != "1.1.0" {
		t.Errorf("expected oscal version 1.1.0, got %s", doc.Metadata.OSCALVersion)
	}

	// Validate results
	if len(doc.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(doc.Results))
	}
	resultEntry := doc.Results[0]

	// Validate findings (1 overall + 4 domains)
	if len(resultEntry.Findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(resultEntry.Findings))
	}

	// Validate observations
	if len(resultEntry.Observations) != 4 {
		t.Errorf("expected 4 observations, got %d", len(resultEntry.Observations))
	}

	// Validate risks (SSAM + Prism + SPC)
	if len(resultEntry.Risks) != 3 {
		t.Errorf("expected 3 risks, got %d", len(resultEntry.Risks))
	}
}

func TestOSCALExport_XML(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:     "host-002",
		Hostname:   "db-server-01",
		Timestamp:  time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		FinalScore: 55.0,
		Acceptable: false,
		Threshold:  80.0,
		DomainScores: model.DomainScores{
			AttackSurface:      60.0,
			BusinessContinuity: 50.0,
			OperationTrust:     55.0,
			Resilience:         55.0,
		},
		PrismScore:           52.0,
		PrismSemanticState:   "degraded",
		PrismInferenceTrend:  "degrading",
		PrismInferenceCollapseRisk: 0.35,
		PrismRiskVelocity:    -2.1,
		Checks: []model.CheckResult{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "Unnecessary Services", Passed: false, Delta: -10.0, Detail: "Found unnecessary services"},
		},
	}

	data, err := ExportOSCAL(result, "xml")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Verify XML header
	if !strings.HasPrefix(string(data), xml.Header) {
		t.Error("expected XML header")
	}

	// Verify XML parseable
	var doc OSCALAssessmentResults
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal XML failed: %v", err)
	}

	if len(doc.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(doc.Results))
	}

	// Check risk status for degraded score
	risks := doc.Results[0].Risks
	if len(risks) < 2 {
		t.Fatalf("expected at least 2 risks, got %d", len(risks))
	}
}

func TestOSCALExport_InvalidFormat(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:    "host-001",
		Hostname:  "test",
		Timestamp: time.Now(),
	}

	_, err := ExportOSCAL(result, "yaml")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestOSCAL_RiskStatusMapping(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{95.0, "satisfied"},
		{80.0, "satisfied"},
		{75.0, "needs-attention"},
		{60.0, "needs-attention"},
		{55.0, "significant-deficiencies"},
		{40.0, "significant-deficiencies"},
		{35.0, "critical-deficiencies"},
		{0.0, "critical-deficiencies"},
	}

	for _, tc := range tests {
		got := riskStatusFromScore(tc.score)
		if got != tc.expected {
			t.Errorf("score %.1f: expected '%s', got '%s'", tc.score, tc.expected, got)
		}
	}
}

func TestOSCALExport_NoPrism(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:     "host-003",
		Hostname:   "simple-host",
		Timestamp:  time.Now(),
		FinalScore: 90.0,
		Acceptable: true,
		Threshold:  80.0,
		DomainScores: model.DomainScores{
			AttackSurface: 90.0,
		},
		Checks: []model.CheckResult{},
	}

	data, err := ExportOSCAL(result, "json")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Only SSAM risk, no Prism or SPC
	if len(doc.Results[0].Risks) != 1 {
		t.Errorf("expected 1 risk (SSAM only), got %d", len(doc.Results[0].Risks))
	}
}

func TestOSCALExport_FromRecord(t *testing.T) {
	rec := &kernel.AssessmentRecord{
		Timestamp:  time.Now(),
		HostID:     "host-004",
		Hostname:   "from-record",
		FinalScore: 88.0,
		Acceptable: true,
		Threshold:  80.0,
	}

	data, err := ExportOSCALFromRecord(rec, "json")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if doc.Results[0].Findings[0].Risk.Score != 88.0 {
		t.Errorf("expected risk score 88.0, got %.1f", doc.Results[0].Findings[0].Risk.Score)
	}
}

func TestOSCALExport_ObservationsHaveMethods(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:    "host-005",
		Hostname:  "test",
		Timestamp: time.Now(),
		Checks: []model.CheckResult{
			{CheckID: "AS-001", Domain: "attack_surface", Name: "Test", Passed: true, Delta: 0, Detail: "ok"},
			{CheckID: "KS-001", Domain: "kernel_security", Name: "Kernel Test", Passed: true, Delta: 0, Detail: "ok"},
			{CheckID: "BC-001", Domain: "business_continuity", Name: "BC Test", Passed: false, Delta: -5, Detail: "failed"},
		},
	}

	data, err := ExportOSCAL(result, "json")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	obs := doc.Results[0].Observations
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}

	// Attack surface and kernel checks should have TEST method
	for _, o := range obs {
		if len(o.Methods) == 0 {
			t.Errorf("observation %s has no methods", o.UUID)
		}
	}

	// Failed check should have relevant evidence
	failedObs := obs[2]
	if len(failedObs.RelevantEvidence) == 0 {
		t.Error("failed observation should have relevant evidence")
	}
}

func TestOSCALExport_PrismFields(t *testing.T) {
	result := &model.AssessmentResult{
		HostID:     "host-006",
		Hostname:   "prism-test",
		Timestamp:  time.Now(),
		FinalScore: 70.0,
		PrismScore: 65.0,
		PrismSemanticState:     "degraded",
		PrismStableMem:         0.20,
		PrismDegradedMem:       0.55,
		PrismUntrustedMem:      0.15,
		PrismCollapseMem:       0.10,
		PrismInferenceTrend:           "degrading",
		PrismInferenceConfidence:      0.72,
		PrismInferenceCollapseRisk:    0.30,
		PrismInferenceModel:           "MarkovChain",
		PrismInferenceHorizonDays:     30,
		PrismRiskVelocity:             -1.5,
		PrismExternalRisk:             0.35,
		Checks: []model.CheckResult{},
	}

	data, err := ExportOSCAL(result, "json")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Find the Prism risk entry
	var foundPrismRisk bool
	for _, risk := range doc.Results[0].Risks {
		if strings.Contains(risk.Title, "Prism") {
			foundPrismRisk = true
			// Verify statement includes semantic and inference info
			if !strings.Contains(risk.Statement, "degraded") {
				t.Error("prism risk statement should mention semantic state")
			}
			if !strings.Contains(risk.Statement, "degrading") {
				t.Error("prism risk statement should mention inference trend")
			}
			// Verify props contain all prism fields
			propNames := make(map[string]bool)
			for _, p := range risk.Props {
				propNames[p.Name] = true
			}
			requiredProps := []string{
				"prism-score", "semantic-state", "stable-membership",
				"degraded-membership", "untrusted-membership", "collapse-membership",
				"inference-trend", "inference-confidence", "inference-collapse-risk",
				"inference-model", "inference-horizon-days",
			}
			for _, rp := range requiredProps {
				if !propNames[rp] {
					t.Errorf("prism risk missing prop: %s", rp)
				}
			}
		}
	}
	if !foundPrismRisk {
		t.Error("expected Prism risk entry in OSCAL output")
	}
}