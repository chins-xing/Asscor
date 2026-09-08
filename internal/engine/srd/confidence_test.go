//go:build engine

package srd

import (
	"context"
	"math"
	"testing"
	"time"
)

// TestExternalReportConfidenceToCheckFailure: a failed external finding with
// an explicit confidence must reach prism.CheckFailure.Confidence; without
// one (0) it is left as-is (prism treats 0 as full trust — legacy).
func TestExternalReportConfidenceToCheckFailure(t *testing.T) {
	cfg := DefaultConfig()
	p := NewPipeline(cfg)

	now := time.Now()
	report := &ExternalAssessmentReport{
		Tool:     "test-tool",
		HostID:   "h1",
		ScanTime: now,
		RawScore: 80,
		Items: []ExternalCheckResult{
			{CheckID: "A-1", Result: "fail", Delta: -10, FailAt: now.Unix(), Confidence: 0.4},
			{CheckID: "A-2", Result: "fail", Delta: -5, FailAt: now.Unix()}, // 0 → full trust
			{CheckID: "A-3", Result: "pass", Delta: 0},
		},
	}
	res := p.Process(context.Background(), report)
	if res == nil {
		t.Fatal("Process returned nil")
	}
	// Process → NodeState snapshot; inspect the stored snapshot.
	p.mu.RLock()
	node := p.snapshots["h1"]
	p.mu.RUnlock()
	if node == nil {
		t.Fatal("no node snapshot stored")
	}
	if len(node.FailedChecks) != 2 {
		t.Fatalf("failed checks = %d, want 2", len(node.FailedChecks))
	}
	if node.FailedChecks[0].CheckID != "A-1" || math.Abs(node.FailedChecks[0].Confidence-0.4) > 1e-9 {
		t.Errorf("A-1 confidence = %v, want 0.4", node.FailedChecks[0].Confidence)
	}
	if math.Abs(node.FailedChecks[1].Confidence-0.0) > 1e-9 {
		t.Errorf("A-2 (unspecified) confidence must stay 0, got %v", node.FailedChecks[1].Confidence)
	}
	// report confidence = mean of failed items' confidences where set = 0.4/1 = 0.4
	if math.Abs(node.Confidence-0.4) > 1e-9 {
		t.Errorf("node confidence = %v, want 0.4", node.Confidence)
	}
}

// TestReportConfidenceNoFailedUnspecified: no failed items or all-unspecified
// → report confidence 1 (legacy).
func TestReportConfidenceDefaults(t *testing.T) {
	now := time.Now()
	allPass := &ExternalAssessmentReport{ScanTime: now, Items: []ExternalCheckResult{{Result: "pass"}}}
	if got := reportConfidence(allPass); got != 1.0 {
		t.Errorf("no-fail report confidence = %v, want 1", got)
	}
	unspecified := &ExternalAssessmentReport{ScanTime: now, Items: []ExternalCheckResult{{Result: "fail", Confidence: 0}}}
	if got := reportConfidence(unspecified); got != 1.0 {
		t.Errorf("all-unspecified confidence = %v, want 1", got)
	}
}

// TestGenericBuildFromItemsConfidence: the generic adapter carries through a
// tool-supplied confidence into the normalized finding.
func TestGenericBuildFromItemsConfidence(t *testing.T) {
	a := &genericAdapter{}
	items := []GenericCheckItem{
		{ID: "X-1", Title: "t", Result: "fail", Severity: "high", Confidence: 0.55},
		{ID: "X-2", Title: "t2", Result: "fail", Severity: "low"},
	}
	report, err := a.buildFromItems(items, GenericProfile)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(report.Items[0].Confidence-0.55) > 1e-9 {
		t.Errorf("item X-1 confidence = %v, want 0.55", report.Items[0].Confidence)
	}
	if report.Items[1].Confidence != 0 {
		t.Errorf("item X-2 (unspecified) confidence must be 0, got %v", report.Items[1].Confidence)
	}
}
