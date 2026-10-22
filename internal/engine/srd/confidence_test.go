//go:build engine

package srd

import (
	"context"
	"math"
	"testing"
	"time"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
)

// newConfidencePipeline wires a parsed kernel [confidence] rule table into an
// SRD pipeline, mirroring what the kernel does through GetConfigObj.
func newConfidencePipeline(t *testing.T, ini string) *Pipeline {
	t.Helper()
	kcfg, err := kernelconfig.Parse(ini)
	if err != nil {
		t.Fatalf("Parse confidence config: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Confidence = &kcfg.Confidence
	return NewPipeline(cfg)
}

// TestExternalToolIDResolvesSourceTable is the I-8 contract: the SRD side must
// consult the SAME rule table as the kernel. A failing item with no confidence
// of its own, from tool "nuclei", resolves via [confidence.source] nuclei=0.65
// into prism.CheckFailure.Confidence. Before the fix it stayed 0.
func TestExternalToolIDResolvesSourceTable(t *testing.T) {
	p := newConfidencePipeline(t, `
[confidence]
enabled = true

[confidence.source]
nuclei = 0.65
`)
	now := time.Now()
	p.Process(context.Background(), &ExternalAssessmentReport{
		Tool:     "nuclei",
		HostID:   "h1",
		ScanTime: now,
		Items: []ExternalCheckResult{
			{CheckID: "N-1", Result: "fail", Delta: -10, FailAt: now.Unix()},
		},
	})
	p.mu.RLock()
	node := p.snapshots["h1"]
	p.mu.RUnlock()
	if node == nil || len(node.FailedChecks) != 1 {
		t.Fatalf("expected 1 failed check, got %+v", node)
	}
	if got := node.FailedChecks[0].Confidence; math.Abs(got-0.65) > 1e-9 {
		t.Errorf("CheckFailure.Confidence = %v, want 0.65 (tool id → [confidence.source])", got)
	}
}

// TestExternalToolIDConfidencePrecedence pins the full I-8 order:
// tool-supplied confidence > [confidence.source] (keyed by tool id) > default.
// The disabled case stays bit-identical (0 passthrough, legacy).
func TestExternalToolIDConfidencePrecedence(t *testing.T) {
	cases := []struct {
		name, ini, tool string
		toolConfidence  float64
		want            float64
	}{
		{
			name: "tool-supplied wins over source table",
			ini:  "[confidence]\nenabled = true\n\n[confidence.source]\nnuclei = 0.65\n",
			tool: "nuclei", toolConfidence: 0.42, want: 0.42,
		},
		{
			name: "unlisted tool falls back to default",
			ini:  "[confidence]\nenabled = true\ndefault = 0.85\n",
			tool: "some-other-tool", want: 0.85,
		},
		{
			name: "disabled config keeps legacy passthrough (0)",
			ini:  "[confidence]\nenabled = false\n\n[confidence.source]\nnuclei = 0.65\n",
			tool: "nuclei", want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newConfidencePipeline(t, tc.ini)
			now := time.Now()
			p.Process(context.Background(), &ExternalAssessmentReport{
				Tool:     tc.tool,
				HostID:   "h1",
				ScanTime: now,
				Items: []ExternalCheckResult{
					{CheckID: "N-1", Result: "fail", Delta: -10, FailAt: now.Unix(), Confidence: tc.toolConfidence},
				},
			})
			p.mu.RLock()
			node := p.snapshots["h1"]
			p.mu.RUnlock()
			if node == nil || len(node.FailedChecks) != 1 {
				t.Fatalf("expected 1 failed check, got %+v", node)
			}
			if got := node.FailedChecks[0].Confidence; math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("CheckFailure.Confidence = %v, want %v", got, tc.want)
			}
		})
	}
}

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
