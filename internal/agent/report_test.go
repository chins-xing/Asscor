package agent

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written to stdout. The reader goroutine drains the pipe so fn's
// output can never block.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	outCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outCh <- buf.String()
	}()
	defer func() {
		os.Stdout = old
	}()
	fn()
	w.Close()
	return <-outCh
}

// ---------------------------------------------------------------------------
// printAssessmentReport — output-shape tests (gap report §2.3). Assertions are
// key-line substrings, not full snapshots, to keep maintenance cost low.
// ---------------------------------------------------------------------------

func newReportAgent() *Agent {
	return &Agent{cfg: AgentConfig{CheckIntervalSec: 3600}}
}

// TestPrintAssessmentReportBarBounds: the score bar is capped at the bar width
// for 0 / 100 / >100 scores (gap report §2.3 boundary cases).
func TestPrintAssessmentReportBarBounds(t *testing.T) {
	a := newReportAgent()
	result := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{
			"resilience":          0,
			"attack_surface":      100,
			"business_continuity": 150, // >100 must be capped at width
			"operation_trust":     55,
		},
		Acceptable:  true,
		FinalScore:  60,
		ThreatCoeff: 1.0,
		SpcScore:    0.5,
		Checks:      []*apiv1.CheckResult{},
	}

	out := captureStdout(t, func() { a.printAssessmentReport(result) })

	if !strings.Contains(out, "[                    ] 0/100") {
		t.Errorf("score 0 must render an empty bar:\n%s", out)
	}
	if !strings.Contains(out, "[====================] 100/100") {
		t.Errorf("score 100 must render a full bar:\n%s", out)
	}
	if !strings.Contains(out, "[====================] 150/100") {
		t.Errorf("score 150 must cap the bar at full width:\n%s", out)
	}
	if !strings.Contains(out, "[===========         ] 55/100") {
		t.Errorf("score 55 must render 11 of 20 filled:\n%s", out)
	}
}

// TestPrintAssessmentReportSpcCVESortAndTruncate: SPC CVEs are printed in
// descending CVSS order and truncated at 15 with a "... and N more" tail.
func TestPrintAssessmentReportSpcCVESortAndTruncate(t *testing.T) {
	a := newReportAgent()
	cves := make([]apiv1.SPCCVEInfo, 20)
	for i := range cves {
		// CVSS ascending (i+1): the list as built is UNSORTED in descending
		// order, so printAssessmentReport's sort.Slice must reorder it.
		cves[i] = apiv1.SPCCVEInfo{
			CVEID:   fmt.Sprintf("CVE-20%02d", i),
			CVSS:    float64(i + 1),
			EPSS:    0.5,
			Penalty: 0.01,
		}
	}
	// CVE-2019 (CVSS 20.0) is the max and sits last; it must sort first.
	// Give it tags + product to verify they render on the top line.
	cves[19] = apiv1.SPCCVEInfo{CVEID: "CVE-2019", CVSS: 20.0, EPSS: 0.9, Penalty: 0.02, InKEV: true, HasPoC: true, Product: "openssl"}

	result := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{"resilience": 50},
		Acceptable:   true,
		FinalScore:   60,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		SpcCVEs:      cves,
		Checks:       []*apiv1.CheckResult{},
	}

	out := captureStdout(t, func() { a.printAssessmentReport(result) })

	if !strings.Contains(out, "[ SPC: Matched CVEs (20) ]") {
		t.Errorf("CVE count header missing:\n%s", out)
	}
	// Highest CVSS (CVE-2019, 20.0) must print before the next one (CVE-2018).
	highIdx := strings.Index(out, "CVE-2019  CVSS:20.0")
	nextIdx := strings.Index(out, "CVE-2018  CVSS:19.0")
	if highIdx < 0 {
		t.Errorf("highest-CVSS CVE missing from output:\n%s", out)
	} else if nextIdx >= 0 && highIdx > nextIdx {
		t.Errorf("CVEs must be sorted by CVSS descending (highest first):\n%s", out)
	}
	// Tags and product render on the top line.
	if !strings.Contains(out, "[KEV] [PoC]") || !strings.Contains(out, "(openssl)") {
		t.Errorf("KEV/PoC tags and product must render:\n%s", out)
	}
	// 20 CVEs → 15 shown + "and 5 more".
	if !strings.Contains(out, "... and 5 more") {
		t.Errorf("truncation tail missing:\n%s", out)
	}
	// The 15th shown is CVE-2005 (CVSS 6.0); CVE-2004 (5.0) must be truncated.
	if !strings.Contains(out, "CVE-2005  CVSS:6.0") {
		t.Errorf("15th CVE should still be shown:\n%s", out)
	}
	if strings.Contains(out, "CVE-2004  CVSS:5.0") {
		t.Errorf("CVE beyond the 15-entry cap must be truncated:\n%s", out)
	}
}

// TestPrintAssessmentReportFinalScoreStates: ThreatCoeff/SpcScore zero fall
// back to 1.0 with a pending-data-sync hint; non-zero scores render plainly;
// Acceptable=false renders NOT ACCEPTABLE.
func TestPrintAssessmentReportFinalScoreStates(t *testing.T) {
	a := newReportAgent()

	// Zero coeff/score → 1.0 fallback + pending hint.
	zero := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{},
		Acceptable:   true,
		FinalScore:   77.5,
		ThreatCoeff:  0,
		SpcScore:     0,
		Checks:       []*apiv1.CheckResult{},
	}
	out := captureStdout(t, func() { a.printAssessmentReport(zero) })
	if !strings.Contains(out, "Final Score: 77.50/100    Status: ACCEPTABLE") {
		t.Errorf("final score line wrong:\n%s", out)
	}
	if !strings.Contains(out, "Threat Coeff: 1.00    SPC Score: 1.00 (pending data sync)") {
		t.Errorf("zero coeff/score must fall back to 1.00 with pending hint:\n%s", out)
	}

	// Non-zero scores render plainly (no pending hint).
	plain := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{},
		Acceptable:   false,
		FinalScore:   41.25,
		ThreatCoeff:  1.4,
		SpcScore:     0.6,
		Checks:       []*apiv1.CheckResult{},
	}
	out2 := captureStdout(t, func() { a.printAssessmentReport(plain) })
	if !strings.Contains(out2, "Final Score: 41.25/100    Status: NOT ACCEPTABLE") {
		t.Errorf("final score line wrong:\n%s", out2)
	}
	if !strings.Contains(out2, "Threat Coeff: 1.40    SPC Score: 0.60") {
		t.Errorf("plain coeff/score render missing:\n%s", out2)
	}
	if strings.Contains(out2, "pending data sync") {
		t.Errorf("non-zero scores must not show the pending hint:\n%s", out2)
	}
}

// TestPrintAssessmentReportEdgeFactors: only factors below 1.0 are shown, with
// the friendly name for two_factor_failure and an ACTIVE marker.
func TestPrintAssessmentReportEdgeFactors(t *testing.T) {
	a := newReportAgent()
	result := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{},
		Acceptable:   true,
		FinalScore:   60,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		EdgeFactors: map[string]float64{
			"two_factor_failure":  0.8,  // < 1.0 → shown
			"no_siem":             1.0,  // == 1.0 → hidden
			"no_ids":              1.25, // > 1.0 → hidden
		},
		Checks: []*apiv1.CheckResult{},
	}
	out := captureStdout(t, func() { a.printAssessmentReport(result) })
	if !strings.Contains(out, "2FA Missing") || !strings.Contains(out, "factor=0.80 (ACTIVE)") {
		t.Errorf("active edge factor must render with friendly name:\n%s", out)
	}
	if strings.Contains(out, "no_siem") || strings.Contains(out, "no_ids") {
		t.Errorf("factors >= 1.0 must be hidden:\n%s", out)
	}

	// No active factors → "(none)".
	none := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{},
		Acceptable:   true,
		FinalScore:   60,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		EdgeFactors:  map[string]float64{"no_siem": 1.0},
		Checks:       []*apiv1.CheckResult{},
	}
	out2 := captureStdout(t, func() { a.printAssessmentReport(none) })
	if !strings.Contains(out2, "(none)") {
		t.Errorf("no active edge factors must render (none):\n%s", out2)
	}
}

// TestPrintAssessmentReportPassRate: all-fail and all-pass check sets render
// [FAIL] / [PASS] lines accordingly, and user-sourced checks are tagged [user].
func TestPrintAssessmentReportPassRate(t *testing.T) {
	a := newReportAgent()

	allFail := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{"resilience": 20},
		Acceptable:   false,
		FinalScore:   30,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		Checks: []*apiv1.CheckResult{
			{CheckId: "KS-001", Domain: "kernel_security", Name: "No Fail2ban", Passed: false, Delta: -2, Detail: "not installed"},
			{CheckId: "KS-002", Domain: "kernel_security", Name: "No Auditd", Passed: false, Delta: -2, Detail: "not installed"},
		},
	}
	out := captureStdout(t, func() { a.printAssessmentReport(allFail) })
	if strings.Count(out, "[FAIL]") != 2 {
		t.Errorf("all-fail set must render 2 [FAIL] lines:\n%s", out)
	}
	if strings.Contains(out, "[PASS]") {
		t.Errorf("all-fail set must render no [PASS] lines:\n%s", out)
	}

	allPass := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{"attack_surface": 95},
		Acceptable:   true,
		FinalScore:   90,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		Checks: []*apiv1.CheckResult{
			{CheckId: "AS-001", Domain: "attack_surface", Name: "SSH Config", Passed: true, Delta: 0, Detail: "ok", Source: "user"},
			{CheckId: "AS-002", Domain: "attack_surface", Name: "Open Ports", Passed: true, Delta: 0, Detail: "ok"},
		},
	}
	out2 := captureStdout(t, func() { a.printAssessmentReport(allPass) })
	if strings.Count(out2, "[PASS]") != 2 {
		t.Errorf("all-pass set must render 2 [PASS] lines:\n%s", out2)
	}
	if strings.Contains(out2, "[FAIL]") {
		t.Errorf("all-pass set must render no [FAIL] lines:\n%s", out2)
	}
	// Source=="user" check is tagged for operators.
	if !strings.Contains(out2, "[PASS] [user] AS-001") {
		t.Errorf("user-sourced check must carry the [user] tag:\n%s", out2)
	}
	if strings.Contains(out2, "[user] AS-002") {
		t.Errorf("builtin check must not carry the [user] tag:\n%s", out2)
	}
}

// TestPrintAssessmentReportCheckDetailVariants: checks with and without Detail
// both render without panicking.
func TestPrintAssessmentReportCheckDetailVariants(t *testing.T) {
	a := newReportAgent()
	result := &apiv1.AssessmentResult{
		DomainScores: map[string]float64{"resilience": 50},
		Acceptable:   true,
		FinalScore:   60,
		ThreatCoeff:  1.0,
		SpcScore:     0.5,
		Checks: []*apiv1.CheckResult{
			{CheckId: "OT-001", Domain: "operation_trust", Name: "No Detail Check", Passed: true},
			{CheckId: "OT-002", Domain: "operation_trust", Name: "With Detail", Passed: false, Detail: "missing"},
		},
	}
	out := captureStdout(t, func() { a.printAssessmentReport(result) })
	if !strings.Contains(out, "No Detail Check") || !strings.Contains(out, "missing") {
		t.Errorf("check detail variants must both render:\n%s", out)
	}
}
