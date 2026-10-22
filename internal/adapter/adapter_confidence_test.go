package adapter

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// nucleiSourceIni is the audit's reproduction (verdict B-1/S19): an external
// tool finding is tagged source=nuclei, and the operator lowers that source's
// confidence to 0.65 in the rule table. Unless ToCheckResult carries Source
// through, ResolveChecks maps the empty source to "builtin" and nuclei never
// matches.
const nucleiSourceIni = `
[confidence]
enabled = true

[confidence.source]
nuclei = 0.65
`

// TestNormalizedFindingToCheckResultCarriesSource: a third-party finding's
// source must survive the model conversion, otherwise the [confidence.source]
// table can never match external scanners (verdict B-1).
func TestNormalizedFindingToCheckResultCarriesSource(t *testing.T) {
	f := NormalizedFinding{
		CheckID:  "AS-005",
		Domain:   "attack_surface",
		Source:   "nuclei",
		Title:    "web vuln",
		Severity: SeverityHigh,
	}
	r := f.ToCheckResult()
	if string(r.Source) != "nuclei" {
		t.Errorf("ToCheckResult Source = %q, want %q", r.Source, "nuclei")
	}
}

// TestExternalFindingResolvedBySourceTable is the audit's headline case:
// source=nuclei + [confidence.source] nuclei=0.65 must resolve to 0.65 and
// keep the source key on the result.
func TestExternalFindingResolvedBySourceTable(t *testing.T) {
	cfg, err := config.Parse(nucleiSourceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	f := NormalizedFinding{
		CheckID:  "AS-005",
		Domain:   "attack_surface",
		Source:   "nuclei",
		Title:    "web vuln",
		Severity: SeverityHigh,
		Passed:   false,
	}
	checks := []model.CheckResult{f.ToCheckResult()}
	cfg.ResolveChecks(checks)

	if got := string(checks[0].Source); got != "nuclei" {
		t.Errorf("resolved Source = %q, want %q", got, "nuclei")
	}
	if math.Abs(checks[0].Confidence-0.65) > 1e-9 {
		t.Errorf("resolved Confidence = %v, want 0.65 (source table must match nuclei)", checks[0].Confidence)
	}
}

// TestNormalizedFindingToCheckResultCarriesToolConfidence: a tool's own
// confidence must reach CheckResult.Confidence (>0 = already resolved, so the
// rule table leaves it alone; 0 = unspecified, resolved by source table).
func TestNormalizedFindingToCheckResultCarriesToolConfidence(t *testing.T) {
	f := NormalizedFinding{
		CheckID:    "AS-005",
		Domain:     "attack_surface",
		Source:     "nuclei",
		Title:      "web vuln",
		Confidence: 0.42,
	}
	r := f.ToCheckResult()
	if math.Abs(r.Confidence-0.42) > 1e-9 {
		t.Errorf("ToCheckResult Confidence = %v, want 0.42 (tool-supplied)", r.Confidence)
	}

	// Explicit confidence wins over the source table (Resolve precedence).
	cfg, err := config.Parse(nucleiSourceIni)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	checks := []model.CheckResult{r}
	cfg.ResolveChecks(checks)
	if math.Abs(checks[0].Confidence-0.42) > 1e-9 {
		t.Errorf("explicit confidence = %v, want 0.42 preserved over source 0.65", checks[0].Confidence)
	}
}

// TestExternalFindingDisabledConfigLeavesConfidenceUntouched: the default
// (Enabled=false) path must stay bit-identical. Even though the conversion now
// carries Source=nuclei, a disabled rule table may not fill Confidence: it
// stays 0 exactly as before B-1 (downstream treats 0 as full trust).
func TestExternalFindingDisabledConfigLeavesConfidenceUntouched(t *testing.T) {
	cfg, err := config.Parse(`
[confidence]
enabled = false

[confidence.source]
nuclei = 0.65
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	checks := []model.CheckResult{NormalizedFinding{
		CheckID: "AS-005", Domain: "attack_surface", Source: "nuclei", Title: "web vuln",
	}.ToCheckResult()}
	cfg.ResolveChecks(checks)
	if checks[0].Confidence != 0 {
		t.Errorf("disabled config touched Confidence: got %v, want 0 (bit-identical default path)", checks[0].Confidence)
	}
	if string(checks[0].Source) != "nuclei" {
		t.Errorf("Source = %q, want nuclei (source is a label, not a score)", checks[0].Source)
	}
}

// TestToCheckResultKeepsUnspecifiedSourceEmpty pins the legacy conversion:
// findings without a source keep Source == "" so ResolveChecks still maps them
// to "builtin" exactly as before B-1 (default path unchanged).
func TestToCheckResultKeepsUnspecifiedSourceEmpty(t *testing.T) {
	f := NormalizedFinding{CheckID: "AS-001", Domain: "attack_surface", Title: "t"}
	if got := string(f.ToCheckResult().Source); got != "" {
		t.Errorf("unspecified source = %q, want empty (legacy)", got)
	}
}
