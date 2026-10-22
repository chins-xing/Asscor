//go:build engine

package adapter_test

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/adapter"
	"github.com/chins-xing/asscor/internal/config"
	enginessam "github.com/chins-xing/asscor/internal/engine/ssam"
	"github.com/chins-xing/asscor/internal/model"
)

// TestExternalFindingDomainDeductionUsesSourceConfidence is the end-to-end
// proof for verdict B-1: an external (nuclei) finding travels
//
//	NormalizedFinding -> ToCheckResult -> ResolveChecks -> CheckInput -> domain score
//
// and the domain deduction must use the source-table confidence 0.65 instead
// of 1.0. A high-severity failure is -15 in adapter.severityToDelta, so the
// domain score is 100-15*0.65 = 90.25 (legacy/ignored source: 85).
func TestExternalFindingDomainDeductionUsesSourceConfidence(t *testing.T) {
	cfg, err := config.Parse(`
[confidence]
enabled = true

[confidence.source]
nuclei = 0.65
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	f := adapter.NormalizedFinding{
		CheckID:  "AS-005",
		Domain:   "attack_surface",
		Source:   "nuclei",
		Title:    "web vuln",
		Severity: adapter.SeverityHigh,
		Passed:   false,
	}
	checks := []model.CheckResult{f.ToCheckResult()}
	cfg.ResolveChecks(checks)

	inputs := enginessam.CheckResultsToInputs(checks)
	scores := enginessam.ComputeDomainScoresBayes(
		enginessam.ConfigToWeights(cfg),
		inputs,
		enginessam.ConfigToConfidencePolicy(cfg),
	)

	const want = 100 - 15*0.65 // 90.25
	var got float64
	found := false
	for _, ds := range scores {
		if ds.Domain == "attack_surface" {
			got = ds.Score
			found = true
		}
	}
	if !found {
		t.Fatalf("no attack_surface domain score in %+v", scores)
	}
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("domain score = %v, want %v (deduction at 0.65, not 1.0 → 85)", got, want)
	}
}
