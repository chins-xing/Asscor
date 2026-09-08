package config

import (
	"strings"
	"testing"
)

// TestValidateRangesRejectsOutOfRange (audit M-6): malformed numeric values
// must fail Parse fast instead of silently poisoning the scoring formulas.
func TestValidateRangesRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name    string
		ini     string
		wantSub string
	}{
		{"negative weight", "[weights]\nattack_surface = -5\n", "[weights] attack_surface"},
		{"zero threshold", "[acceptability]\nthreshold = 0\n", "threshold"},
		{"threshold over 100", "[acceptability]\nthreshold = 150\n", "threshold"},
		{"non-positive threat", "[threat]\ncoefficient = 0\n", "coefficient"},
		{"ACI below -100", "[resilience]\naci_laps_enabled = -200\n", "aci_laps_enabled"},
		{"ACI positive (not a penalty)", "[resilience]\naci_edr_running = 10\n", "aci_edr_running"},
		{"positive check delta", "[check_deltas]\nAS-001 = 5\n", "as-001"},
		{"check delta too negative", "[check_deltas]\nAS-001 = -500\n", "as-001"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.ini)
			if err == nil {
				t.Fatalf("Parse must fail for: %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q should mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateRangesAcceptsDefaults: the zero-value/default config passes.
func TestValidateRangesAcceptsDefaults(t *testing.T) {
	if err := Default().validateRanges(); err != nil {
		t.Fatalf("Default config must validate: %v", err)
	}
}

// TestValidateRangesAcceptsLegalConfig: a fully-specified legal config parses.
func TestValidateRangesAcceptsLegalConfig(t *testing.T) {
	ini := `
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15

[acceptability]
threshold = 80

[threat]
coefficient = 1.0

[resilience]
aci_network_segmentation = -15
aci_laps_enabled = -10

[check_deltas]
AS-001 = -8
OT-002 = -3
`
	cfg, err := Parse(ini)
	if err != nil {
		t.Fatalf("legal config must parse: %v", err)
	}
	if cfg.Threshold != 80 {
		t.Errorf("threshold = %v, want 80", cfg.Threshold)
	}
}
