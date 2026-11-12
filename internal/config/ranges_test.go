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
		// Audit D-02: NaN compares false against every bound, so it used to
		// pass every range check and poison scoring downstream.
		{"NaN weight", "[weights]\nattack_surface = NaN\n", "attack_surface"},
		{"NaN threshold", "[acceptability]\nthreshold = NaN\n", "threshold"},
		{"NaN threat", "[threat]\ncoefficient = NaN\n", "coefficient"},
		{"NaN ACI", "[resilience]\naci_laps_enabled = NaN\n", "aci_laps_enabled"},
		{"NaN edge factor", "[edge_factors]\ntwo_factor_failure = NaN\n", "two_factor_failure"},
		{"NaN check delta", "[check_deltas]\nAS-001 = NaN\n", "as-001"},
		{"NaN spc min_pscore", "[spc]\nmin_pscore = NaN\n", "min_pscore"},
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

// TestEdgeFactorLevel4OverrideOnlyForLevel4 pins audit A11: the override is
// a Level-4 rule. At the default Level 3 the [edge_factors] value must win.
func TestEdgeFactorLevel4OverrideOnlyForLevel4(t *testing.T) {
	ini := func(framework string) string {
		return "[acceptability]\ncompliance_framework = " + framework + "\n\n" +
			"[edge_factors]\ntwo_factor_failure = 0.85\n\n" +
			"[edge_factors.level4_override]\ntwo_factor_failure = 0.70\n"
	}
	cases := []struct {
		framework string
		want      float64
	}{
		{"GB/T 22239-2019 Level 3", 0.85},
		{"GB/T 22239-2019 Level 4", 0.70},
		{"等保四级", 0.70},
		{"", 0.85},
	}
	for _, tc := range cases {
		cfg, err := Parse(ini(tc.framework))
		if err != nil {
			t.Fatalf("framework %q: %v", tc.framework, err)
		}
		if cfg.EdgeFactors.TwoFactorFailure != tc.want {
			t.Errorf("framework %q: two_factor_failure = %v, want %v", tc.framework, cfg.EdgeFactors.TwoFactorFailure, tc.want)
		}
	}
}
