package config

import (
	"fmt"
	"math"
)

// floatInvalid reports NaN/Inf, which comparison-based range checks cannot
// catch (every comparison with NaN is false). Audit D-02: a config with
// threshold = NaN or weight = NaN used to pass validation and poison every
// score downstream.
func floatInvalid(v float64) bool {
	return math.IsNaN(v) || math.IsInf(v, 0)
}

// validateRanges enforces value ranges on parsed numeric configuration so an
// out-of-range value cannot silently poison the scoring formulas (audit M-6).
// It runs after section parsing; violations return an error (fail-fast) so a
// misconfigured config.ini is caught at load instead of producing nonsense
// scores. Weights are normalized to sum 100 later, so individual weights are
// checked for non-negativity only.
func (cfg *Config) validateRanges() error {
	// Domain weights must be non-negative (sum normalized elsewhere).
	w := cfg.Weights
	for _, val := range []struct {
		name  string
		value float64
	}{
		{"attack_surface", w.AttackSurface},
		{"business_continuity", w.BusinessContinuity},
		{"operation_trust", w.OperationTrust},
		{"resilience", w.Resilience},
		{"kernel_security", w.KernelSecurity},
	} {
		if floatInvalid(val.value) || val.value < 0 {
			return fmt.Errorf("config: [weights] %s = %v must be >= 0", val.name, val.value)
		}
	}
	for domain, weight := range cfg.ExtensionWeights {
		if floatInvalid(weight) || weight < 0 {
			return fmt.Errorf("config: [extension_weights] %s = %v must be >= 0", domain, weight)
		}
	}

	// Acceptability threshold ∈ (0, 100].
	if floatInvalid(cfg.Threshold) || cfg.Threshold <= 0 || cfg.Threshold > 100 {
		return fmt.Errorf("config: [acceptability] threshold = %v must be in (0, 100]", cfg.Threshold)
	}

	// Threat coefficient ∈ (0, ...]: values above ~10 are extreme but legal;
	// the meaningful guard is "positive". SPC exposure clamps internally.
	if floatInvalid(cfg.ThreatCoeff) || cfg.ThreatCoeff <= 0 {
		return fmt.Errorf("config: [threat] coefficient = %v must be > 0", cfg.ThreatCoeff)
	}

	// ACI / resilience penalties are score deductions: ∈ [-100, 0].
	for _, val := range []struct {
		name  string
		value float64
	}{
		{"aci_network_segmentation", cfg.ACINetworkSegmentation},
		{"aci_laps_enabled", cfg.ACILAPSEnabled},
		{"aci_offline_backup", cfg.ACIOfflineBackup},
		{"aci_edr_running", cfg.ACIEDRRunning},
		{"aci_remote_logging", cfg.ACIRemoteLogging},
		{"aci_app_whitelist", cfg.ACIAppWhitelist},
		{"aci_dlp_measures", cfg.ACIDLPMeasures},
	} {
		if floatInvalid(val.value) || val.value < -100 || val.value > 0 {
			return fmt.Errorf("config: [resilience] %s = %v must be in [-100, 0] (a penalty)", val.name, val.value)
		}
	}

	// Edge factor penalties are multipliers ∈ (0, 1]; 1.0 = no penalty.
	for _, val := range []struct {
		name  string
		value float64
	}{
		{"two_factor_failure", cfg.EdgeFactors.TwoFactorFailure},
		{"syn_cookie_disabled", cfg.EdgeFactors.SYNCookieDisabled},
		{"selinux_disabled", cfg.EdgeFactors.SELinuxDisabled},
		{"apparmor_disabled", cfg.EdgeFactors.AppArmorDisabled},
		{"no_siem", cfg.EdgeFactors.NoSIEM},
		{"no_ids", cfg.EdgeFactors.NoIDS},
	} {
		if floatInvalid(val.value) || val.value <= 0 || val.value > 1 {
			return fmt.Errorf("config: edge factor %s = %v must be in (0, 1] (1 = no penalty)", val.name, val.value)
		}
	}

	// Per-check deltas are penalties: ∈ [-100, 0]; a positive delta would
	// inflate scores on failure.
	for id, d := range cfg.CheckDeltas {
		if floatInvalid(d) || d > 0 {
			return fmt.Errorf("config: [check_deltas] %s = %v must be <= 0 (a penalty)", id, d)
		}
		if floatInvalid(d) || d < -100 {
			return fmt.Errorf("config: [check_deltas] %s = %v must be >= -100", id, d)
		}
	}

	// SPC min_pscore and ATT&CK thresholds are model inputs too (D-02):
	// reject NaN/Inf and out-of-range values before they reach scoring.
	if floatInvalid(cfg.SPC.MinPScore) || cfg.SPC.MinPScore < 0 || cfg.SPC.MinPScore > 1 {
		return fmt.Errorf("config: [spc] min_pscore = %v must be in [0, 1]", cfg.SPC.MinPScore)
	}
	if floatInvalid(cfg.ATTACK.BeaconThreshold) || cfg.ATTACK.BeaconThreshold < 0 || cfg.ATTACK.BeaconThreshold > 1 {
		return fmt.Errorf("config: [attck] beacon_threshold = %v must be in [0, 1]", cfg.ATTACK.BeaconThreshold)
	}
	if floatInvalid(cfg.ATTACK.AttributionThreshold) || cfg.ATTACK.AttributionThreshold < 0 || cfg.ATTACK.AttributionThreshold > 1 {
		return fmt.Errorf("config: [attck] attribution_threshold = %v must be in [0, 1]", cfg.ATTACK.AttributionThreshold)
	}

	// Confidence policy sanity (if enabled): default/floor ∈ (0,1].
	if cfg.Confidence.Enabled {
		if floatInvalid(cfg.Confidence.Default) || cfg.Confidence.Default <= 0 || cfg.Confidence.Default > 1 {
			return fmt.Errorf("config: [confidence] default = %v must be in (0, 1]", cfg.Confidence.Default)
		}
		if floatInvalid(cfg.Confidence.Floor) || cfg.Confidence.Floor <= 0 || cfg.Confidence.Floor >= 1 {
			return fmt.Errorf("config: [confidence] floor = %v must be in (0, 1)", cfg.Confidence.Floor)
		}
	}

	return nil
}
