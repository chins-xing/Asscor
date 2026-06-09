package prism

import "math"

// ----------------------------------------------------------
// Semantic Layer — Fuzzy State Membership
// ----------------------------------------------------------

// trapezoidUp returns membership for an ascending trapezoid: 0 below lower, 1 above upper.
func trapezoidUp(x, lower, upper float64) float64 {
	if x <= lower {
		return 0.0
	}
	if x >= upper {
		return 1.0
	}
	return (x - lower) / (upper - lower)
}

// trapezoidDown returns membership for a descending trapezoid: 1 below lower, 0 above upper.
func trapezoidDown(x, lower, upper float64) float64 {
	if x <= lower {
		return 1.0
	}
	if x >= upper {
		return 0.0
	}
	return (upper - x) / (upper - lower)
}

// trapezoidTri returns triangular membership peaked at center with zero at both edges.
func trapezoidTri(x, lower, center, upper float64) float64 {
	if x <= lower || x >= upper {
		return 0.0
	}
	if x <= center {
		return (x - lower) / (center - lower)
	}
	return (upper - x) / (upper - center)
}

// computeMemberships applies the four trapezoidal membership functions to a
// normalized Prism score S_norm ∈ [0, 1].
//
// Threshold conventions (from PrismConfig):
//
//	T_stable     = StableThreshold    (default 0.90)
//	T_degraded   = DegradedThreshold  (default 0.70)
//	T_untrusted  = UntrustedThreshold (default 0.50)
//	T_collapse   = 0.0                (implicit)
//
// Membership functions (white paper §14.7):
//
//	μ_stable(S)   = max(0, min(1, (S - T_degraded) / (T_stable - T_degraded)))
//	μ_degraded(S) = max(0, min( (S - T_untrusted)/(T_degraded - T_untrusted),
//	                             (T_stable - S)/(T_stable - T_degraded) ))
//	μ_untrusted(S) = max(0, min( (S - T_collapse)/(T_untrusted - T_collapse),
//	                              (T_degraded - S)/(T_degraded - T_untrusted) ))
//	μ_collapse(S)  = max(0, min(1, (T_untrusted - S)/(T_untrusted - T_collapse)))
func computeMemberships(sNorm float64, cfg PrismConfig) (stable, degraded, untrusted, collapse float64) {
	// sNorm clamped to [0, 1]
	sNorm = math.Max(0.0, math.Min(1.0, sNorm))

	Tstable := cfg.StableThreshold
	Tdegraded := cfg.DegradedThreshold
	Tuntrusted := cfg.UntrustedThreshold
	Tcollapsed := 0.0

	// μ_stable: ascending from T_degraded to T_stable
	stable = trapezoidUp(sNorm, Tdegraded, Tstable)

	// μ_degraded: triangular, peak at center between T_untrusted and T_degraded
	centerDegraded := (Tdegraded + Tuntrusted) / 2.0
	degraded = trapezoidTri(sNorm, Tuntrusted, centerDegraded, Tstable)

	// μ_untrusted: triangular, peak at center between T_collapse and T_untrusted
	centerUntrusted := (Tuntrusted + Tcollapsed) / 2.0
	untrusted = trapezoidTri(sNorm, Tcollapsed, centerUntrusted, Tdegraded)

	// μ_collapse: descending from T_collapse to T_untrusted
	collapse = trapezoidDown(sNorm, Tcollapsed, Tuntrusted)

	return stable, degraded, untrusted, collapse
}

// determineCurrentState returns the dominant state name and normalizes the vector.
func determineCurrentState(memberships [4]float64) (state string, vector [4]float64) {
	names := [4]string{"Stable", "Degraded", "Untrusted", "Collapse"}

	// Normalize to sum = 1
	sum := 0.0
	for _, v := range memberships {
		sum += v
	}

	if sum > 1e-12 {
		for i := range memberships {
			vector[i] = math.Round(memberships[i]/sum*10000) / 10000
		}
	} else {
		// Degenerate case: all scores are 0 — default to Stable
		vector[0] = 1.0
		for i := 1; i < 4; i++ {
			vector[i] = 0.0
		}
	}

	// Pick dominant state
	bestIdx := 0
	bestVal := vector[0]
	for i := 1; i < 4; i++ {
		if vector[i] > bestVal {
			bestVal = vector[i]
			bestIdx = i
		}
	}

	return names[bestIdx], vector
}

// ComputeSemanticState maps a Core Layer raw risk result into a four-state
// fuzzy membership report.
//
// Input: AssetRiskResult from Core Layer (uses PrismScore).
// Output: SemanticRiskReport with membership degrees and dominant state.
func ComputeSemanticState(core *AssetRiskResult, cfg PrismConfig) *SemanticRiskReport {
	if core == nil {
		return nil
	}

	sNorm := core.PrismScore / 100.0

	stable, degraded, untrusted, collapse := computeMemberships(sNorm, cfg)

	memberships := [4]float64{stable, degraded, untrusted, collapse}
	state, vector := determineCurrentState(memberships)

	return &SemanticRiskReport{
		HostID:              core.HostID,
		StableMembership:    stable,
		DegradedMembership:  degraded,
		UntrustedMembership: untrusted,
		CollapseMembership:  collapse,
		CurrentState:        state,
		StateVector:         vector,
	}
}

// ComputeSemanticBatch processes multiple Core Layer results in batch.
func ComputeSemanticBatch(results []*AssetRiskResult, cfg PrismConfig) []*SemanticRiskReport {
	reports := make([]*SemanticRiskReport, 0, len(results))
	for _, r := range results {
		if r == nil {
			continue
		}
		reports = append(reports, ComputeSemanticState(r, cfg))
	}
	return reports
}