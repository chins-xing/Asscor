package prism

import "math"

const secondsPerDay = 86400.0

// ----------------------------------------------------------
// Core Layer — Deterministic Evaluation
// ----------------------------------------------------------

func externalRisk(ssamScore float64) float64 {
	return (100.0 - ssamScore) / 100.0
}

func computeSpillover(upstreamERisk float64, transmission float64) float64 {
	return upstreamERisk * transmission
}

// computePropagatedRisk calculates aggregated upstream propagation risk using
// root-sum-square (RSS) to penalize concentration.
func computePropagatedRisk(incomingEdges []EdgeState, allNodes map[string]*NodeState) float64 {
	sumSquares := 0.0
	for _, e := range incomingEdges {
		upstream, ok := allNodes[e.Source]
		if !ok {
			continue
		}
		erisk := externalRisk(upstream.SSAMScore)
		spill := computeSpillover(erisk, e.RiskTransmission)
		sumSquares += spill * spill
	}
	return math.Min(1.0, math.Sqrt(sumSquares))
}

// computeDebtRaw returns the un-normalized total security debt across all failures.
func computeDebtRaw(failures []CheckFailure, alpha float64, nowUnix int64) float64 {
	if len(failures) == 0 {
		return 0.0
	}
	total := 0.0
	for _, f := range failures {
		elapsedDays := float64(nowUnix-f.FailUnix) / secondsPerDay
		if elapsedDays < 0 {
			elapsedDays = 0
		}
		delta := math.Abs(f.Delta)
		total += delta * math.Pow(elapsedDays, alpha)
	}
	return total
}

// computeCollapseModifier captures multi-debt collapse: when several key checks
// fail concurrently, the trust collapse is super-linear.
// Single-failure debt is already handled by the debt penalty; collapse only
// activates when 2+ failures exist concurrently.
// Formula: min(1, (sum_debt / (norm * cap * sqrt(n)))^beta) where beta > 1, n >= 2.
func computeCollapseModifier(debtRaw float64, nFailures int, cfg PrismConfig) float64 {
	if nFailures < 2 || debtRaw <= 0 {
		return 0.0
	}
	// Scale denominator by sqrt(n) so multi-failure collapse effect grows
	// naturally: the same total debt from 4 concurrent failures is more
	// dangerous than from 1 failure.
	nFactor := math.Sqrt(float64(nFailures))
	denom := cfg.DebtNormDays * cfg.DebtCap * nFactor
	if denom <= 0 {
		return 0.0
	}
	ratio := debtRaw / denom
	mod := math.Pow(ratio, cfg.CollapseBeta)
	return math.Min(1.0, mod)
}

// ComputeRiskVelocity calculates the daily score delta between two snapshots.
// Negative return means the score is degrading.
// Returns 0 if prior snapshot is absent or invalid.
func ComputeRiskVelocity(currentScore float64, prior *RiskSnapshot, nowUnix int64) float64 {
	if prior == nil {
		return 0.0
	}
	deltaDays := float64(nowUnix-prior.Timestamp) / secondsPerDay
	if deltaDays <= 0 {
		return 0.0
	}
	return (currentScore - prior.PrismScore) / deltaDays
}

// ComputeDynamicScore is the Core Layer entry point.
// It takes a node's SSAM score, its failed-check timeline, and incoming edges,
// then returns an orthogonally-decomposed raw risk report.
func ComputeDynamicScore(
	node *NodeState,
	incomingEdges []EdgeState,
	allNodes map[string]*NodeState,
	cfg PrismConfig,
	nowUnix int64,
) AssetRiskResult {
	// Propagation (orthogonal — depends only on upstream nodes)
	propRiskRaw := computePropagatedRisk(incomingEdges, allNodes)
	propPenalty := math.Min(cfg.PropCap, propRiskRaw)

	// Debt (orthogonal — depends only on time × delta)
	debtRaw := computeDebtRaw(node.FailedChecks, cfg.DebtAlpha, nowUnix)
	debtPenalty := math.Min(cfg.DebtCap, debtRaw/cfg.DebtNormDays)

	// Collapse modifier (orthogonal — depends only on multi-debt concurrency)
	collapseMod := computeCollapseModifier(debtRaw, len(node.FailedChecks), cfg)

	// Orthogonal dynamic score with collapse correction
	prismScore := node.SSAMScore * (1.0 - propPenalty) * (1.0 - debtPenalty) * (1.0 - collapseMod)

	// Floor protection
	floor := node.SSAMScore * cfg.ScoreFloor
	prismScore = math.Max(floor, prismScore)
	prismScore = math.Min(100.0, prismScore)

	return AssetRiskResult{
		HostID:           node.HostID,
		SsamScore:        node.SSAMScore,
		PrismScore:       math.Round(prismScore*100) / 100,
		ExternalRisk:     math.Round(externalRisk(node.SSAMScore)*10000) / 10000,
		PropagatedRisk:   math.Round(propRiskRaw*10000) / 10000,
		PropPenalty:      math.Round(propPenalty*10000) / 10000,
		DebtRaw:          math.Round(debtRaw*100) / 100,
		DebtPenalty:      math.Round(debtPenalty*10000) / 10000,
		CollapseModifier: math.Round(collapseMod*10000) / 10000,
		RiskVelocity:     0.0, // caller fills via ComputeRiskVelocity
	}
}
