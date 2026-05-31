package prism

import "math"

const secondsPerDay = 86400.0

func externalRisk(ssamScore float64) float64 {
	return (100.0 - ssamScore) / 100.0
}

func computeSpillover(upstreamERisk float64, transmission float64) float64 {
	return upstreamERisk * transmission
}

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

func computeDebtPenalty(failures []CheckFailure, alpha float64, nowUnix int64) float64 {
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

func ComputeDynamicScore(
	node *NodeState,
	incomingEdges []EdgeState,
	allNodes map[string]*NodeState,
	cfg PrismConfig,
	nowUnix int64,
) AssetRiskResult {
	propRiskRaw := computePropagatedRisk(incomingEdges, allNodes)
	propPenalty := math.Min(cfg.PropCap, propRiskRaw)

	debtRaw := computeDebtPenalty(node.FailedChecks, cfg.DebtAlpha, nowUnix)
	debtPenalty := math.Min(cfg.DebtCap, debtRaw/cfg.DebtNormDays)

	prismScore := node.SSAMScore * (1.0 - propPenalty) * (1.0 - debtPenalty)

	floor := node.SSAMScore * cfg.ScoreFloor
	prismScore = math.Max(floor, prismScore)
	prismScore = math.Min(100.0, prismScore)

	return AssetRiskResult{
		HostID:         node.HostID,
		SsamScore:      node.SSAMScore,
		PrismScore:     math.Round(prismScore*100) / 100,
		ExternalRisk:   math.Round(externalRisk(node.SSAMScore)*10000) / 10000,
		PropagatedRisk: math.Round(propRiskRaw*10000) / 10000,
		PropPenalty:    math.Round(propPenalty*10000) / 10000,
		DebtRaw:        math.Round(debtRaw*100) / 100,
		DebtPenalty:    math.Round(debtPenalty*10000) / 10000,
	}
}
