package ssam

import (
	"math"
	"sort"
)

func ComputeScore(config ScoringConfig, input AssessmentInput) (AssessmentOutput, error) {
	if err := ValidateInput(input); err != nil {
		return AssessmentOutput{}, err
	}

	threatCoeff := input.ThreatCoeff
	if threatCoeff == 0 {
		threatCoeff = 1.0
	}
	spcScore := input.SPCScore
	if spcScore == 0 {
		spcScore = 1.0
	}
	if spcScore < 0.60 {
		spcScore = 0.60
	}

	domainScores := ComputeDomainScores(config.Weights, input.Checks)

	customFactors := BuildCustomFactorMap(config.EdgeFactors)
	edgeFactors := ApplyEdgeFactorsToChecks(config.EdgeFactors, input.Checks, customFactors)

	formulas := RegisterBuiltinFormulas()
	formula, ok := formulas[config.FormulaID]
	if ok && formula != nil {
		finalScore := formula(domainScores, config.Weights, threatCoeff, spcScore, edgeFactors)
		finalScore = math.Round(finalScore*100) / 100

		output := AssessmentOutput{
			HostID:       input.HostID,
			FinalScore:   finalScore,
			Acceptable:   finalScore >= input.Threshold,
			Threshold:    input.Threshold,
			DomainScores: domainScores,
			EdgeFactors:  edgeFactors,
			ThreatCoeff:  threatCoeff,
			SPCScore:     spcScore,
			FormulaID:    config.FormulaID,
			Metadata:     make(map[string]string),
		}

		if err := ValidateOutput(output); err != nil {
			return AssessmentOutput{}, err
		}

		return output, nil
	}

	v2Formulas := RegisterBuiltinFormulasV2()
	v2Formula, v2Ok := v2Formulas[config.FormulaID]
	if v2Ok && v2Formula != nil {
		riskCtx := RiskContext{
			Intrinsic: 1.0,
			Exposure:  spcScore,
			Threat:    threatCoeff,
		}
		if riskCtx.Exposure <= 0 {
			riskCtx.Exposure = 1.0
		}
		if riskCtx.Threat <= 0 {
			riskCtx.Threat = 1.0
		}

		v2FinalScore := v2Formula(domainScores, config.Weights, riskCtx, edgeFactors)

		output := AssessmentOutput{
			HostID:       input.HostID,
			FinalScore:   v2FinalScore.Total,
			Acceptable:   v2FinalScore.Total >= input.Threshold,
			Threshold:    input.Threshold,
			DomainScores: domainScores,
			EdgeFactors:  edgeFactors,
			ThreatCoeff:  threatCoeff,
			SPCScore:     spcScore,
			FormulaID:    config.FormulaID,
			Metadata:     make(map[string]string),
		}

		if err := ValidateOutput(output); err != nil {
			return AssessmentOutput{}, err
		}

		return output, nil
	}

	formula = SSAMV12Formula

	finalScore := formula(domainScores, config.Weights, threatCoeff, spcScore, edgeFactors)
	finalScore = math.Round(finalScore*100) / 100

	output := AssessmentOutput{
		HostID:       input.HostID,
		FinalScore:   finalScore,
		Acceptable:   finalScore >= input.Threshold,
		Threshold:    input.Threshold,
		DomainScores: domainScores,
		EdgeFactors:  edgeFactors,
		ThreatCoeff:  threatCoeff,
		SPCScore:     spcScore,
		FormulaID:    config.FormulaID,
		Metadata:     make(map[string]string),
	}

	if err := ValidateOutput(output); err != nil {
		return AssessmentOutput{}, err
	}

	return output, nil
}

func ComputeDomainScores(weights []WeightConfig, checks []CheckInput) []DomainScore {
	wMap := BuildWeightMap(weights)

	activeDomains := make(map[string]bool)
	for _, c := range checks {
		activeDomains[c.Domain] = true
	}
	if len(activeDomains) == 0 {
		for domain := range wMap {
			activeDomains[domain] = true
		}
	}

	scores := make(map[string]float64)
	for domain := range activeDomains {
		scores[domain] = 100
	}

	for _, check := range checks {
		if check.Passed {
			continue
		}
		current := scores[check.Domain]
		scores[check.Domain] = math.Max(0, current+check.Delta)
	}

	result := make([]DomainScore, 0, len(scores))
	for domain, score := range scores {
		result = append(result, DomainScore{Domain: domain, Score: score})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

func ComputeWeightedSum(weights []WeightConfig, domainScores []DomainScore) float64 {
	wMap := BuildWeightMap(weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		w, ok := wMap[ds.Domain]
		if !ok {
			w = 0
		}
		if w == 0 {
			continue
		}
		sum += ds.Score * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0
	}
	return sum / totalWeight
}

func ApplyEdgeFactors(baseScore float64, factors []EdgeFactorResult) float64 {
	result := baseScore
	for _, f := range factors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			result *= f.Factor
		}
	}
	return math.Round(result*100) / 100
}

func ApplyEdgeFactorsToChecks(edgeFactors []EdgeFactorConfig, checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult {
	efMap := make(map[string]EdgeFactorConfig)
	for _, f := range edgeFactors {
		efMap[f.ID] = f
	}

	triggered := make(map[string]bool)

	for _, check := range checks {
		if check.Passed {
			continue
		}
		for id, cfg := range efMap {
			if cfg.TriggerCheck == check.CheckID {
				triggered[id] = true
			}
		}
	}

	cascadeOverrides := make(map[string]float64)
	for id, cfg := range efMap {
		if triggered[id] && cfg.CascadeTo != "" && cfg.CascadeValue > 0 {
			cascadeOverrides[cfg.CascadeTo] = cfg.CascadeValue
		}
	}

	results := make([]EdgeFactorResult, 0)
	for id, cfg := range efMap {
		factor := cfg.Factor
		active := false

		if triggered[id] {
			active = true
			if custom, ok := customFactors[id]; ok && custom > 0 && custom < 1.0 {
				factor = custom
			}
		}

		if overrideVal, ok := cascadeOverrides[id]; ok {
			if !triggered[id] {
				active = true
			}
			if overrideVal < factor {
				factor = overrideVal
			}
		}

		activeInResult := active
		if cfg.CascadeOnly && active {
			activeInResult = false
		}

		results = append(results, EdgeFactorResult{
			ID:     id,
			Name:   cfg.Name,
			Factor: factor,
			Active: activeInResult,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}
