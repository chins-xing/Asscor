package ssam

import "math"

func SSAMV12Formula(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
	wMap := BuildWeightMap(weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return 0
	}

	baseScore := sum / totalWeight
	baseScore *= threatCoeff
	baseScore *= spcScore

	for _, f := range edgeFactors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			baseScore *= f.Factor
		}
	}

	return math.Round(baseScore*100) / 100
}

func SimpleWeightedFormula(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
	wMap := BuildWeightMap(weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return 0
	}

	return math.Round((sum/totalWeight)*100) / 100
}

func BuildWeightMap(weights []WeightConfig) map[string]float64 {
	wMap := make(map[string]float64)
	for _, w := range weights {
		wMap[w.Domain] = w.Weight
	}
	return wMap
}

func RegisterBuiltinFormulas() map[string]ScoringFormula {
	return map[string]ScoringFormula{
		"ssam_v1.2":       SSAMV12Formula,
		"simple_weighted": SimpleWeightedFormula,
	}
}

func BuildCustomFactorMap(edgeFactors []EdgeFactorConfig) map[string]float64 {
	result := make(map[string]float64)
	for _, f := range edgeFactors {
		result[f.ID] = f.Factor
	}
	return result
}
