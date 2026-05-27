package ssam

import (
	"math"
	"strconv"
)

func SSAMV20Formula(domainScores []DomainScore, weights []WeightConfig, riskCtx RiskContext, edgeFactors []EdgeFactorResult) FinalScore {
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
		return FinalScore{
			Total: 0,
			Layers: RiskLayers{
				Intrinsic: RiskLayerDetail{Coeff: 0, Contributors: []string{"domain_scores"}},
				Exposure:  RiskLayerDetail{Coeff: riskCtx.Exposure, Contributors: []string{"exposure_coefficient"}},
				Threat:    RiskLayerDetail{Coeff: riskCtx.Threat, Contributors: []string{"threat_coefficient"}},
			},
		}
	}

	baseScore := sum / totalWeight

	intrinsicContributors := []string{"domain_scores"}
	for _, f := range edgeFactors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			intrinsicContributors = append(intrinsicContributors, "edge_factor:"+f.ID)
			baseScore *= f.Factor
		}
	}

	baseScore = math.Round(baseScore*100) / 100

	intrinsicCoeff := baseScore / 100.0

	exposureCoeff := riskCtx.Exposure
	if exposureCoeff <= 0 {
		exposureCoeff = 1.0
	}
	if exposureCoeff < 0.60 {
		exposureCoeff = 0.60
	}

	threatCoeff := riskCtx.Threat
	if threatCoeff <= 0 {
		threatCoeff = 1.0
	}
	if threatCoeff < 0.60 {
		threatCoeff = 0.60
	}

	finalScore := intrinsicCoeff * exposureCoeff * threatCoeff * 100
	finalScore = math.Round(finalScore*100) / 100

	return FinalScore{
		Total: finalScore,
		Layers: RiskLayers{
			Intrinsic: RiskLayerDetail{
				Coeff:        math.Round(intrinsicCoeff*100) / 100,
				Contributors: intrinsicContributors,
			},
			Exposure: RiskLayerDetail{
				Coeff:        exposureCoeff,
				Contributors: []string{"exposure_coefficient"},
			},
			Threat: RiskLayerDetail{
				Coeff:        threatCoeff,
				Contributors: []string{"threat_coefficient"},
			},
		},
	}
}

func normalizeRiskContext(rc *RiskContext) {
	if rc.Intrinsic <= 0 {
		rc.Intrinsic = 1.0
	}
	if rc.Exposure <= 0 {
		rc.Exposure = 1.0
	}
	if rc.Threat <= 0 {
		rc.Threat = 1.0
	}
}

func ComputeScoreV2(config ScoringConfig, input AssessmentInputV2) (AssessmentOutputV2, error) {
	if err := ValidateInputV2(input); err != nil {
		return AssessmentOutputV2{}, err
	}

	normalizeRiskContext(&input.RiskContext)

	domainScores := ComputeDomainScores(config.Weights, input.Checks)

	customFactors := BuildCustomFactorMap(config.EdgeFactors)
	edgeFactors := ApplyEdgeFactorsToChecks(config.EdgeFactors, input.Checks, customFactors)

	formulas := RegisterBuiltinFormulasV2()
	formula, ok := formulas[config.FormulaID]
	if !ok || formula == nil {
		formula = SSAMV20Formula
	}

	finalScore := formula(domainScores, config.Weights, input.RiskContext, edgeFactors)

	output := AssessmentOutputV2{
		HostID:       input.HostID,
		FinalScore:   finalScore,
		Acceptable:   finalScore.Total >= input.Threshold,
		Threshold:    input.Threshold,
		DomainScores: domainScores,
		EdgeFactors:  edgeFactors,
		FormulaID:    config.FormulaID,
		Metadata:     make(map[string]string),
	}

	return output, nil
}

func ValidateInputV2(input AssessmentInputV2) error {
	if input.HostID == "" {
		return &SSAMError{Code: "empty_host_id", Message: "host_id must not be empty"}
	}
	if input.Threshold <= 0 || input.Threshold > 100 {
		return &SSAMError{Code: "invalid_threshold", Message: "threshold must be in range (0, 100]"}
	}
	for i, c := range input.Checks {
		if c.Domain == "" {
			return &SSAMError{Code: "empty_domain", Message: "checks[" + strconv.Itoa(i) + "].domain must not be empty"}
		}
	}
	return nil
}

func RegisterBuiltinFormulasV2() map[string]ScoringFormulaV2 {
	return map[string]ScoringFormulaV2{
		"ssam_v2.0": SSAMV20Formula,
	}
}
