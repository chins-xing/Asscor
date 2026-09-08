package ssam

import (
	"math"
	"sort"
)

func ComputeScore(config ScoringConfig, input AssessmentInput) (AssessmentOutput, error) {
	// Legacy entry point: no confidence policy → identical historical output.
	return computeScoreInternal(config, input, DefaultConfidencePolicy())
}

// ComputeScoreWithConfidence is the confidence-native scoring entry (v1
// formulas). It produces the same point estimate as ComputeScore when the
// policy is disabled, and additionally fills the posterior statistics
// (FinalSigma / Lower95 / Upper95 / EvidenceConfidence) and the per-domain
// sigma/confidence when confidence-aware scoring is enabled.
func ComputeScoreWithConfidence(config ScoringConfig, input AssessmentInput, policy ConfidencePolicy) (AssessmentOutput, error) {
	return computeScoreInternal(config, input, policy)
}

func computeScoreInternal(config ScoringConfig, input AssessmentInput, policy ConfidencePolicy) (AssessmentOutput, error) {
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

	domainScores := ComputeDomainScoresBayes(config.Weights, input.Checks, policy)

	customFactors := BuildCustomFactorMap(config.EdgeFactors)
	edgeFactors := ApplyEdgeFactorsToChecksPolicy(config.EdgeFactors, input.Checks, customFactors, policy)

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
		fillPosterior(&output, config, domainScores, policy)

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
		fillPosterior(&output, config, domainScores, policy)

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
	fillPosterior(&output, config, domainScores, policy)

	if err := ValidateOutput(output); err != nil {
		return AssessmentOutput{}, err
	}

	return output, nil
}

// fillPosterior attaches the confidence-aware posterior statistics to an
// output. sigma comes from the RSS propagation over domain sigmas; the 95%
// interval is centered on the ACTUAL final score (which may include
// risk-layer coefficients), i.e. [score − 1.96σ, score + 1.96σ] ∩ [0,100].
// With a disabled policy sigma collapses to 0 and the interval degrades to
// the degenerate [score, score]; evidence confidence is 1 — exactly the
// legacy semantics. Acceptability is NOT changed here (point-estimate
// comparison); the conservative lower-bound mode is a kernel-side option.
func fillPosterior(output *AssessmentOutput, config ScoringConfig, domainScores []DomainScore, policy ConfidencePolicy) {
	sigma, _, _ := FinalBayesStats(config.Weights, domainScores)
	output.FinalSigma = sigma
	output.Lower95 = clamp95(output.FinalScore - 1.96*sigma)
	output.Upper95 = clamp95(output.FinalScore + 1.96*sigma)
	output.EvidenceConfidence = AggregateNodeConfidence(config.Weights, domainScores)
}

func clamp95(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func ComputeDomainScores(weights []WeightConfig, checks []CheckInput) []DomainScore {
	// Legacy entry point: no confidence policy → confidence-aware scoring is
	// disabled → every check counts fully. ComputeDomainScoresBayes with the
	// default (disabled) policy is numerically identical to the historical
	// accumulation (sigma 0, confidence 1), so route through it to keep a
	// single source of truth.
	return ComputeDomainScoresBayes(weights, checks, DefaultConfidencePolicy())
}

// ComputeDomainScoresWithConfidence is the confidence-native scoring entry.
// It is what the engine calls when the kernel enables [confidence].
func ComputeDomainScoresWithConfidence(weights []WeightConfig, checks []CheckInput, policy ConfidencePolicy) []DomainScore {
	return ComputeDomainScoresBayes(weights, checks, policy)
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

// ApplyEdgeFactorsToChecks evaluates edge factors against the (failed) check
// set using the default (disabled) confidence policy — the legacy entry point,
// numerically identical to the historical behavior.
func ApplyEdgeFactorsToChecks(edgeFactors []EdgeFactorConfig, checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult {
	return ApplyEdgeFactorsToChecksPolicy(edgeFactors, checks, customFactors, DefaultConfidencePolicy())
}

// ApplyEdgeFactorsToChecksPolicy evaluates edge factors against the (failed)
// check set with confidence-aware triggering (design §2.4). When a factor is
// trigger-gated and the triggering check's confidence is < 1, the applied
// penalty is attenuated:
//
//	effective_factor = 1 − (1 − factor) · c_trigger
//
// which equals `factor` when c_trigger=1 (legacy) and approaches 1 (no
// penalty) as c_trigger → 0. Cascade values are NOT confidence-attenuated
// (they are secondary, config-declared penalties whose provenance is the
// config, not the trigger observation). EdgeFactorResult.TriggerConfidence
// records the normalized triggering confidence (model-native traceability).
func ApplyEdgeFactorsToChecksPolicy(edgeFactors []EdgeFactorConfig, checks []CheckInput, customFactors map[string]float64, policy ConfidencePolicy) []EdgeFactorResult {
	efMap := make(map[string]EdgeFactorConfig)
	for _, f := range edgeFactors {
		efMap[f.ID] = f
	}

	// For each factor id: was its trigger check failed, and with what
	// (normalized) confidence?
	triggerConf := make(map[string]float64)
	for _, check := range checks {
		if check.Passed {
			continue
		}
		c := NormalizeConfidence(check.Confidence, policy)
		for id, cfg := range efMap {
			if cfg.TriggerCheck == check.CheckID {
				// Multiple failed checks may reference the same trigger
				// check id; keep the most confident trigger (best evidence).
				if prev, ok := triggerConf[id]; !ok || c > prev {
					triggerConf[id] = c
				}
			}
		}
	}

	cascadeOverrides := make(map[string]float64)
	for id, cfg := range efMap {
		if _, triggered := triggerConf[id]; triggered && cfg.CascadeTo != "" && cfg.CascadeValue > 0 {
			cascadeOverrides[cfg.CascadeTo] = cfg.CascadeValue
		}
	}

	results := make([]EdgeFactorResult, 0)
	for id, cfg := range efMap {
		factor := cfg.Factor
		active := false
		tc := 0.0 // trigger confidence; 0 = not trigger-gated/not triggered

		if c, triggered := triggerConf[id]; triggered {
			active = true
			tc = c
			if custom, ok := customFactors[id]; ok && custom > 0 && custom < 1.0 {
				factor = custom
			}
			// Confidence attenuation: milder penalty for low-confidence
			// triggers (design §2.4). With policy disabled c=1 → factor
			// unchanged.
			if factor > 0 && factor < 1.0 {
				factor = 1.0 - (1.0-factor)*c
			}
		}

		if overrideVal, ok := cascadeOverrides[id]; ok {
			if !active {
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
			ID:                id,
			Name:              cfg.Name,
			Factor:            factor,
			Active:            activeInResult,
			TriggerConfidence: tc,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}
