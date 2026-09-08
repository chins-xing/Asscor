package ssam

type DomainScore struct {
	Domain string  `json:"domain"`
	Score  float64 `json:"score"`
	// Sigma is the posterior standard deviation of the domain score under the
	// Bayesian confidence model (0 when confidence-aware scoring is disabled).
	// Model-native output (design CONFIDENCE_MODEL_DESIGN_2026-09-08 §2.2).
	Sigma float64 `json:"sigma,omitempty"`
	// Confidence is the domain-level evidence confidence in [0,1] (1 when no
	// failure evidence or when confidence-aware scoring is disabled).
	Confidence float64 `json:"confidence,omitempty"`
}

type EdgeFactorResult struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Factor float64 `json:"factor"`
	Active bool    `json:"active"`
	// TriggerConfidence is the confidence of the triggering failed check
	// (model-native, design §2.4). 1 when confidence-aware scoring is
	// disabled or the factor was not trigger-gated.
	TriggerConfidence float64 `json:"trigger_confidence,omitempty"`
}

type CheckInput struct {
	CheckID string  `json:"check_id"`
	Domain  string  `json:"domain"`
	Name    string  `json:"name"`
	Passed  bool    `json:"passed"`
	Delta   float64 `json:"delta"`
	Detail  string  `json:"detail"`
	// Confidence is the intelligence confidence of THIS observation in
	// [0,1]. 0 means "unspecified" and is normalized by the active
	// ConfidencePolicy to its Default. Model-native input (design §2).
	Confidence float64 `json:"confidence,omitempty"`
}

type AssessmentInput struct {
	HostID       string             `json:"host_id"`
	Hostname     string             `json:"hostname"`
	Threshold    float64            `json:"threshold"`
	Checks       []CheckInput       `json:"checks"`
	ThreatCoeff  float64            `json:"threat_coefficient"`
	SPCScore     float64            `json:"spc_score"`
	WeightShifts map[string]float64 `json:"weight_shifts,omitempty"`
}

type AssessmentOutput struct {
	HostID       string             `json:"host_id"`
	FinalScore   float64            `json:"final_score"`
	Acceptable   bool               `json:"acceptable"`
	Threshold    float64            `json:"threshold"`
	DomainScores []DomainScore      `json:"domain_scores"`
	EdgeFactors  []EdgeFactorResult `json:"edge_factors"`
	ThreatCoeff  float64            `json:"threat_coefficient"`
	SPCScore     float64            `json:"spc_score"`
	FormulaID    string             `json:"formula_id"`
	Metadata     map[string]string  `json:"metadata,omitempty"`
	// Confidence-aware posterior statistics (model-native, design §2.3).
	FinalSigma  float64 `json:"final_sigma,omitempty"`
	Lower95     float64 `json:"score_lower95,omitempty"`
	Upper95     float64 `json:"score_upper95,omitempty"`
	// EvidenceConfidence is the aggregate domain-level confidence of the
	// scoring evidence in [0,1].
	EvidenceConfidence float64 `json:"evidence_confidence,omitempty"`
}

type WeightConfig struct {
	Domain string  `json:"domain"`
	Weight float64 `json:"weight"`
}

type EdgeFactorConfig struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Factor       float64 `json:"factor"`
	TriggerCheck string  `json:"trigger_check,omitempty"`
	CascadeTo    string  `json:"cascade_to,omitempty"`
	CascadeValue float64 `json:"cascade_value,omitempty"`
	CascadeOnly  bool    `json:"cascade_only,omitempty"`
}

type ScoringConfig struct {
	Weights     []WeightConfig     `json:"weights"`
	EdgeFactors []EdgeFactorConfig `json:"edge_factors"`
	FormulaID   string             `json:"formula_id"`
	// ConfidencePolicy carries the kernel's confidence configuration. When
	// zero-valued (the default), confidence-aware scoring is DISABLED and all
	// formulas behave exactly as before (backward compatibility).
	ConfidencePolicy ConfidencePolicy `json:"confidence_policy,omitempty"`
}

type ScoringFormula func(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64
