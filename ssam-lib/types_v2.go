package ssam

type RiskContext struct {
	Intrinsic float64 `json:"intrinsic"`
	Exposure  float64 `json:"exposure"`
	Threat    float64 `json:"threat"`
}

type RiskLayerDetail struct {
	Coeff        float64            `json:"coeff"`
	Weight       float64            `json:"weight"`
	Contributors []string           `json:"contributors"`
	Details      map[string]float64 `json:"details,omitempty"`
}

type RiskLayers struct {
	Intrinsic RiskLayerDetail `json:"intrinsic"`
	Exposure  RiskLayerDetail `json:"exposure"`
	Threat    RiskLayerDetail `json:"threat"`
}

type FinalScore struct {
	Total  float64    `json:"total"`
	Layers RiskLayers `json:"layers"`
}

type AssessmentInputV2 struct {
	HostID       string             `json:"host_id"`
	Hostname     string             `json:"hostname"`
	Threshold    float64            `json:"threshold"`
	Checks       []CheckInput       `json:"checks"`
	RiskContext  RiskContext        `json:"risk_context"`
	WeightShifts map[string]float64 `json:"weight_shifts,omitempty"`
}

type AssessmentOutputV2 struct {
	HostID       string             `json:"host_id"`
	FinalScore   FinalScore         `json:"final_score"`
	Acceptable   bool               `json:"acceptable"`
	Threshold    float64            `json:"threshold"`
	DomainScores []DomainScore      `json:"domain_scores"`
	EdgeFactors  []EdgeFactorResult `json:"edge_factors"`
	FormulaID    string             `json:"formula_id"`
	Metadata     map[string]string  `json:"metadata,omitempty"`
}

type ScoringFormulaV2 func(domainScores []DomainScore, weights []WeightConfig, riskCtx RiskContext, edgeFactors []EdgeFactorResult) FinalScore
