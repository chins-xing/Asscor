package ssam

type DomainScore struct {
	Domain string  `json:"domain"`
	Score  float64 `json:"score"`
}

type EdgeFactorResult struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Factor float64 `json:"factor"`
	Active bool    `json:"active"`
}

type CheckInput struct {
	CheckID string  `json:"check_id"`
	Domain  string  `json:"domain"`
	Name    string  `json:"name"`
	Passed  bool    `json:"passed"`
	Delta   float64 `json:"delta"`
	Detail  string  `json:"detail"`
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
}

type ScoringFormula func(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64
