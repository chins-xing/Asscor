package ssam

import (
	"encoding/json"
	"time"
)

type SSAMIR struct {
	Meta   IRMeta   `json:"meta"`
	Input  IRInput  `json:"input"`
	Output IROutput `json:"output"`
}

type IRMeta struct {
	Version   string `json:"version"`
	FormulaID string `json:"formula_id"`
	Timestamp string `json:"timestamp"`
}

type IRInput struct {
	HostID      string             `json:"host_id"`
	Hostname    string             `json:"hostname"`
	Threshold   float64            `json:"threshold"`
	Checks      []CheckInput       `json:"checks"`
	RiskContext RiskContext        `json:"risk_context"`
	Weights     []WeightConfig     `json:"weights"`
	EdgeFactors []EdgeFactorConfig `json:"edge_factors"`
}

type IROutput struct {
	FinalScore   float64            `json:"final_score"`
	Acceptable   bool               `json:"acceptable"`
	Threshold    float64            `json:"threshold"`
	DomainScores []DomainScore      `json:"domain_scores"`
	RiskLayers   RiskLayers         `json:"risk_layers"`
	EdgeFactors  []EdgeFactorResult `json:"edge_factors"`
}

func NewIR(input AssessmentInputV2, config ScoringConfig, output AssessmentOutputV2) SSAMIR {
	return SSAMIR{
		Meta: IRMeta{
			Version:   "2.0",
			FormulaID: config.FormulaID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
		Input: IRInput{
			HostID:      input.HostID,
			Hostname:    input.Hostname,
			Threshold:   input.Threshold,
			Checks:      input.Checks,
			RiskContext: input.RiskContext,
			Weights:     config.Weights,
			EdgeFactors: config.EdgeFactors,
		},
		Output: IROutput{
			FinalScore:   output.FinalScore.Total,
			Acceptable:   output.Acceptable,
			Threshold:    output.Threshold,
			DomainScores: output.DomainScores,
			RiskLayers:   output.FinalScore.Layers,
			EdgeFactors:  output.EdgeFactors,
		},
	}
}

func (ir SSAMIR) MarshalJSON() ([]byte, error) {
	type Alias SSAMIR
	return json.MarshalIndent(Alias(ir), "", "  ")
}

func UnmarshalIR(data []byte) (SSAMIR, error) {
	var ir SSAMIR
	if err := json.Unmarshal(data, &ir); err != nil {
		return SSAMIR{}, err
	}
	return ir, nil
}

func (ir SSAMIR) Validate() error {
	if ir.Meta.Version == "" {
		return &SSAMError{Code: "invalid_ir", Message: "meta.version must not be empty"}
	}
	if ir.Meta.FormulaID == "" {
		return &SSAMError{Code: "invalid_ir", Message: "meta.formula_id must not be empty"}
	}
	if ir.Meta.Timestamp == "" {
		return &SSAMError{Code: "invalid_ir", Message: "meta.timestamp must not be empty"}
	}
	if ir.Input.HostID == "" {
		return &SSAMError{Code: "invalid_ir", Message: "input.host_id must not be empty"}
	}
	if ir.Input.Threshold <= 0 || ir.Input.Threshold > 100 {
		return &SSAMError{Code: "invalid_ir", Message: "input.threshold must be in range (0, 100]"}
	}
	if ir.Output.FinalScore < 0 || ir.Output.FinalScore > 100 {
		return &SSAMError{Code: "invalid_ir", Message: "output.final_score must be in range [0, 100]"}
	}
	return nil
}
