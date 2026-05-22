package ssam

import (
	"context"
	"time"
)

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
	HostID       string        `json:"host_id"`
	Hostname     string        `json:"hostname"`
	Timestamp    time.Time     `json:"timestamp"`
	Threshold    float64       `json:"threshold"`
	Checks       []CheckInput  `json:"checks"`
	ThreatCoeff  float64       `json:"threat_coefficient"`
	SPCScore     float64       `json:"spc_score"`
	WeightShifts map[string]float64 `json:"weight_shifts,omitempty"`
}

type AssessmentOutput struct {
	HostID        string            `json:"host_id"`
	FinalScore    float64           `json:"final_score"`
	Acceptable    bool              `json:"acceptable"`
	Threshold     float64           `json:"threshold"`
	DomainScores  []DomainScore     `json:"domain_scores"`
	EdgeFactors   []EdgeFactorResult `json:"edge_factors"`
	ThreatCoeff   float64           `json:"threat_coefficient"`
	SPCScore      float64           `json:"spc_score"`
	FormulaID     string            `json:"formula_id"`
	CalculatedAt  time.Time         `json:"calculated_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
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
	Weights      []WeightConfig      `json:"weights"`
	EdgeFactors  []EdgeFactorConfig  `json:"edge_factors"`
	FormulaID    string              `json:"formula_id"`
	Threshold    float64             `json:"threshold"`
	ThreatCoeff  float64             `json:"threat_coefficient"`
	SPCScore     float64             `json:"spc_score"`
}

type DomainProvider interface {
	ListDomains() []string
	GetDomainLabel(id string) string
	GetDefaultWeight(id string) float64
}

type EdgeFactorProvider interface {
	ListEdgeFactors() []EdgeFactorResult
	EvaluateEdgeFactors(checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult
}

type ScoringProvider interface {
	ComputeScore(ctx context.Context, input *AssessmentInput) (*AssessmentOutput, error)
	ComputeDomainScores(checks []CheckInput) []DomainScore
	ComputeWeightedSum(domainScores []DomainScore) float64
	ApplyEdgeFactors(baseScore float64, factors []EdgeFactorResult) float64
	SetWeights(weights []WeightConfig)
	GetWeights() []WeightConfig
	SetFormula(formulaID string)
	GetFormula() string
}

type ScoringFormula func(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64

type HookPhase string

const (
	HookPreScore  HookPhase = "pre_score"
	HookPostScore HookPhase = "post_score"
	HookPreEdge   HookPhase = "pre_edge"
	HookPostEdge  HookPhase = "post_edge"
)

type AssessmentHook func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error

type HookProvider interface {
	RegisterHook(phase HookPhase, id string, hook AssessmentHook, priority int)
	UnregisterHook(id string)
	ExecuteHooks(ctx context.Context, phase HookPhase, input *AssessmentInput, output *AssessmentOutput) []error
}

type Provider interface {
	ScoringProvider
	DomainProvider
	EdgeFactorProvider
	HookProvider
}
