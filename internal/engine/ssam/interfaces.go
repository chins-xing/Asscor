package ssam

import (
	"context"

	ssam "github.com/chins-xing/ssam"
)

type HookPhase string

const (
	HookPreScore  HookPhase = "pre_score"
	HookPostScore HookPhase = "post_score"
	HookPreEdge   HookPhase = "pre_edge"
	HookPostEdge  HookPhase = "post_edge"
)

type AssessmentHook func(ctx context.Context, input *AssessmentInput, output *AssessmentOutput) error

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
	ComputeScore(ctx context.Context, input *ssam.AssessmentInput) (*ssam.AssessmentOutput, error)
	ComputeDomainScores(checks []ssam.CheckInput) []ssam.DomainScore
	ComputeWeightedSum(domainScores []ssam.DomainScore) float64
	ApplyEdgeFactors(baseScore float64, factors []ssam.EdgeFactorResult) float64
	SetWeights(weights []WeightConfig)
	GetWeights() []WeightConfig
	SetEdgeFactors(factors []EdgeFactorConfig)
	InitializeDefaults(defaultWeights map[string]float64, defaultFactors []EdgeFactorConfig)
	SetFormula(formulaID string)
	GetFormula() string
}

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
