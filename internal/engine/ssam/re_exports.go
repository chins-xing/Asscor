//go:build engine

package ssam

import (
	ssam "github.com/chins-xing/ssam"
)

type (
	DomainScore      = ssam.DomainScore
	EdgeFactorResult = ssam.EdgeFactorResult
	CheckInput       = ssam.CheckInput
	AssessmentInput  = ssam.AssessmentInput
	AssessmentOutput = ssam.AssessmentOutput
	WeightConfig     = ssam.WeightConfig
	EdgeFactorConfig = ssam.EdgeFactorConfig
	ScoringConfig    = ssam.ScoringConfig
	ScoringFormula   = ssam.ScoringFormula

	RiskContext        = ssam.RiskContext
	RiskLayerDetail    = ssam.RiskLayerDetail
	RiskLayers         = ssam.RiskLayers
	FinalScore         = ssam.FinalScore
	AssessmentInputV2  = ssam.AssessmentInputV2
	AssessmentOutputV2 = ssam.AssessmentOutputV2
	ScoringFormulaV2   = ssam.ScoringFormulaV2
	SSAMIR             = ssam.SSAMIR
	IRMeta             = ssam.IRMeta
	IRInput            = ssam.IRInput
	IROutput           = ssam.IROutput
)

type SSAMError = ssam.SSAMError

var (
	ErrNilInput       = ssam.ErrNilInput
	ErrUnknownFormula = ssam.ErrUnknownFormula
	ErrEmptyWeights   = ssam.ErrEmptyWeights
	ErrInvalidScore   = ssam.ErrInvalidScore
)

var (
	DefaultWeights       = ssam.DefaultWeights
	DefaultEdgeFactors   = ssam.DefaultEdgeFactors
	DefaultScoringConfig = ssam.DefaultScoringConfig
)

var (
	ValidateInput  = ssam.ValidateInput
	ValidateOutput = ssam.ValidateOutput
	NewIR          = ssam.NewIR
	UnmarshalIR    = ssam.UnmarshalIR
	EvalAST        = ssam.EvalAST
	ASTToFormula   = ssam.ASTToFormula
	SSAMV12AST     = ssam.SSAMV12AST
	SSAMV20AST     = ssam.SSAMV20AST
)
