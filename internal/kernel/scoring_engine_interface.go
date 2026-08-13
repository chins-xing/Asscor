package kernel

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
	prismlib "github.com/chins-xing/prism"
)

// ScoringEngineProvider is the contract between the assessor module and the
// SSAM scoring engine. Implementations live in optional build-tag modules.
type ScoringEngineProvider interface {
	Assess(hostID string, hostname string) *model.AssessmentResult
	AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
	PluginEngine() AssessorEngine
	SetPluginEngine(e AssessorEngine)
	RecomputeFinalScore(result *model.AssessmentResult) float64
	ReloadWeights(cfg *config.Config)
	ValidateEdgeFactors(registeredChecks []model.CheckItem) []string
	PrintReport(result *model.AssessmentResult) string
}

// PrismEngineProvider is the contract for the Prism/SRD risk dynamics engine.
type PrismEngineProvider interface {
	ComputeDynamicScore(node *prismlib.NodeState, incomingEdges []prismlib.EdgeState, allNodes map[string]*prismlib.NodeState, nowUnix int64) prismlib.AssetRiskResult
	ComputeSemanticState(core *prismlib.AssetRiskResult) *prismlib.SemanticRiskReport
	PredictFuture(semantic *prismlib.SemanticRiskReport, model prismlib.InferenceModel) *prismlib.FutureRiskReport
	Config() prismlib.PrismConfig
	UpdateConfig(cfg prismlib.PrismConfig)
}

// ATTACKInjectionTarget accepts an optional ATT&CK analysis provider. The
// assessor module implements it so the attck_ext extension can inject itself.
type ATTACKInjectionTarget interface {
	SetATTACKProvider(provider ATTACKProvider)
}
