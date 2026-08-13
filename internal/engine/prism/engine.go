//go:build engine

package prism

import (
	"sync"

	prismlib "github.com/chins-xing/prism"
)

// Engine wraps prism-lib with concurrency-safe configuration.
type Engine struct {
	mu  sync.RWMutex
	cfg prismlib.PrismConfig
}

func NewEngine() *Engine {
	return &Engine{
		cfg: prismlib.DefaultConfig(),
	}
}

func NewEngineWithConfig(cfg prismlib.PrismConfig) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Config() prismlib.PrismConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

func (e *Engine) UpdateConfig(cfg prismlib.PrismConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

// ----------------------------------------------------------
// Core Layer
// ----------------------------------------------------------

func (e *Engine) ComputeDynamicScore(
	node *prismlib.NodeState,
	incomingEdges []prismlib.EdgeState,
	allNodes map[string]*prismlib.NodeState,
	nowUnix int64,
) prismlib.AssetRiskResult {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.ComputeDynamicScore(node, incomingEdges, allNodes, cfg, nowUnix)
}

func (e *Engine) ComputeRiskVelocity(
	currentScore float64,
	prior *prismlib.RiskSnapshot,
	nowUnix int64,
) float64 {
	return prismlib.ComputeRiskVelocity(currentScore, prior, nowUnix)
}

func (e *Engine) FindPropagationPaths(
	source, target string,
	nodes map[string]*prismlib.NodeState,
	edges []prismlib.EdgeState,
	nowUnix int64,
	maxDepth int,
	limit int,
) []prismlib.PathResult {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.FindPropagationPaths(source, target, nodes, edges, cfg, nowUnix, maxDepth, limit)
}

// ----------------------------------------------------------
// Semantic Layer
// ----------------------------------------------------------

// ComputeSemanticState maps a Core Layer result to a four-state
// fuzzy membership report.
func (e *Engine) ComputeSemanticState(core *prismlib.AssetRiskResult) *prismlib.SemanticRiskReport {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.ComputeSemanticState(core, cfg)
}

// ComputeSemanticBatch processes multiple Core Layer results.
func (e *Engine) ComputeSemanticBatch(results []*prismlib.AssetRiskResult) []*prismlib.SemanticRiskReport {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.ComputeSemanticBatch(results, cfg)
}

// ----------------------------------------------------------
// Inference Layer
// ----------------------------------------------------------

// PredictFuture predicts future states using the given (or default) model.
func (e *Engine) PredictFuture(
	semantic *prismlib.SemanticRiskReport,
	model prismlib.InferenceModel,
) *prismlib.FutureRiskReport {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.PredictFuture(semantic, model, cfg)
}

// PredictFutureBatch predicts future states for multiple semantic reports.
func (e *Engine) PredictFutureBatch(
	reports []*prismlib.SemanticRiskReport,
	model prismlib.InferenceModel,
) []*prismlib.FutureRiskReport {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return prismlib.PredictFutureBatch(reports, model, cfg)
}

// ----------------------------------------------------------
// Full Pipeline (convenience)
// ----------------------------------------------------------

// EvaluateFull performs the complete three-layer pipeline:
// Core → Semantic → Inference, returning all three reports.
func (e *Engine) EvaluateFull(
	node *prismlib.NodeState,
	incomingEdges []prismlib.EdgeState,
	allNodes map[string]*prismlib.NodeState,
	nowUnix int64,
	model prismlib.InferenceModel,
) (core *prismlib.AssetRiskResult, semantic *prismlib.SemanticRiskReport, future *prismlib.FutureRiskReport) {
	// Core
	result := e.ComputeDynamicScore(node, incomingEdges, allNodes, nowUnix)
	core = &result

	// Semantic
	semantic = e.ComputeSemanticState(core)

	// Inference
	if semantic != nil {
		future = e.PredictFuture(semantic, model)
	}

	return core, semantic, future
}
