package prism

import (
	"sync"

	prismlib "github.com/chins-xing/prism"
)

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
