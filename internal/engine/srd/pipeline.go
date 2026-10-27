//go:build engine

package srd

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	ascorprism "github.com/chins-xing/asscor/internal/engine/prism"
	"github.com/chins-xing/asscor/internal/logger"
	prismlib "github.com/chins-xing/prism"
)

// PrismScoringEngine is the Prism interface that SRD depends on.
// Implementations (e.g., internal/prism.Engine) inject via SetPrismEngine.
// SRD owns this interface; Prism adapters depend on SRD.
type PrismScoringEngine interface {
	ComputeDynamicScore(node *prismlib.NodeState, incomingEdges []prismlib.EdgeState, allNodes map[string]*prismlib.NodeState, nowUnix int64) prismlib.AssetRiskResult
	ComputeSemanticState(core *prismlib.AssetRiskResult) *prismlib.SemanticRiskReport
	PredictFuture(semantic *prismlib.SemanticRiskReport, model prismlib.InferenceModel) *prismlib.FutureRiskReport
}

// Pipeline processes ExternalAssessmentReport through the Prism engine.
// It normalizes external tool output into Prism NodeState and computes SRD scores.
type Pipeline struct {
	cfg       Config
	prism     PrismScoringEngine
	mu        sync.RWMutex
	snapshots map[string]*prismlib.NodeState
	topology  map[string]*TopologyInfo
}

// TopologyInfo carries a host's network position for real-edge construction.
type TopologyInfo struct {
	Subnets []string
	Zone    string
}

// NewPipeline creates a new SRD pipeline with a built-in Prism engine.
// Use SetPrismEngine to inject a custom implementation.
func NewPipeline(cfg Config) *Pipeline {
	return NewPipelineWithEngine(cfg, ascorprism.NewEngine())
}

// NewPipelineWithEngine creates a new SRD pipeline with the given Prism engine.
func NewPipelineWithEngine(cfg Config, prism PrismScoringEngine) *Pipeline {
	return &Pipeline{
		cfg:       cfg,
		prism:     prism,
		snapshots: make(map[string]*prismlib.NodeState),
		topology:  make(map[string]*TopologyInfo),
	}
}

// SetTopology records a host's network position for real-edge construction.
func (p *Pipeline) SetTopology(hostID string, subnets []string, zone string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.topology[hostID] = &TopologyInfo{Subnets: subnets, Zone: zone}
}

// SetPrismEngine replaces the Prism engine at runtime.
func (p *Pipeline) SetPrismEngine(engine PrismScoringEngine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prism = engine
}

// Process converts an external assessment report into a Prism result and stores a topology snapshot.
func (p *Pipeline) Process(ctx context.Context, report *ExternalAssessmentReport) *SRDResult {
	if report == nil {
		return nil
	}

	node := p.reportToNodeState(report)
	nowUnix := time.Now().Unix()

	p.mu.Lock()
	p.snapshots[report.HostID] = node
	allNodes := make(map[string]*prismlib.NodeState, len(p.snapshots))
	for id, n := range p.snapshots {
		allNodes[id] = n
	}
	p.mu.Unlock()

	// buildIncomingEdges acquires its own RLock (via areConnected) — must be
	// called OUTSIDE the write lock to avoid a non-reentrant RWMutex deadlock.
	incomingEdges := p.buildIncomingEdges(report.HostID, allNodes)

	prismResult := p.prism.ComputeDynamicScore(node, incomingEdges, allNodes, nowUnix)

	semantic := p.prism.ComputeSemanticState(&prismResult)
	future := p.prism.PredictFuture(semantic, nil)

	logger.WithComponent("srd").Debug("external report processed",
		"tool", report.Tool,
		"host", report.HostID,
		"items", len(report.Items),
		"raw_score", report.RawScore,
		"ssam_score", prismResult.SsamScore,
		"prism_score", prismResult.PrismScore,
		"semantic_state", semantic.CurrentState,
		"inference_trend", future.Trend,
	)

	return &SRDResult{
		Report:          report,
		PrismResult:     &prismResult,
		SemanticResult:  semantic,
		InferenceResult: future,
		ProcessedAt:     time.Now(),
	}
}

// ProcessFromFile reads an external report file, detects the tool type, and processes it.
func (p *Pipeline) ProcessFromFile(ctx context.Context, path string) (*SRDResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try each registered adapter in order: specific tools first, then generic.
	for _, toolID := range []string{"openscap", "lynis"} {
		if ad, ok := Get(toolID); ok && ad.SupportsFormat(path) && ad.IsEnabled(p.cfg) {
			report, err := ad.Parse(ctx, data)
			if err == nil && report != nil {
				return p.Process(ctx, report), nil
			}
		}
	}

	// Fall back to generic adapter.
	if ad, ok := Get("generic"); ok && ad.IsEnabled(p.cfg) {
		report, err := ad.Parse(ctx, data)
		if err == nil && report != nil {
			return p.Process(ctx, report), nil
		}
		return nil, err
	}

	return nil, nil
}

// ProcessFromBytes detects the adapter by content and processes the report.
func (p *Pipeline) ProcessFromBytes(ctx context.Context, toolID string, data []byte) (*SRDResult, error) {
	var ad Adapter
	if toolID != "" {
		var ok bool
		ad, ok = Get(toolID)
		if !ok {
			return nil, nil
		}
	} else {
		// Auto-detect by content.
		for _, id := range []string{"openscap", "lynis"} {
			if a, ok := Get(id); ok && a.IsEnabled(p.cfg) {
				report, err := a.Parse(ctx, data)
				if err == nil && report != nil {
					return p.Process(ctx, report), nil
				}
			}
		}
		if ad == nil {
			ad, _ = Get("generic")
		}
	}

	if ad == nil {
		return nil, nil
	}

	report, err := ad.Parse(ctx, data)
	if err != nil {
		return nil, err
	}
	return p.Process(ctx, report), nil
}

func (p *Pipeline) reportToNodeState(report *ExternalAssessmentReport) *prismlib.NodeState {
	node := &prismlib.NodeState{
		HostID:     report.HostID,
		SSAMScore:  report.RawScore,
		Confidence: reportConfidence(report),
	}

	for _, item := range report.Items {
		if item.Result == "fail" {
			failAt := item.FailAt
			if failAt == 0 {
				failAt = report.ScanTime.Unix()
			}
			confidence := item.Confidence
			// 0 = the tool did not supply one → resolve through the SAME rule
			// table as the kernel, keyed by the tool id (audit I-8). The
			// Enabled guard keeps the default path bit-identical: with
			// confidence disabled the item stays 0 (prism treats 0 as full
			// trust), exactly as before.
			if confidence <= 0 && p.cfg.Confidence != nil && p.cfg.Confidence.Enabled {
				confidence = p.cfg.Confidence.Resolve(item.CheckID, report.Tool, item.Category)
			}
			node.FailedChecks = append(node.FailedChecks, prismlib.CheckFailure{
				CheckID:    item.CheckID,
				Delta:      item.Delta,
				FailUnix:   failAt,
				Confidence: confidence, // 0 → prism treats as 1.0 (legacy)
			})
		}
	}

	return node
}

// reportConfidence aggregates per-item confidences into a report-level signal
// for NodeState.Confidence (mean of the failed items' confidences, clamped to
// [0,1]; 1 when there are no failed items or all are unspecified).
func reportConfidence(report *ExternalAssessmentReport) float64 {
	if report == nil {
		return 1.0
	}
	sum := 0.0
	n := 0.0
	for _, item := range report.Items {
		if item.Result != "fail" {
			continue
		}
		if item.Confidence > 0 {
			sum += item.Confidence
			n++
		}
	}
	if n == 0 {
		return 1.0
	}
	avg := sum / n
	if avg > 1 {
		return 1.0
	}
	return avg
}

func (p *Pipeline) buildIncomingEdges(hostID string, allNodes map[string]*prismlib.NodeState) []prismlib.EdgeState {
	all := p.BuildEdges(allNodes)
	edges := make([]prismlib.EdgeState, 0, len(all))
	for _, e := range all {
		if e.Target == hostID {
			edges = append(edges, e)
		}
	}
	return edges
}

// areConnected checks whether two hosts share a subnet. Returns true when
// topology data is incomplete (conservative fallback to complete graph).
func (p *Pipeline) areConnected(hostA, hostB string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.areConnectedLocked(hostA, hostB)
}

// areConnectedLocked is the no-lock variant — caller must hold p.mu (R or W).
func (p *Pipeline) areConnectedLocked(hostA, hostB string) bool {
	a, aOK := p.topology[hostA]
	b, bOK := p.topology[hostB]
	if !aOK || !bOK {
		return true // no topology data → assume connected (backward compatible)
	}
	for _, sa := range a.Subnets {
		for _, sb := range b.Subnets {
			if subnetOverlap(sa, sb) {
				return true
			}
		}
	}
	return false
}

// GetReachableHosts returns hosts sharing a subnet with hostID — the
// lateral-movement scope used by the lifecycle Locator.
func (p *Pipeline) GetReachableHosts(hostID string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var reachable []string
	for id := range p.snapshots {
		if id != hostID && p.areConnectedLocked(hostID, id) {
			reachable = append(reachable, id)
		}
	}
	return reachable
}

// subnetOverlap reports whether two CIDR strings overlap.
func subnetOverlap(a, b string) bool {
	_, na, err1 := net.ParseCIDR(a)
	_, nb, err2 := net.ParseCIDR(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP)
}

// SRDResult holds the processed external report and its full Prism-computed analysis.
type SRDResult struct {
	Report          *ExternalAssessmentReport
	PrismResult     *prismlib.AssetRiskResult
	SemanticResult  *prismlib.SemanticRiskReport
	InferenceResult *prismlib.FutureRiskReport
	ProcessedAt     time.Time
}
