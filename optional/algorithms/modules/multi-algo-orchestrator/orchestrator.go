// Package multialgo provides an optional multi-algorithm orchestration engine
// for ASSCOR. It is NOT part of the core ASSCOR framework — users must manually
// clone this module and recompile the kernel to enable it.
//
// The orchestrator wires into ASSCOR via the Extension Point system:
//   - Subscribes to "assessor.pre_score" to intercept scoring
//   - Fires "multialgo.result" with the merged OrchestrationResult
//
// Usage (in cmd/kernel/main.go):
//
//	import multialgo "github.com/asscor/asscor-optional-multi-algo"
//
//	// After kernel bootstrap:
//	cfg := multialgo.OrchestrationConfig{
//	    Mode:  multialgo.ModeCascade,
//	    Merge: multialgo.MergeWorstOf,
//	    Algorithms: []multialgo.AlgorithmProfile{...},
//	}
//	orch := multialgo.NewOrchestrator(cfg)
//	orch.Register(k.Extensions())
//
// Config-driven (config.ini):
//
//	[optional.multi_algo]
//	enabled = true
//	mode = cascade
//	merge = worst_of
package multialgo

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/model"
)

// AlgorithmRole labels an algorithm's position in the orchestration.
type AlgorithmRole string

const (
	RolePrimary   AlgorithmRole = "primary"
	RoleSecondary AlgorithmRole = "secondary"
	RoleAdvisory  AlgorithmRole = "advisory"
)

// ExecutionMode controls how algorithms are dispatched.
type ExecutionMode string

const (
	ModeSequential ExecutionMode = "sequential"
	ModeParallel   ExecutionMode = "parallel"
	ModeCascade    ExecutionMode = "cascade"
)

// MergeStrategy controls how multiple results are combined.
type MergeStrategy string

const (
	MergeBestOf          MergeStrategy = "best_of"
	MergeWorstOf         MergeStrategy = "worst_of"
	MergeWeightedAverage MergeStrategy = "weighted_average"
	MergePrimaryOnly     MergeStrategy = "primary_only"
	MergeConsensus       MergeStrategy = "consensus"
	// MergeWhiteboxFirst merges only white-box algorithms (primary/secondary).
	// Advisory (black-box) algorithms never enter the final score — their output
	// is recorded as untrusted reference only, preserving white-box determinism.
	MergeWhiteboxFirst MergeStrategy = "whitebox_first"
)

// CheckMode controls how checks from multiple algorithms are combined.
type CheckMode string

const (
	CheckMerge       CheckMode = "merge"
	CheckIndependent CheckMode = "independent"
	CheckTagged      CheckMode = "tagged"
)

// AlgorithmProfile describes one scoring algorithm.
type AlgorithmProfile struct {
	ID                string
	Name              string
	Role              AlgorithmRole
	EngineConstructor func() engine.AssessorEngine
	Confidence        float64
	SharedChecks      []string
	IndependentChecks []model.CheckItem
	Enabled           bool
}

// OrchestrationConfig controls multi-algorithm execution and merging.
type OrchestrationConfig struct {
	Mode             ExecutionMode
	Merge            MergeStrategy
	CheckMode        CheckMode
	CascadeThreshold float64
	Algorithms       []AlgorithmProfile
}

// OrchestrationResult holds the complete multi-algorithm output.
type OrchestrationResult struct {
	FinalScore          float64
	Acceptable          bool
	Threshold           float64
	AlgoResults         []AlgoResult
	DomainScores        *model.DynamicDomainScores
	Checks              []model.CheckResult
	MergeStrategy       MergeStrategy
	PrimaryScore        float64
	NumAlgos            int
	EliminatedByCascade []string
	AlgoSpread          float64
	AlgoVariance        float64
	WorstAlgo           string
	BestAlgo            string
}

// AlgoResult holds a single algorithm's output.
type AlgoResult struct {
	AlgoID       string
	AlgoName     string
	Role         AlgorithmRole
	Score        float64
	Acceptable   bool
	DomainScores *model.DynamicDomainScores
	Checks       []model.CheckResult
	Duration     time.Duration
	Error        string
	Confidence   float64
}

// Orchestrator executes multiple scoring algorithms and merges results.
type Orchestrator struct {
	cfg OrchestrationConfig
	id  string
}

// NewOrchestrator creates an orchestrator with the given config.
func NewOrchestrator(cfg OrchestrationConfig) *Orchestrator {
	if err := cfg.Validate(); err != nil {
		panic("invalid orchestrator config: " + err.Error())
	}
	return &Orchestrator{cfg: cfg, id: "multi-algo-orchestrator"}
}

// Register wires the orchestrator into the ASSCOR extension point system.
// Call this after kernel bootstrap.
func (o *Orchestrator) Register(ext kernel.ModuleExtensions) {
	ext.RegisterExtension(o.id, "assessor.pre_score", func(ctx context.Context, data interface{}) error {
		result, ok := data.(*model.AssessmentResult)
		if !ok || result == nil {
			return nil
		}
		o.interceptAndScore(ctx, result)
		return nil
	}, 45)
}

// Run executes all enabled algorithms.
func (o *Orchestrator) Run(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult) *OrchestrationResult {
	enabled := o.enabledAlgorithms()
	if len(enabled) == 0 {
		return &OrchestrationResult{FinalScore: 100, Acceptable: true}
	}

	var algoResults []AlgoResult
	switch o.cfg.Mode {
	case ModeParallel:
		algoResults = o.runParallel(ctx, hostID, hostname, baseChecks, enabled)
	case ModeCascade:
		algoResults = o.runCascade(ctx, hostID, hostname, baseChecks, enabled)
	default:
		algoResults = o.runSequential(ctx, hostID, hostname, baseChecks, enabled)
	}

	return o.buildOrchestrationResult(algoResults)
}

func (o *Orchestrator) interceptAndScore(ctx context.Context, result *model.AssessmentResult) {
	or := o.Run(ctx, result.HostID, result.Hostname, result.Checks)
	result.FinalScore = or.FinalScore
	result.Acceptable = or.Acceptable
	if or.DomainScores != nil {
		result.DomainScores = or.DomainScores.ToLegacy()
	}
	result.UncertaintyNote = fmt.Sprintf("Multi-algo (%s, %s, spread=%.1f)",
		o.cfg.Merge, or.BestAlgo, or.AlgoSpread)
}

func (o *Orchestrator) enabledAlgorithms() []AlgorithmProfile {
	var enabled []AlgorithmProfile
	for _, a := range o.cfg.Algorithms {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	return enabled
}

func (o *Orchestrator) runSequential(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
	var results []AlgoResult
	for _, algo := range algos {
		results = append(results, o.runSingle(ctx, hostID, hostname, baseChecks, algo))
	}
	return results
}

func (o *Orchestrator) runParallel(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
	results := make([]AlgoResult, len(algos))
	var wg sync.WaitGroup
	for i, algo := range algos {
		wg.Add(1)
		go func(idx int, a AlgorithmProfile) {
			defer wg.Done()
			results[idx] = o.runSingle(ctx, hostID, hostname, baseChecks, a)
		}(i, algo)
	}
	wg.Wait()
	return results
}

func (o *Orchestrator) runCascade(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
	var results []AlgoResult
	for i, algo := range algos {
		if i > 0 && o.cfg.CascadeThreshold > 0 && len(results) > 0 {
			if results[len(results)-1].Score >= o.cfg.CascadeThreshold {
				results = append(results, AlgoResult{
					AlgoID: algo.ID, AlgoName: algo.Name,
					Role: algo.Role, Error: "skipped_by_cascade",
				})
				continue
			}
		}
		results = append(results, o.runSingle(ctx, hostID, hostname, baseChecks, algo))
	}
	return results
}

func (o *Orchestrator) runSingle(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algo AlgorithmProfile) AlgoResult {
	start := time.Now()
	checks := o.buildChecksForAlgo(baseChecks, algo)

	var score float64
	var acceptable bool
	var errStr string

	eng := algo.EngineConstructor()
	if eng != nil {
		built := model.AssessmentResult{
			HostID: hostID, Hostname: hostname,
			Timestamp: time.Now(), Checks: checks,
		}
		if err := eng.ComputeScore(ctx, &built); err != nil {
			errStr = err.Error()
		} else {
			score = built.FinalScore
			acceptable = built.Acceptable
		}
	} else {
		errStr = "no engine constructor"
	}

	return AlgoResult{
		AlgoID: algo.ID, AlgoName: algo.Name,
		Role: algo.Role, Score: score, Acceptable: acceptable,
		Checks: checks, Duration: time.Since(start),
		Error: errStr, Confidence: algo.Confidence,
	}
}

func (o *Orchestrator) buildChecksForAlgo(baseChecks []model.CheckResult, algo AlgorithmProfile) []model.CheckResult {
	sharedSet := make(map[string]bool)
	for _, id := range algo.SharedChecks {
		sharedSet[id] = true
	}
	var checks []model.CheckResult
	switch o.cfg.CheckMode {
	case CheckIndependent:
		for _, c := range algo.IndependentChecks {
			checks = append(checks, c.Run())
		}
		for _, c := range baseChecks {
			if sharedSet[c.CheckID] {
				checks = append(checks, c)
			}
		}
	case CheckTagged:
		for _, c := range algo.IndependentChecks {
			r := c.Run()
			checks = append(checks, r)
		}
		for _, c := range baseChecks {
			checks = append(checks, c)
		}
	default:
		for _, c := range algo.IndependentChecks {
			checks = append(checks, c.Run())
		}
		checkIDs := make(map[string]bool)
		for _, c := range checks {
			checkIDs[c.CheckID] = true
		}
		for _, c := range baseChecks {
			if sharedSet[c.CheckID] && !checkIDs[c.CheckID] {
				checks = append(checks, c)
				checkIDs[c.CheckID] = true
			}
		}
	}
	return checks
}

func (o *Orchestrator) buildOrchestrationResult(algoResults []AlgoResult) *OrchestrationResult {
	if len(algoResults) == 0 {
		return &OrchestrationResult{FinalScore: 100, Acceptable: true}
	}
	r := &OrchestrationResult{AlgoResults: algoResults, MergeStrategy: o.cfg.Merge}
	var scores []float64
	var weights []float64
	var minScore, maxScore float64 = 101, 0
	var minAlgo, maxAlgo string
	var eliminated []string

	for i := range algoResults {
		ar := &algoResults[i]
		if ar.Error == "skipped_by_cascade" {
			eliminated = append(eliminated, ar.AlgoName)
			continue
		}
		if ar.Error != "" {
			continue
		}
		// WhiteboxFirst: advisory (black-box) algorithms never enter the score pool.
		if o.cfg.Merge == MergeWhiteboxFirst && ar.Role == RoleAdvisory {
			continue
		}
		scores = append(scores, ar.Score)
		weights = append(weights, ar.Confidence)
		if ar.Score < minScore {
			minScore = ar.Score
			minAlgo = ar.AlgoName
		}
		if ar.Score > maxScore {
			maxScore = ar.Score
			maxAlgo = ar.AlgoName
		}
	}
	r.WorstAlgo = minAlgo
	r.BestAlgo = maxAlgo
	r.EliminatedByCascade = eliminated

	if len(scores) == 0 {
		r.FinalScore = 100
		r.Acceptable = true
		return r
	}
	r.AlgoSpread = maxScore - minScore
	r.AlgoVariance = computeVariance(scores)

	for _, ar := range algoResults {
		if ar.Role == RolePrimary && ar.Error == "" {
			r.PrimaryScore = ar.Score
			break
		}
	}
	if r.PrimaryScore == 0 && len(scores) > 0 {
		r.PrimaryScore = scores[0]
	}

	switch o.cfg.Merge {
	case MergeBestOf:
		r.FinalScore = maxScore
	case MergeWorstOf:
		r.FinalScore = minScore
	case MergeWeightedAverage:
		var ws, tw float64
		for i, s := range scores {
			w := 1.0
			if i < len(weights) && weights[i] > 0 {
				w = weights[i]
			}
			ws += s * w
			tw += w
		}
		if tw > 0 {
			r.FinalScore = ws / tw
		} else {
			r.FinalScore = scores[0]
		}
	case MergeConsensus:
		if r.AlgoSpread <= 5.0 && len(scores) > 1 {
			var sum float64
			for _, s := range scores {
				sum += s
			}
			r.FinalScore = sum / float64(len(scores))
		} else {
			r.FinalScore = minScore
		}
	case MergeWhiteboxFirst:
		// scores already exclude advisory (black-box) algorithms.
		// White-box pool merges with worst_of semantics to eliminate barrel effect.
		r.FinalScore = minScore
	default:
		r.FinalScore = r.PrimaryScore
	}
	r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
	r.DomainScores = mergeDomainScores(algoResults, o.cfg.Merge)
	r.Checks = collectAllChecks(algoResults)
	return r
}

func collectAllChecks(results []AlgoResult) []model.CheckResult {
	seen := make(map[string]bool)
	var checks []model.CheckResult
	for _, ar := range results {
		if ar.Error != "" {
			continue
		}
		for _, c := range ar.Checks {
			if !seen[c.CheckID] {
				seen[c.CheckID] = true
				checks = append(checks, c)
			}
		}
	}
	return checks
}

func mergeDomainScores(results []AlgoResult, strategy MergeStrategy) *model.DynamicDomainScores {
	dyn := model.NewDynamicDomainScores()
	if len(results) == 0 {
		return dyn
	}
	domainScores := make(map[string][]float64)
	for _, ar := range results {
		if ar.Error != "" || ar.DomainScores == nil {
			continue
		}
		for domain, score := range ar.DomainScores.GetAll() {
			domainScores[domain] = append(domainScores[domain], score)
		}
	}
	for domain, scores := range domainScores {
		if len(scores) == 0 {
			continue
		}
		var merged float64
		switch strategy {
		case MergeBestOf:
			merged = maxFloat(scores)
		case MergeWorstOf, MergeConsensus:
			merged = minFloat(scores)
		case MergeWeightedAverage:
			var sum float64
			for _, s := range scores {
				sum += s
			}
			merged = sum / float64(len(scores))
		default:
			merged = scores[0]
		}
		dyn.Set(domain, merged)
	}
	return dyn
}

func computeVariance(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	var sum float64
	for _, s := range scores {
		sum += s
	}
	mean := sum / float64(len(scores))
	var variance float64
	for _, s := range scores {
		d := s - mean
		variance += d * d
	}
	return variance / float64(len(scores))
}

func maxFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	max := vals[0]
	for _, v := range vals[1:] {
		if v > max {
			max = v
		}
	}
	return math.Round(max*100) / 100
}

func minFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	min := vals[0]
	for _, v := range vals[1:] {
		if v < min {
			min = v
		}
	}
	return math.Round(min*100) / 100
}

// Validate checks the configuration for consistency.
func (c OrchestrationConfig) Validate() error {
	if len(c.Algorithms) == 0 {
		return fmt.Errorf("at least one algorithm is required")
	}
	seenIDs := make(map[string]bool)
	hasPrimary := false
	for _, a := range c.Algorithms {
		if a.ID == "" {
			return fmt.Errorf("algorithm ID is required")
		}
		if seenIDs[a.ID] {
			return fmt.Errorf("duplicate algorithm ID: %s", a.ID)
		}
		seenIDs[a.ID] = true
		if a.Role == RolePrimary {
			hasPrimary = true
		}
		if a.Confidence < 0 || a.Confidence > 1 {
			return fmt.Errorf("algorithm %s confidence must be in [0,1]", a.ID)
		}
	}
	if !hasPrimary {
		return fmt.Errorf("at least one primary algorithm is required")
	}
	return nil
}
