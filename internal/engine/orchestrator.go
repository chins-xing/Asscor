package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	ModeSequential ExecutionMode = "sequential" // run one after another
	ModeParallel   ExecutionMode = "parallel"   // run all concurrently
	ModeCascade    ExecutionMode = "cascade"    // primary first, secondary only if below threshold
)

// MergeStrategy controls how multiple results are combined into one final score.
type MergeStrategy string

const (
	MergeBestOf          MergeStrategy = "best_of"            // highest score wins
	MergeWorstOf         MergeStrategy = "worst_of"           // lowest score wins — eliminates barrel effect
	MergeWeightedAverage MergeStrategy = "weighted_average"    // weighted by algorithm confidence
	MergePrimaryOnly     MergeStrategy = "primary_only"       // primary score only, secondary advisory
	MergeConsensus       MergeStrategy = "consensus"          // all must agree; uses worst if disagreement
)

// CheckMode controls how check items from multiple algorithms are combined.
type CheckMode string

const (
	CheckMerge       CheckMode = "merge"        // union of all checks, deduplicate by CheckID (last writer wins)
	CheckIndependent CheckMode = "independent"   // each algorithm's checks are isolated to its own scoring
	CheckTagged      CheckMode = "tagged"        // checks tagged with source algorithm, scoring sees all tags
)

// AlgorithmProfile describes one scoring algorithm in the orchestration.
type AlgorithmProfile struct {
	ID          string
	Name        string
	Role        AlgorithmRole
	Engine      AssessorEngine          // scoring engine (SSAM, legacy, custom)
	Confidence  float64                 // confidence weight [0-1], used for weighted merges
	SharedChecks []string               // CheckIDs shared with other algorithms
	IndependentChecks []model.CheckItem // algorithm-specific checks not shared
	Enabled     bool
}

// OrchestrationConfig controls the multi-algorithm execution and merging.
type OrchestrationConfig struct {
	Mode          ExecutionMode
	Merge         MergeStrategy
	CheckMode     CheckMode
	CascadeThreshold float64 // for Cascade mode: if primary score >= this, skip secondaries

	// Algorithms in execution order. First is always considered primary when Role not set.
	Algorithms []AlgorithmProfile
}

// OrchestrationResult holds the complete multi-algorithm output.
type OrchestrationResult struct {
	FinalScore     float64
	Acceptable     bool
	Threshold      float64
	AlgoResults    []AlgoResult              // per-algorithm detailed results
	DomainScores   *model.DynamicDomainScores // final merged domain scores
	Checks         []model.CheckResult        // final merged check results
	MergeStrategy  MergeStrategy
	PrimaryScore   float64
	NumAlgos       int
	EliminatedByCascade []string              // algorithms skipped in Cascade mode

	// Barrel-effect elimination metrics
	AlgoSpread     float64  // max - min across algorithm scores
	AlgoVariance   float64  // statistical variance
	WorstAlgo      string   // which algorithm produced the lowest score
	BestAlgo       string   // which algorithm produced the highest score
}

// AlgoResult holds a single algorithm's scoring output.
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

// AlgorithmOrchestrator executes multiple scoring algorithms according to
// orchestration config and merges results to eliminate single-algorithm barrel effects.
type AlgorithmOrchestrator struct {
	cfg OrchestrationConfig
}

// NewOrchestrator creates a multi-algorithm orchestrator.
func NewOrchestrator(cfg OrchestrationConfig) *AlgorithmOrchestrator {
	return &AlgorithmOrchestrator{cfg: cfg}
}

// Run executes all enabled algorithms according to the orchestration config.
func (o *AlgorithmOrchestrator) Run(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult) *OrchestrationResult {
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

	result := o.buildOrchestrationResult(algoResults)
	result.NumAlgos = len(algoResults)
	return result
}

func (o *AlgorithmOrchestrator) enabledAlgorithms() []AlgorithmProfile {
	var enabled []AlgorithmProfile
	for _, a := range o.cfg.Algorithms {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	return enabled
}

func (o *AlgorithmOrchestrator) runSequential(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
	var results []AlgoResult
	for _, algo := range algos {
		r := o.runSingle(ctx, hostID, hostname, baseChecks, algo)
		results = append(results, r)
	}
	return results
}

func (o *AlgorithmOrchestrator) runParallel(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
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

func (o *AlgorithmOrchestrator) runCascade(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algos []AlgorithmProfile) []AlgoResult {
	var results []AlgoResult
	var eliminated []string

	for i, algo := range algos {
		if i > 0 && o.cfg.CascadeThreshold > 0 && len(results) > 0 {
			lastScore := results[len(results)-1].Score
			if lastScore >= o.cfg.CascadeThreshold {
				eliminated = append(eliminated, algo.ID)
				results = append(results, AlgoResult{
					AlgoID: algo.ID, AlgoName: algo.Name,
					Role: algo.Role, Error: "skipped_by_cascade",
				})
				continue
			}
		}

		r := o.runSingle(ctx, hostID, hostname, baseChecks, algo)
		results = append(results, r)
	}

	_ = eliminated
	return results
}

func (o *AlgorithmOrchestrator) runSingle(ctx context.Context, hostID, hostname string, baseChecks []model.CheckResult, algo AlgorithmProfile) AlgoResult {
	start := time.Now()

	checks := o.buildChecksForAlgo(baseChecks, algo)

	var score float64
	var acceptable bool
	var errStr string

	if algo.Engine != nil {
		built := model.AssessmentResult{
			HostID:    hostID,
			Hostname:  hostname,
			Timestamp: time.Now(),
			Checks:    checks,
		}
		if err := algo.Engine.ComputeScore(ctx, &built); err != nil {
			errStr = err.Error()
		} else {
			score = built.FinalScore
			acceptable = built.Acceptable
		}
	} else {
		errStr = "no engine configured"
	}

	return AlgoResult{
		AlgoID:     algo.ID,
		AlgoName:   algo.Name,
		Role:       algo.Role,
		Score:      score,
		Acceptable: acceptable,
		Checks:     checks,
		Duration:   time.Since(start),
		Error:      errStr,
		Confidence: algo.Confidence,
	}
}

func (o *AlgorithmOrchestrator) buildChecksForAlgo(baseChecks []model.CheckResult, algo AlgorithmProfile) []model.CheckResult {
	sharedSet := make(map[string]bool)
	for _, id := range algo.SharedChecks {
		sharedSet[id] = true
	}

	var checks []model.CheckResult

	switch o.cfg.CheckMode {
	case CheckIndependent:
		// Independent mode: only this algorithm's independent checks + base checks tagged with this algo
		for _, c := range algo.IndependentChecks {
			checks = append(checks, c.Run())
		}
		for _, c := range baseChecks {
			if sharedSet[c.CheckID] {
				checks = append(checks, c)
			}
		}

	case CheckTagged:
		// Tagged mode: all checks run, but tagged with algorithm source
		for _, c := range algo.IndependentChecks {
			r := c.Run()
			r.Source = algo.ID
			checks = append(checks, r)
		}
		for _, c := range baseChecks {
			c.Source = algo.ID
			checks = append(checks, c)
		}

	default: // CheckMerge
		// Merge mode: union of independent + shared base checks
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

func (o *AlgorithmOrchestrator) buildOrchestrationResult(algoResults []AlgoResult) *OrchestrationResult {
	if len(algoResults) == 0 {
		return &OrchestrationResult{FinalScore: 100, Acceptable: true}
	}

	r := &OrchestrationResult{
		AlgoResults:   algoResults,
		MergeStrategy: o.cfg.Merge,
	}

	// Collect scores and compute spread
	var scores []float64
	var weights []float64
	var minScore, maxScore float64
	var minAlgo, maxAlgo string
	minScore = 101 // above max possible
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

	// Compute spread and variance
	r.AlgoSpread = maxScore - minScore
	r.AlgoVariance = computeVariance(scores)

	// Find primary score
	for _, ar := range algoResults {
		if ar.Role == RolePrimary && ar.Error == "" {
			r.PrimaryScore = ar.Score
			break
		}
	}
	if r.PrimaryScore == 0 && len(scores) > 0 {
		r.PrimaryScore = scores[0] // fallback: first successful
	}

	// Apply merge strategy
	switch o.cfg.Merge {
	case MergeBestOf:
		r.FinalScore = maxScore
		r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
		// Collect checks from the best-scoring algorithm
		for _, ar := range algoResults {
			if ar.Score == maxScore && ar.Error == "" {
				r.Checks = ar.Checks
				break
			}
		}

	case MergeWorstOf:
		// Eliminate barrel effect: use the lowest score
		r.FinalScore = minScore
		r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
		for _, ar := range algoResults {
			if ar.Score == minScore && ar.Error == "" {
				r.Checks = ar.Checks
				break
			}
		}

	case MergeWeightedAverage:
		var weightedSum, totalWeight float64
		for i, s := range scores {
			w := 1.0
			if i < len(weights) && weights[i] > 0 {
				w = weights[i]
			}
			weightedSum += s * w
			totalWeight += w
		}
		if totalWeight > 0 {
			r.FinalScore = weightedSum / totalWeight
		} else {
			r.FinalScore = scores[0]
		}
		r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
		r.Checks = collectAllChecks(algoResults)

	case MergeConsensus:
		// Consensus: if all agree (within 5% spread), use average. Otherwise use worst.
		if r.AlgoSpread <= 5.0 && len(scores) > 1 {
			var sum float64
			for _, s := range scores {
				sum += s
			}
			r.FinalScore = sum / float64(len(scores))
		} else {
			r.FinalScore = minScore
		}
		r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
		r.Checks = collectAllChecks(algoResults)

	default: // MergePrimaryOnly
		r.FinalScore = r.PrimaryScore
		r.Acceptable = r.FinalScore >= o.cfg.CascadeThreshold
		// Use primary algorithm's checks
		for _, ar := range algoResults {
			if ar.Role == RolePrimary && ar.Error == "" {
				r.Checks = ar.Checks
				break
			}
		}
		if len(r.Checks) == 0 && len(scores) > 0 {
			r.Checks = algoResults[0].Checks
		}
	}

	// Merge domain scores from all algorithms
	r.DomainScores = mergeDomainScores(algoResults, o.cfg.Merge)

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

	// Collect per-domain scores from all algorithms
	domainScores := make(map[string][]float64)

	for _, ar := range results {
		if ar.Error != "" || ar.DomainScores == nil {
			continue
		}
		for domain, score := range ar.DomainScores.GetAll() {
			domainScores[domain] = append(domainScores[domain], score)
		}
	}

	// Merge per domain according to strategy
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
			merged = scores[0] // PrimaryOnly: use first
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
	return max
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
	return min
}

// Validate checks the orchestrator configuration for consistency.
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
			return fmt.Errorf("algorithm %s confidence must be in [0,1], got %.2f", a.ID, a.Confidence)
		}
	}
	if !hasPrimary && len(c.Algorithms) > 0 {
		// Auto-assign first enabled as primary
		c.Algorithms[0].Role = RolePrimary
	}
	return nil
}
