package ssam

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type Engine struct {
	mu           sync.RWMutex
	weights      map[string]float64
	edgeFactors  map[string]EdgeFactorConfig
	formulaID    string
	formulas     map[string]ScoringFormula
	hooks        map[HookPhase][]hookEntry
	domains      []DomainScore
}

type hookEntry struct {
	id       string
	hook     AssessmentHook
	priority int
}

var _ Provider = (*Engine)(nil)

func NewEngine() *Engine {
	e := &Engine{
		weights:     make(map[string]float64),
		edgeFactors: make(map[string]EdgeFactorConfig),
		formulaID:   "ssam_v1.2",
		formulas:    make(map[string]ScoringFormula),
		hooks:       make(map[HookPhase][]hookEntry),
	}
	e.formulas["ssam_v1.2"] = e.ssamV12Formula
	e.formulas["simple_weighted"] = e.simpleWeightedFormula
	return e
}

func (e *Engine) ComputeScore(ctx context.Context, input *AssessmentInput) (*AssessmentOutput, error) {
	if input == nil {
		return nil, ErrNilInput
	}

	if err := ValidateInput(input); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	output := &AssessmentOutput{
		HostID:       input.HostID,
		Threshold:    input.Threshold,
		ThreatCoeff:  input.ThreatCoeff,
		SPCScore:     input.SPCScore,
		FormulaID:    e.formulaID,
		CalculatedAt: time.Now(),
		Metadata:     make(map[string]string),
	}

	if output.ThreatCoeff == 0 {
		output.ThreatCoeff = 1.0
	}
	if output.SPCScore == 0 {
		output.SPCScore = 1.0
	}

	e.ExecuteHooks(ctx, HookPreScore, input, output)

	output.DomainScores = e.ComputeDomainScores(input.Checks)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostScore, input, output)

	e.ExecuteHooks(ctx, HookPreEdge, input, output)

	customFactors := e.buildCustomFactorMap()
	output.EdgeFactors = e.ApplyEdgeFactorsToChecks(input.Checks, customFactors)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostEdge, input, output)

	output.FinalScore = e.applyFormula(output.DomainScores, output.ThreatCoeff, output.SPCScore, output.EdgeFactors)
	output.FinalScore = math.Round(output.FinalScore*100) / 100
	output.Acceptable = output.FinalScore >= output.Threshold

	return output, nil
}

func (e *Engine) ComputeDomainScores(checks []CheckInput) []DomainScore {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activeDomains := make(map[string]bool)
	for _, c := range checks {
		activeDomains[c.Domain] = true
	}
	if len(activeDomains) == 0 {
		for domain := range e.weights {
			activeDomains[domain] = true
		}
	}

	scores := make(map[string]float64)
	for domain := range activeDomains {
		scores[domain] = 100
	}

	for _, check := range checks {
		if check.Passed {
			continue
		}
		current := scores[check.Domain]
		scores[check.Domain] = math.Max(0, current+check.Delta)
	}

	result := make([]DomainScore, 0, len(scores))
	for domain, score := range scores {
		result = append(result, DomainScore{Domain: domain, Score: score})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

func (e *Engine) ComputeWeightedSum(domainScores []DomainScore) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		w, ok := e.weights[ds.Domain]
		if !ok {
			w = 0
		}
		if w == 0 {
			continue
		}
		sum += ds.Score * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0
	}
	return sum / totalWeight
}

func (e *Engine) ApplyEdgeFactors(baseScore float64, factors []EdgeFactorResult) float64 {
	result := baseScore
	for _, f := range factors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			result *= f.Factor
		}
	}
	return math.Round(result*100) / 100
}

func (e *Engine) ApplyEdgeFactorsToChecks(checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]EdgeFactorResult, 0)
	triggered := make(map[string]bool)

	for _, check := range checks {
		if check.Passed {
			continue
		}
		for id, cfg := range e.edgeFactors {
			if cfg.TriggerCheck == check.CheckID {
				triggered[id] = true
			}
		}
	}

	cascadeOverrides := make(map[string]float64)
	for id, cfg := range e.edgeFactors {
		if triggered[id] && cfg.CascadeTo != "" && cfg.CascadeValue > 0 {
			cascadeOverrides[cfg.CascadeTo] = cfg.CascadeValue
		}
	}

	for id, cfg := range e.edgeFactors {
		factor := cfg.Factor
		active := false

		if triggered[id] {
			active = true
			if custom, ok := customFactors[id]; ok && custom > 0 && custom < 1.0 {
				factor = custom
			}
		}

		if overrideVal, ok := cascadeOverrides[id]; ok && triggered[id] {
			if overrideVal < factor {
				factor = overrideVal
			}
		}

		activeInResult := active
		if cfg.CascadeOnly && active {
			activeInResult = false
		}

		results = append(results, EdgeFactorResult{
			ID:     id,
			Name:   cfg.Name,
			Factor: factor,
			Active: activeInResult,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

func (e *Engine) ListEdgeFactors() []EdgeFactorResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]EdgeFactorResult, 0, len(e.edgeFactors))
	for id, cfg := range e.edgeFactors {
		results = append(results, EdgeFactorResult{
			ID:     id,
			Name:   cfg.Name,
			Factor: cfg.Factor,
			Active: false,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

func (e *Engine) EvaluateEdgeFactors(checks []CheckInput, customFactors map[string]float64) []EdgeFactorResult {
	return e.ApplyEdgeFactorsToChecks(checks, customFactors)
}

func (e *Engine) SetWeights(weights []WeightConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.weights = make(map[string]float64)
	for _, w := range weights {
		e.weights[w.Domain] = w.Weight
	}
}

func (e *Engine) GetWeights() []WeightConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]WeightConfig, 0, len(e.weights))
	for domain, weight := range e.weights {
		result = append(result, WeightConfig{Domain: domain, Weight: weight})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

func (e *Engine) SetFormula(formulaID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.formulas[formulaID]; ok {
		e.formulaID = formulaID
	}
}

func (e *Engine) GetFormula() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.formulaID
}

func (e *Engine) RegisterFormula(id string, formula ScoringFormula) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.formulas[id] = formula
}

func (e *Engine) SetEdgeFactors(factors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.edgeFactors = make(map[string]EdgeFactorConfig)
	for _, f := range factors {
		e.edgeFactors[f.ID] = f
	}
}

func (e *Engine) ListDomains() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domains := make([]string, 0, len(e.weights))
	for d := range e.weights {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

func (e *Engine) GetDomainLabel(id string) string {
	return id
}

func (e *Engine) GetDefaultWeight(id string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if w, ok := e.weights[id]; ok {
		return w
	}
	return 0
}

func (e *Engine) RegisterHook(phase HookPhase, id string, hook AssessmentHook, priority int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks[phase] = append(e.hooks[phase], hookEntry{id: id, hook: hook, priority: priority})
	sort.Slice(e.hooks[phase], func(i, j int) bool {
		return e.hooks[phase][i].priority < e.hooks[phase][j].priority
	})
}

func (e *Engine) UnregisterHook(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for phase, hooks := range e.hooks {
		filtered := hooks[:0]
		for _, h := range hooks {
			if h.id != id {
				filtered = append(filtered, h)
			}
		}
		if len(filtered) == 0 {
			delete(e.hooks, phase)
		} else {
			e.hooks[phase] = filtered
		}
	}
}

func (e *Engine) ExecuteHooks(ctx context.Context, phase HookPhase, input *AssessmentInput, output *AssessmentOutput) []error {
	e.mu.RLock()
	hooks := make([]hookEntry, len(e.hooks[phase]))
	copy(hooks, e.hooks[phase])
	e.mu.RUnlock()

	var errs []error
	for _, h := range hooks {
		if err := h.hook(ctx, input, output); err != nil {
			logger.WithComponent("ssam").Warn("hook error", "hook_id", h.id, "phase", phase, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

func (e *Engine) buildCustomFactorMap() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]float64)
	for id, cfg := range e.edgeFactors {
		result[id] = cfg.Factor
	}
	return result
}

func (e *Engine) applyFormula(domainScores []DomainScore, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
	e.mu.RLock()
	formula, ok := e.formulas[e.formulaID]
	e.mu.RUnlock()

	if !ok || formula == nil {
		return e.ssamV12Formula(domainScores, e.GetWeights(), threatCoeff, spcScore, edgeFactors)
	}
	return formula(domainScores, e.GetWeights(), threatCoeff, spcScore, edgeFactors)
}

func (e *Engine) ssamV12Formula(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
	wMap := make(map[string]float64)
	for _, w := range weights {
		wMap[w.Domain] = w.Weight
	}

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return 0
	}

	baseScore := sum / totalWeight
	baseScore *= threatCoeff
	baseScore *= spcScore

	for _, f := range edgeFactors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			baseScore *= f.Factor
		}
	}

	return math.Round(baseScore*100) / 100
}

func (e *Engine) simpleWeightedFormula(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
	wMap := make(map[string]float64)
	for _, w := range weights {
		wMap[w.Domain] = w.Weight
	}

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return 0
	}

	return math.Round((sum/totalWeight)*100) / 100
}

func (e *Engine) InitializeDefaults(defaultWeights map[string]float64, defaultFactors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.weights) == 0 && len(defaultWeights) > 0 {
		e.weights = make(map[string]float64)
		for k, v := range defaultWeights {
			e.weights[k] = v
		}
	}

	if len(e.edgeFactors) == 0 && len(defaultFactors) > 0 {
		e.edgeFactors = make(map[string]EdgeFactorConfig)
		for _, f := range defaultFactors {
			e.edgeFactors[f.ID] = f
		}
	}
}
