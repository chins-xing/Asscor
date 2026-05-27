package ssam

import (
	"context"
	"math"
	"sort"
	"sync"

	ssam "github.com/chins-xing/ssam"
	"github.com/asscor/asscor/internal/logger"
)

type Engine struct {
	mu    sync.RWMutex
	cfg   ssam.ScoringConfig
	hooks map[HookPhase][]hookEntry
}

type hookEntry struct {
	id       string
	hook     AssessmentHook
	priority int
}

var _ Provider = (*Engine)(nil)

func NewEngine() *Engine {
	return &Engine{
		cfg:   ssam.DefaultScoringConfig,
		hooks: make(map[HookPhase][]hookEntry),
	}
}

func NewDefaultEngine() *Engine {
	return NewEngine()
}

func (e *Engine) ComputeScore(ctx context.Context, input *ssam.AssessmentInput) (*ssam.AssessmentOutput, error) {
	if input == nil {
		return nil, ErrNilInput
	}

	if err := ValidateInput(*input); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	output := &ssam.AssessmentOutput{
		HostID:      input.HostID,
		Threshold:   input.Threshold,
		ThreatCoeff: input.ThreatCoeff,
		SPCScore:    input.SPCScore,
		Metadata:    make(map[string]string),
	}

	if output.ThreatCoeff == 0 {
		output.ThreatCoeff = 1.0
	}
	if output.SPCScore == 0 {
		output.SPCScore = 1.0
	}
	if output.SPCScore < 0.60 {
		output.SPCScore = 0.60
	}

	e.ExecuteHooks(ctx, HookPreScore, input, output)

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	domainScores := ssam.ComputeDomainScores(cfg.Weights, input.Checks)
	output.DomainScores = domainScores

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostScore, input, output)

	e.ExecuteHooks(ctx, HookPreEdge, input, output)

	customFactors := e.buildCustomFactorMap()
	edgeFactors := ssam.ApplyEdgeFactorsToChecks(cfg.EdgeFactors, input.Checks, customFactors)
	output.EdgeFactors = edgeFactors

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostEdge, input, output)

	formulas := ssam.RegisterBuiltinFormulas()
	formulas["custom_42"] = e.custom42Formula
	for id, f := range e.getCustomFormulas() {
		formulas[id] = f
	}
	formula, ok := formulas[cfg.FormulaID]
	if !ok || formula == nil {
		formula = ssam.SSAMV12Formula
	}

	finalScore := formula(domainScores, cfg.Weights, output.ThreatCoeff, output.SPCScore, edgeFactors)
	output.FinalScore = math.Round(finalScore*100) / 100
	output.FormulaID = cfg.FormulaID
	output.Acceptable = output.FinalScore >= output.Threshold

	return output, nil
}

func (e *Engine) custom42Formula(domainScores []ssam.DomainScore, weights []ssam.WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []ssam.EdgeFactorResult) float64 {
	return 42.0
}

func (e *Engine) ComputeScoreV2(ctx context.Context, input *ssam.AssessmentInputV2) (*ssam.AssessmentOutputV2, error) {
	if input == nil {
		return nil, ErrNilInput
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	output, err := ssam.ComputeScoreV2(cfg, *input)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

func (e *Engine) getCustomFormulas() map[string]ssam.ScoringFormula {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]ssam.ScoringFormula)
	return result
}

func (e *Engine) ComputeDomainScores(checks []ssam.CheckInput) []ssam.DomainScore {
	e.mu.RLock()
	weights := e.cfg.Weights
	e.mu.RUnlock()
	return ssam.ComputeDomainScores(weights, checks)
}

func (e *Engine) ComputeWeightedSum(domainScores []ssam.DomainScore) float64 {
	e.mu.RLock()
	weights := e.cfg.Weights
	e.mu.RUnlock()
	return ssam.ComputeWeightedSum(weights, domainScores)
}

func (e *Engine) ApplyEdgeFactors(baseScore float64, factors []ssam.EdgeFactorResult) float64 {
	return ssam.ApplyEdgeFactors(baseScore, factors)
}

func (e *Engine) ApplyEdgeFactorsToChecks(checks []ssam.CheckInput, customFactors map[string]float64) []ssam.EdgeFactorResult {
	e.mu.RLock()
	edgeFactors := e.cfg.EdgeFactors
	e.mu.RUnlock()
	return ssam.ApplyEdgeFactorsToChecks(edgeFactors, checks, customFactors)
}

func (e *Engine) ListEdgeFactors() []ssam.EdgeFactorResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]ssam.EdgeFactorResult, 0, len(e.cfg.EdgeFactors))
	for _, cfg := range e.cfg.EdgeFactors {
		results = append(results, ssam.EdgeFactorResult{
			ID:     cfg.ID,
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

func (e *Engine) EvaluateEdgeFactors(checks []ssam.CheckInput, customFactors map[string]float64) []ssam.EdgeFactorResult {
	return e.ApplyEdgeFactorsToChecks(checks, customFactors)
}

func (e *Engine) SetWeights(weights []WeightConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Weights = append([]WeightConfig{}, weights...)
}

func (e *Engine) GetWeights() []WeightConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]WeightConfig, len(e.cfg.Weights))
	copy(result, e.cfg.Weights)
	return result
}

func (e *Engine) SetFormula(formulaID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.FormulaID = formulaID
}

func (e *Engine) GetFormula() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.FormulaID
}

func (e *Engine) RegisterFormula(id string, formula ssam.ScoringFormula) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.FormulaID = id
}

func (e *Engine) SetEdgeFactors(factors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.EdgeFactors = append([]EdgeFactorConfig{}, factors...)
}

func (e *Engine) ListDomains() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domains := make([]string, 0, len(e.cfg.Weights))
	for _, w := range e.cfg.Weights {
		domains = append(domains, w.Domain)
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
	for _, w := range e.cfg.Weights {
		if w.Domain == id {
			return w.Weight
		}
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

func (e *Engine) ExecuteHooks(ctx context.Context, phase HookPhase, input *ssam.AssessmentInput, output *ssam.AssessmentOutput) []error {
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
	for _, f := range e.cfg.EdgeFactors {
		result[f.ID] = f.Factor
	}
	return result
}

func (e *Engine) InitializeDefaults(defaultWeights map[string]float64, defaultFactors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.cfg.Weights) == 0 && len(defaultWeights) > 0 {
		e.cfg.Weights = make([]WeightConfig, 0, len(defaultWeights))
		for k, v := range defaultWeights {
			e.cfg.Weights = append(e.cfg.Weights, WeightConfig{Domain: k, Weight: v})
		}
	}

	if len(e.cfg.EdgeFactors) == 0 && len(defaultFactors) > 0 {
		e.cfg.EdgeFactors = append([]EdgeFactorConfig{}, defaultFactors...)
	}
}
