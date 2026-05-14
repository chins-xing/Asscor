package engine

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/argus-security/argus/internal/model"
)

type AssessmentPhase string

const (
	PhasePreCheck     AssessmentPhase = "pre_check"
	PhasePostCheck    AssessmentPhase = "post_check"
	PhasePreScore     AssessmentPhase = "pre_score"
	PhasePostScore    AssessmentPhase = "post_score"
	PhasePreEdge      AssessmentPhase = "pre_edge"
	PhasePostEdge     AssessmentPhase = "post_edge"
	PhasePreReport    AssessmentPhase = "pre_report"
	PhasePostReport   AssessmentPhase = "post_report"
)

type AssessmentHook func(ctx context.Context, result *model.AssessmentResult) error

type hookRegistration struct {
	id       string
	phase    AssessmentPhase
	hook     AssessmentHook
	priority int
}

type HookRegistry struct {
	mu    sync.RWMutex
	hooks map[AssessmentPhase][]hookRegistration
}

func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		hooks: make(map[AssessmentPhase][]hookRegistration),
	}
}

func (h *HookRegistry) Register(id string, phase AssessmentPhase, hook AssessmentHook, priority int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hooks[phase] = append(h.hooks[phase], hookRegistration{
		id:       id,
		phase:    phase,
		hook:     hook,
		priority: priority,
	})
	sort.Slice(h.hooks[phase], func(i, j int) bool {
		return h.hooks[phase][i].priority < h.hooks[phase][j].priority
	})
}

func (h *HookRegistry) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for phase, hooks := range h.hooks {
		filtered := hooks[:0]
		for _, hk := range hooks {
			if hk.id != id {
				filtered = append(filtered, hk)
			}
		}
		if len(filtered) == 0 {
			delete(h.hooks, phase)
		} else {
			h.hooks[phase] = filtered
		}
	}
}

func (h *HookRegistry) Execute(ctx context.Context, phase AssessmentPhase, result *model.AssessmentResult) []error {
	h.mu.RLock()
	hooks := make([]hookRegistration, len(h.hooks[phase]))
	copy(hooks, h.hooks[phase])
	h.mu.RUnlock()

	var errs []error
	for _, hk := range hooks {
		if err := hk.hook(ctx, result); err != nil {
			log.Printf("[engine:hook] %s@%s: %v", hk.id, phase, err)
			errs = append(errs, fmt.Errorf("%s: %w", hk.id, err))
		}
	}
	return errs
}

type DynamicScoringEngine struct {
	mu      sync.RWMutex
	weights *model.DynamicWeights
	hooks   *HookRegistry
}

func NewDynamicScoringEngine() *DynamicScoringEngine {
	return &DynamicScoringEngine{
		weights: model.NewDynamicWeights(),
		hooks:   NewHookRegistry(),
	}
}

func (e *DynamicScoringEngine) SetWeight(domain string, weight float64) {
	e.weights.Set(domain, weight)
}

func (e *DynamicScoringEngine) GetWeight(domain string) float64 {
	return e.weights.Get(domain)
}

func (e *DynamicScoringEngine) GetWeights() *model.DynamicWeights {
	return e.weights
}

func (e *DynamicScoringEngine) Hooks() *HookRegistry {
	return e.hooks
}

func (e *DynamicScoringEngine) ComputeWeightedSum(scores *model.DynamicDomainScores) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	allWeights := e.weights.GetAll()
	if len(allWeights) == 0 {
		metas := model.ListDomains()
		for _, m := range metas {
			if _, exists := allWeights[m.ID]; !exists {
				allWeights[m.ID] = m.DefaultWeight
			}
		}
	}

	sum := 0.0
	totalWeight := 0.0
	for domain, weight := range allWeights {
		if !scores.Has(domain) {
			continue
		}
		score := scores.Get(domain)
		sum += score * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0
	}
	return sum / totalWeight
}

func (e *DynamicScoringEngine) InitializeDefaults() {
	e.mu.Lock()
	defer e.mu.Unlock()
	metas := model.ListDomains()
	for _, m := range metas {
		if e.weights.Get(m.ID) == 0 {
			e.weights.Set(m.ID, m.DefaultWeight)
		}
	}
	e.weights.Normalize(100)
}

type ScoreFormula struct {
	ID          string
	Name        string
	Description string
	Compute     func(scores *model.DynamicDomainScores, weights *model.DynamicWeights) float64
}

var formulaRegistry = struct {
	mu       sync.RWMutex
	formulas map[string]ScoreFormula
}{formulas: make(map[string]ScoreFormula)}

func RegisterScoreFormula(formula ScoreFormula) {
	formulaRegistry.mu.Lock()
	defer formulaRegistry.mu.Unlock()
	formulaRegistry.formulas[formula.ID] = formula
}

func GetScoreFormula(id string) (ScoreFormula, bool) {
	formulaRegistry.mu.RLock()
	defer formulaRegistry.mu.RUnlock()
	f, ok := formulaRegistry.formulas[id]
	return f, ok
}

func ListScoreFormulas() []ScoreFormula {
	formulaRegistry.mu.RLock()
	defer formulaRegistry.mu.RUnlock()
	result := make([]ScoreFormula, 0, len(formulaRegistry.formulas))
	for _, f := range formulaRegistry.formulas {
		result = append(result, f)
	}
	return result
}

type CheckActivator func(item *model.CheckItem, result *model.AssessmentResult) bool

type CheckRegistryExtension struct {
	mu         sync.RWMutex
	activators map[string]CheckActivator
	priorities map[string]int
	filters    []func(item *model.CheckItem) bool
}

var checkExtRegistry = &CheckRegistryExtension{
	activators: make(map[string]CheckActivator),
	priorities: make(map[string]int),
}

func RegisterCheckActivator(checkID string, activator CheckActivator) {
	checkExtRegistry.mu.Lock()
	defer checkExtRegistry.mu.Unlock()
	checkExtRegistry.activators[checkID] = activator
}

func SetCheckPriority(checkID string, priority int) {
	checkExtRegistry.mu.Lock()
	defer checkExtRegistry.mu.Unlock()
	checkExtRegistry.priorities[checkID] = priority
}

func GetCheckPriority(checkID string) int {
	checkExtRegistry.mu.RLock()
	defer checkExtRegistry.mu.RUnlock()
	if p, ok := checkExtRegistry.priorities[checkID]; ok {
		return p
	}
	return 50
}

func ShouldActivateCheck(item *model.CheckItem, result *model.AssessmentResult) bool {
	checkExtRegistry.mu.RLock()
	defer checkExtRegistry.mu.RUnlock()
	if activator, ok := checkExtRegistry.activators[item.ID]; ok {
		return activator(item, result)
	}
	return true
}

func SortChecksByPriority(items []model.CheckItem) {
	sort.SliceStable(items, func(i, j int) bool {
		pi := GetCheckPriority(items[i].ID)
		pj := GetCheckPriority(items[j].ID)
		return pi < pj
	})
}
