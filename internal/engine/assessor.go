package engine

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/adapter"
	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/model"
)

type Assessor struct {
	cfg           *config.Config
	scoringEngine *DynamicScoringEngine
	maxWorkers    int
	resultsCache  sync.Map
	mu            sync.RWMutex
}

func NewAssessor(cfg *config.Config) *Assessor {
	engine := NewDynamicScoringEngine()

	if cfg != nil {
		w := cfg.Weights
		engine.SetWeight(model.DomainAttackSurface, w.AttackSurface)
		engine.SetWeight(model.DomainBusinessContinuity, w.BusinessContinuity)
		engine.SetWeight(model.DomainOperationTrust, w.OperationTrust)
		engine.SetWeight(model.DomainResilience, w.Resilience)

		for domain, val := range cfg.ExtensionWeights {
			engine.SetWeight(domain, val)
		}
	}

	engine.InitializeDefaults()

	return &Assessor{
		cfg:           cfg,
		scoringEngine: engine,
		maxWorkers:    10,
	}
}

func (a *Assessor) ScoringEngine() *DynamicScoringEngine {
	return a.scoringEngine
}

func (a *Assessor) Assess() *model.AssessmentResult {
	ctx := context.Background()
	hostname, _ := os.Hostname()
	result := &model.AssessmentResult{
		HostID:    hostname,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: a.cfg.Threshold,
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreCheck, result)

	adapterResults := a.runAdapterPipeline()
	for _, r := range adapterResults {
		for _, f := range r.Findings {
			result.Checks = append(result.Checks, f.ToCheckResult())
		}
		if r.Error != nil {
			log.Printf("[assessor] adapter %s failed: %v", r.AdapterID, r.Error)
			result.Checks = append(result.Checks, model.CheckResult{
				CheckID: "ADAPTER-" + r.AdapterID,
				Domain:  "attack_surface",
				Name:    "External Adapter: " + r.AdapterName,
				Passed:  false,
				Delta:   -5,
				Detail:  fmt.Sprintf("Adapter %s execution failed: %v", r.AdapterName, r.Error),
			})
		}
	}

	delegatedIDs := a.buildDelegatedSet(adapterResults)

	items := checks.GetAll()
	if len(items) == 0 && len(result.Checks) == 0 {
		return a.buildEmptyResult(result)
	}

	var remainingItems []model.CheckItem
	for _, item := range items {
		if delegatedIDs[item.ID] {
			continue
		}
		if !ShouldActivateCheck(&item, result) {
			continue
		}
		remainingItems = append(remainingItems, item)
	}

	SortChecksByPriority(remainingItems)

	a.runChecksConcurrently(remainingItems, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostCheck, result)

	dynScores := a.computeDynamicDomainScores(result)
	for domain, score := range dynScores.GetAll() {
		result.DomainScores.Set(domain, score)
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreEdge, result)

	a.evaluateEdgeFactorChain(result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostEdge, result)

	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = a.cfg.ThreatCoeff
	}
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}

	result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
	result.Acceptable = result.FinalScore >= result.Threshold

	a.scoringEngine.Hooks().Execute(ctx, PhasePreReport, result)

	return result
}

func (a *Assessor) buildEmptyResult(result *model.AssessmentResult) *model.AssessmentResult {
	result.Acceptable = true
	result.FinalScore = 100
	result.DomainScores = model.DomainScores{
		AttackSurface:      100,
		BusinessContinuity: 100,
		OperationTrust:     100,
		Resilience:         100,
	}
	result.ThreatCoeff = a.cfg.ThreatCoeff
	result.SPCScore = 1.0
	return result
}

func (a *Assessor) AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult {
	ctx := context.Background()
	result := &model.AssessmentResult{
		HostID:    hostID,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: a.cfg.Threshold,
		Checks:    checkResults,
	}

	if len(checkResults) == 0 {
		return a.buildEmptyResult(result)
	}

	dynScores := a.computeDynamicDomainScores(result)
	for domain, score := range dynScores.GetAll() {
		result.DomainScores.Set(domain, score)
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreEdge, result)

	a.evaluateEdgeFactorChain(result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostEdge, result)

	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = a.cfg.ThreatCoeff
	}
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}

	result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
	result.Acceptable = result.FinalScore >= result.Threshold

	return result
}

func (a *Assessor) runChecksConcurrently(items []model.CheckItem, result *model.AssessmentResult) {
	sem := make(chan struct{}, a.maxWorkers)
	var wg sync.WaitGroup
	resultsCh := make(chan model.CheckResult, len(items))

	for _, item := range items {
		wg.Add(1)
		go func(it model.CheckItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resultsCh <- it.Run()
		}(item)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		result.Checks = append(result.Checks, r)
	}
}

func (a *Assessor) runAdapterPipeline() []adapter.PipelineResult {
	if len(a.cfg.AdapterConfig) == 0 {
		return nil
	}

	enabledCount := 0
	for _, v := range a.cfg.AdapterConfig {
		if v == "on" || v == "true" || v == "1" {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		return nil
	}

	allAdapters := adapter.List()
	if len(allAdapters) == 0 {
		return nil
	}

	pipeline := adapter.NewPipeline(a.cfg.AdapterConfig)
	pipeline.WithAdapters(allAdapters...)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	return pipeline.RunAll(ctx)
}

func (a *Assessor) buildDelegatedSet(results []adapter.PipelineResult) map[string]bool {
	delegated := make(map[string]bool)
	for _, r := range results {
		if r.Error != nil {
			continue
		}
		for _, f := range r.Findings {
			if f.DelegatedTo != "" {
				delegationRules := adapter.GetDelegationRules(r.AdapterID)
				for _, rule := range delegationRules {
					delegated[rule.CheckID] = true
				}
			}
		}
	}
	return delegated
}

func (a *Assessor) computeDynamicDomainScores(result *model.AssessmentResult) *model.DynamicDomainScores {
	scores := model.NewDynamicDomainScores()

	activeDomains := make(map[string]bool)
	for _, c := range result.Checks {
		activeDomains[c.Domain] = true
	}
	if len(activeDomains) == 0 {
		for _, id := range model.ListDomainIDs() {
			activeDomains[id] = true
		}
	}

	for domain := range activeDomains {
		scores.Set(domain, 100)
	}

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		delta := a.cfg.CheckDeltas[check.CheckID]
		if delta == 0 {
			delta = check.Delta
		}
		current := scores.Get(check.Domain)
		scores.Set(check.Domain, math.Max(0, current+delta))
	}

	return scores
}

func (a *Assessor) evaluateEdgeFactorChain(result *model.AssessmentResult) {
	model.ResetAllEdgeFactors()

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		switch check.CheckID {
		case "EF-001":
			model.SetEdgeFactorValue("EF-002FA", a.cfg.EdgeFactors.TwoFactorFailure)
		case "EF-002":
			model.SetEdgeFactorValue("EF-002FA", 0.82)
		}
	}

	factors := model.ActiveEdgeFactors()
	mapped := model.EdgeFactors{TwoFactorFailure: 1.0}
	if len(factors) > 0 {
		for _, f := range model.ListEdgeFactors() {
			if f.ID == "EF-002FA" && f.Active {
				mapped.TwoFactorFailure = f.Factor
			}
		}
	}
	result.EdgeFactors = mapped
}

func (a *Assessor) checkPassed(id string, result *model.AssessmentResult) (bool, string) {
	for _, c := range result.Checks {
		if c.CheckID == id {
			return c.Passed, c.Detail
		}
	}
	return true, ""
}

func (a *Assessor) computeDynamicFinalScore(scores *model.DynamicDomainScores, result *model.AssessmentResult) float64 {
	baseScore := a.scoringEngine.ComputeWeightedSum(scores)

	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = a.cfg.ThreatCoeff
	}
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}

	baseScore *= result.ThreatCoeff
	baseScore *= result.SPCScore

	var chain model.EdgeFactorChain
	baseScore = chain.Apply(baseScore)

	return math.Round(baseScore*100) / 100
}

func (a *Assessor) PrintReport(result *model.AssessmentResult) string {
	bar := func(score float64, width int) string {
		filled := int(score / 100 * float64(width))
		if filled > width {
			filled = width
		}
		b := make([]byte, width)
		for i := 0; i < width; i++ {
			if i < filled {
				b[i] = '='
			} else {
				b[i] = ' '
			}
		}
		return string(b)
	}

	report := fmt.Sprintf("[ Core Domain Scores ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	for _, m := range model.ListDomainsByCategory(model.CategoryCore) {
		label := m.Label
		if label == "" {
			label = model.GetDomainLabel(m.ID)
		}
		score := result.DomainScores.Get(m.ID)
		report += fmt.Sprintf("  %-20s : [%-20s] %.0f/100\n", label, bar(score, 20), score)
	}

	checksByDomain := make(map[string][]model.CheckResult)
	for _, c := range result.Checks {
		checksByDomain[c.Domain] = append(checksByDomain[c.Domain], c)
	}

	coreIDs := make(map[string]bool)
	for _, m := range model.ListDomainsByCategory(model.CategoryCore) {
		coreIDs[m.ID] = true
	}

	report += fmt.Sprintf("\n[ Extension Domain Scores ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	extFound := false
	for domain, checks := range checksByDomain {
		if coreIDs[domain] {
			continue
		}
		extFound = true
		passed := 0
		for _, c := range checks {
			if c.Passed {
				passed++
			}
		}
		label := model.GetDomainLabel(domain)
		score := result.DomainScores.Get(domain)
		report += fmt.Sprintf("  %-20s : [%-20s] %.0f/100  (%d of %d checks passed)\n",
			label, bar(score, 20), score, passed, len(checks))
	}
	if !extFound {
		report += fmt.Sprintf("  (none)\n")
	}

	report += fmt.Sprintf("\n[ Edge Factor Report ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	for _, ef := range model.ListEdgeFactors() {
		if ef.Active {
			report += fmt.Sprintf("  %-12s : %-30s factor=%.2f (ACTIVE)\n", ef.ID, ef.Name, ef.Factor)
		}
	}

	for domain, checks := range checksByDomain {
		label := model.GetDomainLabel(domain)
		report += fmt.Sprintf("\n[ %s Details ]\n", label)
		report += fmt.Sprintf("---------------------------------------------------------------\n")
		for _, c := range checks {
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			detail := c.Detail
			if detail != "" {
				report += fmt.Sprintf("  [%s] %s : %s (%s)\n", status, c.CheckID, c.Name, detail)
			} else {
				report += fmt.Sprintf("  [%s] %s : %s\n", status, c.CheckID, c.Name)
			}
		}
	}

	report += fmt.Sprintf("\n---------------------------------------------------------------\n")
	var status string
	if result.Acceptable {
		status = "ACCEPTABLE"
	} else {
		status = "NOT ACCEPTABLE"
	}
	report += fmt.Sprintf("  Final Score: %.2f/100    Threshold: %.2f    Status: %s\n",
		result.FinalScore, result.Threshold, status)
	report += fmt.Sprintf("  Threat Coeff: %.2f    SPC Score: %.2f\n",
		result.ThreatCoeff, result.SPCScore)
	report += fmt.Sprintf("---------------------------------------------------------------\n")

	return report
}

func (a *Assessor) ValidateEdgeFactors(registeredChecks []model.CheckItem) []string {
	var warnings []string

	overlapLabels := map[string]string{
		"RS-005": "SYN Cookie edge factor overlap (SSAM 1.3 removed overlap, resilience domain only)",
		"OT-004": "Supply chain edge factor overlap (SSAM 1.3 removed overlap, operation trust domain only)",
		"RS-003": "Auto-block edge factor overlap (SSAM 1.3 removed overlap, resilience domain only)",
		"BC-003": "Resource tension edge factor overlap (SSAM 1.3 removed overlap, business continuity domain only)",
	}

	for _, check := range registeredChecks {
		if label, exists := overlapLabels[check.ID]; exists {
			warnings = append(warnings, fmt.Sprintf("Edge factor conflict: %s", label))
		}
	}

	return warnings
}

func (a *Assessor) ReloadWeights(cfg *config.Config) {
	if cfg == nil {
		return
	}
	w := cfg.Weights
	a.scoringEngine.SetWeight(model.DomainAttackSurface, w.AttackSurface)
	a.scoringEngine.SetWeight(model.DomainBusinessContinuity, w.BusinessContinuity)
	a.scoringEngine.SetWeight(model.DomainOperationTrust, w.OperationTrust)
	a.scoringEngine.SetWeight(model.DomainResilience, w.Resilience)

	for domain, val := range cfg.ExtensionWeights {
		a.scoringEngine.SetWeight(domain, val)
	}
	log.Println("[assessor] weights reloaded from config")
}

func (a *Assessor) RegisterHook(id string, phase AssessmentPhase, hook AssessmentHook, priority int) {
	a.scoringEngine.Hooks().Register(id, phase, hook, priority)
}

func (a *Assessor) UnregisterHook(id string) {
	a.scoringEngine.Hooks().Unregister(id)
}
