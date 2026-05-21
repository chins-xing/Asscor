package kernel

import (
	"context"
	"math"
	"sync"

	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/engine"
	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
)

type AssessorModule struct {
	kernel *Kernel
	cfg    *config.Config
	engine *engine.Assessor

	mu      sync.RWMutex
	results map[string]*model.AssessmentResult

	state PluginState
}

func (m *AssessorModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "assessor",
		Version:     "1.2.0",
		Description: "ARGUS assessment engine — computes domain scores and final acceptability score",
		Author:      "ARGUS Core Team",
	}
}

func (m *AssessorModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "config", Interface: (*config.Config)(nil)},
	}
}

func (m *AssessorModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.state = PluginInitialized
	m.results = make(map[string]*model.AssessmentResult)

	if impl, ok := k.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	m.engine = engine.NewAssessor(m.cfg)

	warnings := m.engine.ValidateEdgeFactors(checks.GetAll())
	for _, w := range warnings {
		logger.With("component", "assessor").Warn("edge factor warning", "warning", w)
	}

	k.Container().Bind((*AssessorInterface)(nil), m)

	k.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "assessor.pre_evaluate",
		Description: "Called before each host assessment",
		Version:     "1.0",
	})
	k.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "assessor.post_evaluate",
		Description: "Called after each host assessment completes",
		Version:     "1.0",
	})

	return nil
}

func (m *AssessorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	logger.With("component", "assessor").Info("started")
	return nil
}

func (m *AssessorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("assessor")
	m.state = PluginStopped
	logger.With("component", "assessor").Info("stopped")
	return nil
}

func (m *AssessorModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *AssessorModule) Evaluate(hostID string) *model.AssessmentResult {
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)

	result := m.engine.Assess()
	result.HostID = hostID

	m.applySPCAndCTI(hostID, result)

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", result)

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "assessor.result",
		Payload: result,
		Source:  "assessor",
	})

	return result
}

func (m *AssessorModule) EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult {
	logger.With("component", "assessor").Info("EvaluateFromResults called", "host_id", hostID, "checks", len(checkResults))

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)

	result := m.engine.AssessFromResults(hostID, hostname, checkResults)

	m.applySPCAndCTI(hostID, result)

	result.FinalScore = m.recomputeFinalScore(result)

	logger.With("component", "assessor").Info("assessment score computed", "host_id", hostID, "score", result.FinalScore, "spc_score", result.SPCScore, "threat_coeff", result.ThreatCoeff)

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", result)

	subCount := m.kernel.Bus().SubscriberCount("assessor.result")
	logger.With("component", "assessor").Debug("publishing assessor.result", "subscribers", subCount)

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "assessor.result",
		Payload: result,
		Source:  "assessor",
	})

	return result
}

func (m *AssessorModule) applySPCAndCTI(hostID string, result *model.AssessmentResult) {
	if impl, ok := m.kernel.Container().Resolve((*SPCInterface)(nil)); ok {
		if spc, ok2 := impl.(SPCInterface); ok2 && spc.Enabled() {
			m.syncACIToAsset(spc, hostID, result)

			var packages []string
			if asset := spc.GetAsset(hostID); asset != nil {
				packages = asset.Packages
			}
			correction := spc.Calculate(hostID, packages)
			result.SPCScore = correction.Score

			if len(correction.Weights) > 0 {
				if result.DomainWeightShift == nil {
					result.DomainWeightShift = make(map[string]float64)
				}
				for k, v := range correction.Weights {
					result.DomainWeightShift[k] = v
				}
			}

			logger.With("component", "assessor").Info("SPC correction applied",
				"host_id", hostID,
				"p_score", correction.Score,
				"action", correction.Action,
				"affected_cve", len(correction.AffectedCVE))
		}
	}

	if impl, ok := m.kernel.Container().Resolve((*CTIInterface)(nil)); ok {
		if cti, ok2 := impl.(CTIInterface); ok2 {
			result.ThreatCoeff = cti.GetCoefficient()
		}
	}
}

func (m *AssessorModule) syncACIToAsset(spc SPCInterface, hostID string, result *model.AssessmentResult) {
	asset := spc.GetAsset(hostID)
	if asset == nil {
		asset = &LocalAsset{HostID: hostID}
	}

	aciChecks := map[string]*bool{
		"AC-001": nil,
		"AC-002": nil,
		"AC-003": nil,
		"AC-004": nil,
		"AC-005": nil,
		"AC-006": nil,
		"AC-007": nil,
		"AC-008": nil,
	}

	for i := range result.Checks {
		c := &result.Checks[i]
		if _, exists := aciChecks[c.CheckID]; exists {
			passed := c.Passed
			aciChecks[c.CheckID] = &passed
		}
	}

	changed := false

	if p := aciChecks["AC-001"]; p != nil && *p {
		if asset.NetworkZone != "internal" && asset.NetworkZone != "lan" {
			asset.NetworkZone = "internal"
			changed = true
		}
	}

	if p := aciChecks["AC-004"]; p != nil && *p {
		if !asset.Compensations.IPSRules {
			asset.Compensations.IPSRules = true
			changed = true
		}
	}

	if p := aciChecks["AC-005"]; p != nil && *p {
		if !asset.Compensations.AppWhitelist {
			asset.Compensations.AppWhitelist = true
			changed = true
		}
	}

	if changed {
		spc.UpsertAsset(*asset)
	}
}

func (m *AssessorModule) recomputeFinalScore(result *model.AssessmentResult) float64 {
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}
	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = 1.0
	}

	dynScores := model.NewDynamicDomainScores()
	dynScores.Set(model.DomainAttackSurface, result.DomainScores.AttackSurface)
	dynScores.Set(model.DomainBusinessContinuity, result.DomainScores.BusinessContinuity)
	dynScores.Set(model.DomainOperationTrust, result.DomainScores.OperationTrust)
	dynScores.Set(model.DomainResilience, result.DomainScores.Resilience)
	dynScores.Set(model.DomainKernelSecurity, result.DomainScores.KernelSecurity)

	baseScore := m.engine.ScoringEngine().ComputeWeightedSum(dynScores)

	baseScore *= result.ThreatCoeff
	baseScore *= result.SPCScore

	activeFactors := result.EdgeFactors.ActiveFactors()
	for _, f := range activeFactors {
		baseScore *= f
	}

	return math.Round(baseScore*100) / 100
}

func (m *AssessorModule) GetResult(hostID string) *model.AssessmentResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.results[hostID]
}

type AssessorInterface interface {
	Evaluate(hostID string) *model.AssessmentResult
	EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
	GetResult(hostID string) *model.AssessmentResult
}