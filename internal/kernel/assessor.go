package kernel

import (
	"context"
	"log"
	"sync"

	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/engine"
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
		log.Printf("assessor: %s", w)
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
	log.Println("assessor: started")
	return nil
}

func (m *AssessorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("assessor")
	m.state = PluginStopped
	log.Println("assessor: stopped")
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
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)

	result := m.engine.AssessFromResults(hostID, hostname, checkResults)

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