package kernel

import (
	"context"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

type AdapterIntegrationModule struct {
	kernel KernelContext

	mu           sync.RWMutex
	adapterCfg   map[string]string
	syncInterval time.Duration
	state        PluginState
}

func NewAdapterIntegrationModule() *AdapterIntegrationModule {
	return &AdapterIntegrationModule{
		adapterCfg:   make(map[string]string),
		syncInterval: 6 * time.Hour,
	}
}

func (m *AdapterIntegrationModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "adapter_integration",
		Version:     "1.0.0",
		Description: "Adapter integration — runs external tool adapters and feeds findings into the assessment pipeline",
		Author:      "ASSCOR Core Team",
	}
}

func (m *AdapterIntegrationModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "assessor", Interface: (*AssessorInterface)(nil)},
	}
}

func (m *AdapterIntegrationModule) Priority() int {
	return 45
}

func (m *AdapterIntegrationModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

	if cfg := kc.GetConfigObj(); cfg != nil {
		m.adapterCfg = cfg.AdapterConfig
	}

	kc.Container().Bind((*AdapterIntegrationInterface)(nil), m)

	return nil
}

func (m *AdapterIntegrationModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	go m.syncLoop()
	logger.WithComponent("adapter_integration").Info("started")
	return nil
}

func (m *AdapterIntegrationModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.state = PluginStopped
	logger.WithComponent("adapter_integration").Info("stopped")
	return nil
}

func (m *AdapterIntegrationModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *AdapterIntegrationModule) syncLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("adapter_integration").Error("syncLoop panic recovered", "panic", r)
		}
	}()

	m.RunAdapters(context.Background())

	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-ticker.C:
			m.RunAdapters(context.Background())
		}
	}
}

func (m *AdapterIntegrationModule) RunAdapters(ctx context.Context) []adapter.PipelineResult {
	allAdapters := adapter.List()
	if len(allAdapters) == 0 {
		return nil
	}

	cfg := m.getAdapterConfig()
	pipeline := adapter.NewPipeline(cfg).WithAdapters(allAdapters...)
	results := pipeline.RunAll(ctx)

	var totalFindings int
	for _, r := range results {
		totalFindings += len(r.Findings)
	}

	if totalFindings > 0 {
		m.publishAdapterFindings(results)
	}

	logger.WithComponent("adapter_integration").Info("adapter sync completed",
		"adapters", len(results), "findings", totalFindings)
	return results
}

func (m *AdapterIntegrationModule) publishAdapterFindings(results []adapter.PipelineResult) {
	for _, r := range results {
		if r.Error != nil || len(r.Findings) == 0 {
			continue
		}

		var checkResults []model.CheckResult
		for _, f := range r.Findings {
			cr := f.ToCheckResult()
			if cr.Domain == "" {
				continue
			}
			checkResults = append(checkResults, cr)
		}

		if len(checkResults) == 0 {
			continue
		}

		m.kernel.Bus().Publish(context.Background(), Message{
			Topic:     "adapter.findings",
			Payload: map[string]interface{}{
				"adapter_id": r.AdapterID,
				"adapter":    r.AdapterName,
				"findings":   checkResults,
				"timestamp":  time.Now(),
			},
			Source:    "adapter_integration",
			Timestamp: time.Now(),
		})
	}
}

func (m *AdapterIntegrationModule) CollectFindings() []model.CheckResult {
	cfg := m.getAdapterConfig()
	allAdapters := adapter.List()
	var allFindings []model.CheckResult

	for _, a := range allAdapters {
		if !a.IsEnabled(cfg) {
			continue
		}

		findings, err := adapter.ExecuteAdapter(context.Background(), a, cfg)
		if err != nil {
			logger.WithComponent("adapter_integration").Warn("adapter execution failed",
				"adapter_id", a.ID(), "error", err)
			continue
		}

		for _, f := range findings {
			cr := f.ToCheckResult()
			if cr.Domain != "" {
				allFindings = append(allFindings, cr)
			}
		}
	}

	return allFindings
}

func (m *AdapterIntegrationModule) getAdapterConfig() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg := make(map[string]string, len(m.adapterCfg))
	for k, v := range m.adapterCfg {
		cfg[k] = v
	}
	return cfg
}

type AdapterIntegrationInterface interface {
	RunAdapters(ctx context.Context) []adapter.PipelineResult
	CollectFindings() []model.CheckResult
}
