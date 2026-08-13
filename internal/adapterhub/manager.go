//go:build adapter

package adapterhub

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

// Manager manages the lifecycle of all unified adapters.
type Manager struct {
	mu            sync.RWMutex
	adapters      map[string]*adapterEntry
	ruleEngine    *RuleEngine
	globalConfig  map[string]string
	state         ManagerState
	syncInterval  time.Duration
	healthCh      chan healthReport
	bus           BusPublisher
}

// BusPublisher is the interface for publishing events.
type BusPublisher interface {
	Publish(ctx context.Context, topic string, payload interface{}) error
}

// adapterEntry holds an adapter with its runtime state.
type adapterEntry struct {
	Adapter    UnifiedAdapter
	Metadata   AdapterMetadata
	State      AdapterState
	Config     map[string]string
	Health     HealthInfo
	LastRun    time.Time
	LastOutput Output
}

// healthReport contains health check results.
type healthReport struct {
	AdapterID string
	Health    HealthInfo
}

// ManagerState represents the state of the manager.
type ManagerState int

const (
	ManagerStateInitialized ManagerState = iota
	ManagerStateRunning
	ManagerStateStopping
	ManagerStateStopped
)

// NewManager creates a new adapter manager.
func NewManager(ruleEngine *RuleEngine) *Manager {
	return &Manager{
		adapters:     make(map[string]*adapterEntry),
		ruleEngine:   ruleEngine,
		globalConfig: make(map[string]string),
		state:        ManagerStateInitialized,
		syncInterval: 6 * time.Hour,
		healthCh:     make(chan healthReport, 100),
	}
}

// SetBus sets the bus publisher for events.
func (m *Manager) SetBus(bus BusPublisher) {
	m.bus = bus
}

// SetSyncInterval sets the interval for periodic adapter execution.
func (m *Manager) SetSyncInterval(interval time.Duration) {
	m.syncInterval = interval
}

// Register registers an adapter with the manager.
func (m *Manager) Register(adapter UnifiedAdapter) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	meta := adapter.Metadata()
	if meta.ID == "" {
		return fmt.Errorf("adapter ID cannot be empty")
	}
	if _, exists := m.adapters[meta.ID]; exists {
		return fmt.Errorf("adapter %s already registered", meta.ID)
	}

	m.adapters[meta.ID] = &adapterEntry{
		Adapter:  adapter,
		Metadata: meta,
		State:    StateRegistered,
		Health: HealthInfo{
			Status:    HealthUnknown,
			Timestamp: time.Now(),
		},
	}

	logger.WithComponent("adapterhub").Info("adapter registered",
		"adapter_id", meta.ID,
		"category", meta.Category,
		"priority", meta.Priority)

	return nil
}

// Unregister removes an adapter from the manager.
func (m *Manager) Unregister(adapterID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.adapters[adapterID]
	if !ok {
		return fmt.Errorf("adapter %s not found", adapterID)
	}

	if entry.State == StateRunning {
		return fmt.Errorf("cannot unregister adapter %s: still running", adapterID)
	}

	delete(m.adapters, adapterID)
	return nil
}

// Initialize initializes all registered adapters.
func (m *Manager) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != ManagerStateInitialized {
		return fmt.Errorf("manager not in initialized state")
	}

	for id, entry := range m.adapters {
		if entry.State != StateRegistered {
			continue
		}

		execCtx := m.buildContext(entry)
		if err := entry.Adapter.Initialize(execCtx); err != nil {
			logger.WithComponent("adapterhub").Error("adapter init failed",
				"adapter_id", id, "error", err)
			continue
		}

		entry.State = StateInitialized
		logger.WithComponent("adapterhub").Debug("adapter initialized", "adapter_id", id)
	}

	m.state = ManagerStateRunning
	return nil
}

// Start starts the manager's background tasks.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.state != ManagerStateRunning {
		m.mu.Unlock()
		return fmt.Errorf("manager not in running state")
	}
	m.mu.Unlock()

	go m.runHealthCheckLoop(ctx)
	go m.runSyncLoop(ctx)

	return nil
}

// Stop stops all adapters and the manager.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != ManagerStateRunning {
		return fmt.Errorf("manager not in running state")
	}

	m.state = ManagerStateStopping

	for id, entry := range m.adapters {
		if entry.State != StateInitialized && entry.State != StateRunning {
			continue
		}

		execCtx := m.buildContext(entry)
		if err := entry.Adapter.Stop(execCtx); err != nil {
			logger.WithComponent("adapterhub").Warn("adapter stop error",
				"adapter_id", id, "error", err)
		}
		entry.State = StateStopped
	}

	m.state = ManagerStateStopped
	close(m.healthCh)
	return nil
}

// Execute runs a specific adapter with the given input.
func (m *Manager) Execute(ctx context.Context, adapterID string, input Input) (Output, error) {
	m.mu.RLock()
	entry, ok := m.adapters[adapterID]
	m.mu.RUnlock()

	if !ok {
		return Output{}, fmt.Errorf("adapter %s not found", adapterID)
	}

	if entry.State != StateInitialized && entry.State != StateRunning {
		return Output{}, fmt.Errorf("adapter %s not initialized", adapterID)
	}

	execCtx := m.buildContext(entry)
	start := time.Now()

	output, err := entry.Adapter.Execute(execCtx, input)
	output.Duration = time.Since(start)
	output.AdapterID = adapterID
	output.Timestamp = time.Now()

	if err != nil {
		output.Error = err
		logger.WithComponent("adapterhub").Error("adapter execution failed",
			"adapter_id", adapterID, "error", err)
	} else {
		for i := range output.Findings {
			m.ruleEngine.ApplyAll(output.Findings[i])
		}
		output.Findings = m.filterFindings(output.Findings, adapterID)
	}

	entry.LastRun = time.Now()
	entry.LastOutput = output

	return output, nil
}

// ExecuteAll runs all enabled adapters.
func (m *Manager) ExecuteAll(ctx context.Context, input Input) []ExecutionResult {
	var results []ExecutionResult

	adapters := m.getSortedAdapters()
	for _, id := range adapters {
		entry := m.getAdapterEntry(id)
		if entry == nil {
			continue
		}

		if entry.State != StateInitialized && entry.State != StateRunning {
			continue
		}

		if !m.isAdapterEnabled(entry) {
			continue
		}

		output, err := m.Execute(ctx, id, input)
		results = append(results, ExecutionResult{
			AdapterID: id,
			Output:    output,
			Error:     err,
		})
	}

	return results
}

// GetAdapter returns an adapter's metadata and state.
func (m *Manager) GetAdapter(adapterID string) (AdapterMetadata, AdapterState, HealthInfo) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.adapters[adapterID]
	if !ok {
		return AdapterMetadata{}, StateStopped, HealthInfo{Status: HealthUnknown}
	}

	return entry.Metadata, entry.State, entry.Health
}

// ListAdapters returns all registered adapters sorted by priority.
func (m *Manager) ListAdapters() []AdapterInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var adapters []AdapterInfo
	for _, entry := range m.adapters {
		adapters = append(adapters, AdapterInfo{
			Metadata:  entry.Metadata,
			State:     entry.State,
			Health:    entry.Health,
			LastRun:   entry.LastRun,
			Enabled:   m.isAdapterEnabled(entry),
		})
	}

	sort.Slice(adapters, func(i, j int) bool {
		if adapters[i].Metadata.Category != adapters[j].Metadata.Category {
			return adapters[i].Metadata.Category < adapters[j].Metadata.Category
		}
		return adapters[i].Metadata.Priority < adapters[j].Metadata.Priority
	})

	return adapters
}

// AdapterInfo contains information about a registered adapter.
type AdapterInfo struct {
	Metadata AdapterMetadata
	State    AdapterState
	Health   HealthInfo
	LastRun  time.Time
	Enabled  bool
}

// ExecutionResult contains the result of an adapter execution.
type ExecutionResult struct {
	AdapterID string
	Output    Output
	Error     error
}

// SetAdapterConfig sets the configuration for a specific adapter.
func (m *Manager) SetAdapterConfig(adapterID string, config map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.adapters[adapterID]
	if !ok {
		return fmt.Errorf("adapter %s not found", adapterID)
	}

	entry.Config = config
	return nil
}

// SetGlobalConfig sets the global configuration for all adapters.
func (m *Manager) SetGlobalConfig(config map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalConfig = config
}

func (m *Manager) getAdapterEntry(adapterID string) *adapterEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.adapters[adapterID]
}

func (m *Manager) getSortedAdapters() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ids []string
	for id := range m.adapters {
		ids = append(ids, id)
	}

	sort.Slice(ids, func(i, j int) bool {
		a, b := m.adapters[ids[i]], m.adapters[ids[j]]
		if a.Metadata.Category != b.Metadata.Category {
			return a.Metadata.Category < b.Metadata.Category
		}
		return a.Metadata.Priority < b.Metadata.Priority
	})

	return ids
}

func (m *Manager) isAdapterEnabled(entry *adapterEntry) bool {
	cfg := m.globalConfig
	if entry.Config != nil {
		for k, v := range entry.Config {
			cfg[k] = v
		}
	}

	enabledKey := fmt.Sprintf("adapter_%s_enabled", entry.Metadata.ID)
	if enabled, ok := cfg[enabledKey]; ok {
		return enabled == "true" || enabled == "on" || enabled == "1"
	}

	enabledKey = fmt.Sprintf("%s_enabled", entry.Metadata.ID)
	if enabled, ok := cfg[enabledKey]; ok {
		return enabled == "true" || enabled == "on" || enabled == "1"
	}

	return false
}

func (m *Manager) buildContext(entry *adapterEntry) AdapterContext {
	cfg := make(map[string]string)
	for k, v := range m.globalConfig {
		cfg[k] = v
	}
	for k, v := range entry.Config {
		cfg[k] = v
	}

	return AdapterContext{
		Rules:    m.ruleEngine.globalRules,
		Config:   cfg,
		Metadata: map[string]interface{}{"adapter_id": entry.Metadata.ID},
	}
}

func (m *Manager) filterFindings(findings []*NormalizedFinding, tool string) []*NormalizedFinding {
	if m.ruleEngine == nil {
		return findings
	}
	return m.ruleEngine.ApplyFilter(findings, tool)
}

func (m *Manager) runHealthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.performHealthCheck(ctx)
		}
	}
}

func (m *Manager) performHealthCheck(ctx context.Context) {
	m.mu.RLock()
	adapters := make(map[string]*adapterEntry)
	for id, entry := range m.adapters {
		if entry.State == StateRunning || entry.State == StateInitialized {
			adapters[id] = entry
		}
	}
	m.mu.RUnlock()

	for id, entry := range adapters {
		execCtx := m.buildContext(entry)
		health := entry.Adapter.HealthCheck(execCtx)

		m.mu.Lock()
		if m.adapters[id] != nil {
			m.adapters[id].Health = health
		}
		m.mu.Unlock()

		select {
		case m.healthCh <- healthReport{AdapterID: id, Health: health}:
		default:
		}

		if health.Status == HealthUnhealthy {
			logger.WithComponent("adapterhub").Warn("adapter unhealthy",
				"adapter_id", id, "message", health.Message)
		}
	}
}

func (m *Manager) runSyncLoop(ctx context.Context) {
	m.runSync(ctx)

	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runSync(ctx)
		}
	}
}

func (m *Manager) runSync(ctx context.Context) {
	m.mu.RLock()
	var enabledAdapters []*adapterEntry
	for _, entry := range m.adapters {
		if (entry.State == StateRunning || entry.State == StateInitialized) && m.isAdapterEnabled(entry) {
			enabledAdapters = append(enabledAdapters, entry)
		}
	}
	m.mu.RUnlock()

	for _, entry := range enabledAdapters {
		input := Input{
			Source:    entry.Metadata.ID,
			Timestamp: time.Now(),
		}

		output, err := m.Execute(ctx, entry.Metadata.ID, input)
		if err != nil {
			logger.WithComponent("adapterhub").Warn("sync execution failed",
				"adapter_id", entry.Metadata.ID, "error", err)
			continue
		}

		if m.bus != nil && len(output.Findings) > 0 {
			m.bus.Publish(ctx, "adapterhub.findings", map[string]interface{}{
				"adapter_id": entry.Metadata.ID,
				"findings":   output.Findings,
				"timestamp":   time.Now(),
			})
		}
	}
}
