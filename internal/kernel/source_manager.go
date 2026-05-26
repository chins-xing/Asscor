package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
)

type SourceState string

const (
	SourceStateNotInstalled SourceState = "not_installed"
	SourceStateInstalled    SourceState = "installed"
	SourceStateEnabled      SourceState = "enabled"
	SourceStateRunning      SourceState = "running"
	SourceStateError        SourceState = "error"
	SourceStateDisabled     SourceState = "disabled"
	SourceStateUninstalling SourceState = "uninstalling"
)

type SourceCategory string

const (
	SourceCategoryScanner    SourceCategory = "scanner"
	SourceCategoryManagement SourceCategory = "management"
)

type SourcePriority string

const (
	SourcePriorityP0 SourcePriority = "P0"
	SourcePriorityP1 SourcePriority = "P1"
	SourcePriorityP2 SourcePriority = "P2"
)

type SourceSpec struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Category     SourceCategory `json:"category"`
	Priority     SourcePriority `json:"priority"`
	Version      string         `json:"version"`
	Description  string         `json:"description"`
	Interface    string         `json:"interface,omitempty"`
	AdapterID    string         `json:"adapter_id"`
	OutputFormat string         `json:"output_format"`
	AdaptDiff    string         `json:"adapt_difficulty"`
	AccessValue  string         `json:"access_value"`
	DelegatedChecks []string   `json:"delegated_checks,omitempty"`
	DependsOn    []string       `json:"depends_on,omitempty"`
}

type SourceStatus struct {
	ID         string      `json:"id"`
	State      SourceState `json:"state"`
	Version    string      `json:"version"`
	Enabled    bool        `json:"enabled"`
	LastSync   time.Time   `json:"last_sync,omitempty"`
	LastError  string      `json:"last_error,omitempty"`
	Findings   int         `json:"findings_count"`
	SyncCount  int64       `json:"sync_count"`
	ErrorCount int64       `json:"error_count"`
	InstalledAt time.Time  `json:"installed_at,omitempty"`
	ConfiguredAt time.Time `json:"configured_at,omitempty"`
}

type SourceConfig struct {
	ID       string            `json:"id"`
	Settings map[string]string `json:"settings"`
}

type AuditLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	SourceID  string    `json:"source_id"`
	Operator  string    `json:"operator"`
	Detail    string    `json:"detail"`
	Success   bool      `json:"success"`
}

type SourceManagerInterface interface {
	DeploySource(ctx context.Context, spec SourceSpec, cfg SourceConfig) error
	UninstallSource(ctx context.Context, id string, force bool) error
	EnableSource(ctx context.Context, id string) error
	DisableSource(ctx context.Context, id string) error
	UpdateSource(ctx context.Context, id string, version string) error
	GetSourceStatus(id string) (*SourceStatus, bool)
	ListSources(category SourceCategory) []SourceStatus
	ListAllSources() []SourceStatus
	ConfigureSource(ctx context.Context, id string, cfg SourceConfig) error
	GetSourceConfig(id string) (*SourceConfig, bool)
	GetSourceSpec(id string) (*SourceSpec, bool)
	RunSourceNow(ctx context.Context, id string) error
	GetAuditLog(sourceID string, limit int) []AuditLogEntry
	HealthCheck(ctx context.Context) error
}

type SourceManagerModule struct {
	kernel KernelContext

	mu       sync.RWMutex
	specs    map[string]SourceSpec
	statuses map[string]SourceStatus
	configs  map[string]SourceConfig
	auditLog []AuditLogEntry
	stateDir string
	state    PluginState
}

func NewSourceManagerModule() *SourceManagerModule {
	return &SourceManagerModule{
		specs:    make(map[string]SourceSpec),
		statuses: make(map[string]SourceStatus),
		configs:  make(map[string]SourceConfig),
		auditLog: make([]AuditLogEntry, 0),
		stateDir: "data/source_manager",
	}
}

func (m *SourceManagerModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "source_manager",
		Version:     "1.0.0",
		Description: "External source lifecycle management — deploy, configure, enable/disable, update, uninstall",
		Author:      "ASSCOR Core Team",
	}
}

func (m *SourceManagerModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "adapter_integration", Interface: (*AdapterIntegrationInterface)(nil)},
	}
}

func (m *SourceManagerModule) Priority() int {
	return 55
}

func (m *SourceManagerModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

	os.MkdirAll(m.stateDir, 0755)
	m.loadState()

	if cfg := kc.GetConfigObj(); cfg != nil {
		m.syncFromAdapterRegistry(cfg)
	}

	kc.Container().Bind((*SourceManagerInterface)(nil), m)
	logger.WithComponent("source_manager").Info("initialized", "sources", len(m.specs))
	return nil
}

func (m *SourceManagerModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	logger.WithComponent("source_manager").Info("started")
	return nil
}

func (m *SourceManagerModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.saveState()
	m.state = PluginStopped
	logger.WithComponent("source_manager").Info("stopped")
	return nil
}

func (m *SourceManagerModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *SourceManagerModule) DeploySource(ctx context.Context, spec SourceSpec, cfg SourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if spec.ID == "" {
		return fmt.Errorf("source id is required")
	}
	if spec.Name == "" {
		return fmt.Errorf("source name is required")
	}
	if spec.Category != SourceCategoryScanner && spec.Category != SourceCategoryManagement {
		return fmt.Errorf("invalid source category: %s", spec.Category)
	}
	if spec.Priority != SourcePriorityP0 && spec.Priority != SourcePriorityP1 && spec.Priority != SourcePriorityP2 {
		return fmt.Errorf("invalid source priority: %s", spec.Priority)
	}

	if existing, exists := m.statuses[spec.ID]; exists && existing.State != SourceStateNotInstalled {
		return fmt.Errorf("source %s already deployed (state: %s)", spec.ID, existing.State)
	}

	for _, dep := range spec.DependsOn {
		depStatus, exists := m.statuses[dep]
		if !exists || (depStatus.State != SourceStateEnabled && depStatus.State != SourceStateRunning) {
			return fmt.Errorf("dependency %s is not available (state: %s)", dep, depStatus.State)
		}
	}

	now := time.Now()
	m.specs[spec.ID] = spec
	m.statuses[spec.ID] = SourceStatus{
		ID:          spec.ID,
		State:       SourceStateInstalled,
		Version:     spec.Version,
		Enabled:     false,
		InstalledAt: now,
	}
	cfg.ID = spec.ID
	m.configs[spec.ID] = cfg

	m.applyConfigToAdapter(spec.ID, cfg)

	m.appendAuditLog("deploy", spec.ID, "system", fmt.Sprintf("deployed v%s", spec.Version), true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.deployed", map[string]interface{}{"source_id": spec.ID, "version": spec.Version})

	logger.WithComponent("source_manager").Info("source deployed", "id", spec.ID, "version", spec.Version)
	return nil
}

func (m *SourceManagerModule) UninstallSource(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, specExists := m.specs[id]
	if !specExists {
		return fmt.Errorf("source %s not found", id)
	}

	status, statusExists := m.statuses[id]
	if !statusExists {
		return fmt.Errorf("source %s status not found", id)
	}

	if status.State == SourceStateRunning && !force {
		return fmt.Errorf("source %s is running, stop it first or use force", id)
	}

	for _, s := range m.specs {
		for _, dep := range s.DependsOn {
			if dep == id {
				depStatus := m.statuses[s.ID]
				if depStatus.Enabled {
					return fmt.Errorf("source %s is depended on by %s (enabled), uninstall that first", id, s.ID)
				}
			}
		}
	}

	m.removeConfigFromAdapter(id, spec)

	delete(m.specs, id)
	delete(m.statuses, id)
	delete(m.configs, id)

	m.appendAuditLog("uninstall", id, "system", fmt.Sprintf("uninstalled (force=%v)", force), true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.uninstalled", map[string]interface{}{"source_id": id, "force": force})

	logger.WithComponent("source_manager").Info("source uninstalled", "id", id, "force", force)
	return nil
}

func (m *SourceManagerModule) EnableSource(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[id]; !exists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if status.State == SourceStateEnabled || status.State == SourceStateRunning {
		return fmt.Errorf("source %s is already enabled", id)
	}
	if status.State == SourceStateNotInstalled {
		return fmt.Errorf("source %s is not installed", id)
	}

	for _, dep := range m.specs[id].DependsOn {
		depStatus, exists := m.statuses[dep]
		if !exists || !depStatus.Enabled {
			return fmt.Errorf("dependency %s is not enabled", dep)
		}
	}

	status.State = SourceStateEnabled
	status.Enabled = true
	status.ConfiguredAt = time.Now()
	m.statuses[id] = status

	m.setAdapterEnabled(id, true)

	m.appendAuditLog("enable", id, "system", "source enabled", true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.enabled", map[string]interface{}{"source_id": id})

	logger.WithComponent("source_manager").Info("source enabled", "id", id)
	return nil
}

func (m *SourceManagerModule) DisableSource(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[id]; !exists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if !status.Enabled {
		return fmt.Errorf("source %s is already disabled", id)
	}

	status.State = SourceStateDisabled
	status.Enabled = false
	m.statuses[id] = status

	m.setAdapterEnabled(id, false)

	m.appendAuditLog("disable", id, "system", "source disabled", true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.disabled", map[string]interface{}{"source_id": id})

	logger.WithComponent("source_manager").Info("source disabled", "id", id)
	return nil
}

func (m *SourceManagerModule) UpdateSource(ctx context.Context, id string, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, specExists := m.specs[id]
	if !specExists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if status.State == SourceStateNotInstalled {
		return fmt.Errorf("source %s is not installed", id)
	}

	oldVersion := spec.Version
	spec.Version = version
	m.specs[id] = spec

	status.Version = version
	status.State = SourceStateInstalled
	if status.Enabled {
		status.State = SourceStateEnabled
	}
	m.statuses[id] = status

	m.appendAuditLog("update", id, "system", fmt.Sprintf("updated %s -> %s", oldVersion, version), true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.updated", map[string]interface{}{"source_id": id, "old_version": oldVersion, "new_version": version})

	logger.WithComponent("source_manager").Info("source updated", "id", id, "old", oldVersion, "new", version)
	return nil
}

func (m *SourceManagerModule) GetSourceStatus(id string) (*SourceStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.statuses[id]
	if !ok {
		return nil, false
	}
	cp := s
	return &cp, true
}

func (m *SourceManagerModule) ListSources(category SourceCategory) []SourceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []SourceStatus
	for id, status := range m.statuses {
		if spec, ok := m.specs[id]; ok && spec.Category == category {
			cp := status
			result = append(result, cp)
		}
	}
	return result
}

func (m *SourceManagerModule) ListAllSources() []SourceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]SourceStatus, 0, len(m.statuses))
	for _, status := range m.statuses {
		cp := status
		result = append(result, cp)
	}
	return result
}

func (m *SourceManagerModule) ConfigureSource(ctx context.Context, id string, cfg SourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[id]; !exists {
		return fmt.Errorf("source %s not found", id)
	}

	cfg.ID = id
	m.configs[id] = cfg

	status := m.statuses[id]
	status.ConfiguredAt = time.Now()
	m.statuses[id] = status

	m.applyConfigToAdapter(id, cfg)

	m.appendAuditLog("configure", id, "system", "source reconfigured", true)
	m.saveState()

	logger.WithComponent("source_manager").Info("source configured", "id", id, "keys", len(cfg.Settings))
	return nil
}

func (m *SourceManagerModule) GetSourceConfig(id string) (*SourceConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[id]
	if !ok {
		return nil, false
	}
	cp := cfg
	return &cp, true
}

func (m *SourceManagerModule) GetSourceSpec(id string) (*SourceSpec, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	spec, ok := m.specs[id]
	if !ok {
		return nil, false
	}
	cp := spec
	return &cp, true
}

func (m *SourceManagerModule) RunSourceNow(ctx context.Context, id string) error {
	m.mu.Lock()
	status, exists := m.statuses[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("source %s not found", id)
	}
	if !status.Enabled {
		m.mu.Unlock()
		return fmt.Errorf("source %s is not enabled", id)
	}
	status.State = SourceStateRunning
	m.statuses[id] = status
	m.mu.Unlock()

	if m.kernel == nil {
		m.mu.Lock()
		status = m.statuses[id]
		status.State = SourceStateEnabled
		status.LastSync = time.Now()
		status.SyncCount++
		m.statuses[id] = status
		m.mu.Unlock()
		m.appendAuditLog("run", id, "system", "manual run (no kernel)", true)
		return nil
	}

	impl, ok := m.kernel.Container().Resolve((*AdapterIntegrationInterface)(nil))
	if !ok {
		return fmt.Errorf("adapter integration not available")
	}
	adapterInteg, ok := impl.(AdapterIntegrationInterface)
	if !ok {
		return fmt.Errorf("adapter integration type mismatch")
	}

	results := adapterInteg.RunAdapters(ctx)

	m.mu.Lock()
	status = m.statuses[id]
	findings := 0
	for _, r := range results {
		if r.AdapterID == id || r.AdapterName == m.specs[id].Name {
			findings = len(r.Findings)
			if r.Error != nil {
				status.State = SourceStateError
				status.LastError = r.Error.Error()
				status.ErrorCount++
			} else {
				status.State = SourceStateEnabled
				status.LastError = ""
			}
			break
		}
	}
	status.LastSync = time.Now()
	status.SyncCount++
	status.Findings = findings
	m.statuses[id] = status
	m.mu.Unlock()

	m.appendAuditLog("run", id, "system", fmt.Sprintf("manual run, findings=%d", findings), true)
	m.saveState()

	return nil
}

func (m *SourceManagerModule) GetAuditLog(sourceID string, limit int) []AuditLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []AuditLogEntry
	for i := len(m.auditLog) - 1; i >= 0; i-- {
		if sourceID == "" || m.auditLog[i].SourceID == sourceID {
			filtered = append(filtered, m.auditLog[i])
			if limit > 0 && len(filtered) >= limit {
				break
			}
		}
	}
	return filtered
}

func (m *SourceManagerModule) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	errorCount := 0
	for _, status := range m.statuses {
		if status.State == SourceStateError {
			errorCount++
		}
	}
	if errorCount > 0 {
		return fmt.Errorf("%d source(s) in error state", errorCount)
	}
	return nil
}

func (m *SourceManagerModule) appendAuditLog(action, sourceID, operator, detail string, success bool) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Action:    action,
		SourceID:  sourceID,
		Operator:  operator,
		Detail:    detail,
		Success:   success,
	}
	m.auditLog = append(m.auditLog, entry)
	if len(m.auditLog) > 10000 {
		m.auditLog = m.auditLog[len(m.auditLog)-5000:]
	}
}

func (m *SourceManagerModule) syncFromAdapterRegistry(cfg *config.Config) {
	adapters := adapter.List()
	for _, a := range adapters {
		id := a.ID()
		if _, exists := m.specs[id]; exists {
			continue
		}

		var category SourceCategory
		switch a.Category() {
		case "scanner":
			category = SourceCategoryScanner
		case "management":
			category = SourceCategoryManagement
		default:
			category = SourceCategoryScanner
		}

		var priority SourcePriority
		switch a.Priority() {
		case "P0":
			priority = SourcePriorityP0
		case "P1":
			priority = SourcePriorityP1
		case "P2":
			priority = SourcePriorityP2
		default:
			priority = SourcePriorityP1
		}

		enabled := a.IsEnabled(cfg.AdapterConfig)
		state := SourceStateInstalled
		if enabled {
			state = SourceStateEnabled
		}

		m.specs[id] = SourceSpec{
			ID:        id,
			Name:      a.Name(),
			Category:  category,
			Priority:  priority,
			Version:   a.Version(),
			AdapterID: id,
		}

		m.statuses[id] = SourceStatus{
			ID:          id,
			State:       state,
			Version:     a.Version(),
			Enabled:     enabled,
			InstalledAt: time.Now(),
		}

		settings := make(map[string]string)
		for k, v := range cfg.AdapterConfig {
			if k == id || (len(k) > len(id)+1 && k[:len(id)+1] == id+".") {
				settings[k] = v
			}
		}
		m.configs[id] = SourceConfig{ID: id, Settings: settings}
	}
}

func (m *SourceManagerModule) setAdapterEnabled(id string, enabled bool) {
	if m.kernel == nil {
		return
	}
	if cfg := m.kernel.GetConfigObj(); cfg != nil {
		val := "off"
		if enabled {
			val = "on"
		}
		cfg.AdapterConfig[id] = val
		m.kernel.SetConfig("adapters."+id, val)
	}
}

func (m *SourceManagerModule) applyConfigToAdapter(id string, cfg SourceConfig) {
	if m.kernel == nil {
		return
	}
	if kernelCfg := m.kernel.GetConfigObj(); kernelCfg != nil {
		for k, v := range cfg.Settings {
			kernelCfg.AdapterConfig[id+"."+k] = v
		}
		if enabled, ok := cfg.Settings["enabled"]; ok {
			kernelCfg.AdapterConfig[id] = enabled
		}
	}
}

func (m *SourceManagerModule) removeConfigFromAdapter(id string, spec SourceSpec) {
	if m.kernel == nil {
		return
	}
	if cfg := m.kernel.GetConfigObj(); cfg != nil {
		delete(cfg.AdapterConfig, id)
		prefix := id + "."
		for k := range cfg.AdapterConfig {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				delete(cfg.AdapterConfig, k)
			}
		}
	}
}

func (m *SourceManagerModule) publishEvent(ctx context.Context, topic string, payload map[string]interface{}) {
	if m.kernel == nil {
		return
	}
	m.kernel.Bus().Publish(ctx, Message{
		Topic:     topic,
		Payload:   payload,
		Source:    "source_manager",
		Timestamp: time.Now(),
	})
}

func (m *SourceManagerModule) saveState() {
	state := struct {
		Specs    map[string]SourceSpec    `json:"specs"`
		Statuses map[string]SourceStatus  `json:"statuses"`
		Configs  map[string]SourceConfig  `json:"configs"`
		AuditLog []AuditLogEntry          `json:"audit_log"`
	}{
		Specs:    m.specs,
		Statuses: m.statuses,
		Configs:  m.configs,
		AuditLog: m.auditLog,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		logger.WithComponent("source_manager").Error("failed to marshal state", "error", err)
		return
	}

	path := filepath.Join(m.stateDir, "source_manager_state.json")
	if err := os.MkdirAll(m.stateDir, 0755); err != nil {
		logger.WithComponent("source_manager").Error("failed to create state dir", "error", err)
		return
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		logger.WithComponent("source_manager").Error("failed to write state", "error", err)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		logger.WithComponent("source_manager").Error("failed to rename state file", "error", err)
		return
	}
}

func (m *SourceManagerModule) loadState() {
	path := filepath.Join(m.stateDir, "source_manager_state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.WithComponent("source_manager").Warn("failed to read state", "error", err)
		}
		return
	}

	var state struct {
		Specs    map[string]SourceSpec    `json:"specs"`
		Statuses map[string]SourceStatus  `json:"statuses"`
		Configs  map[string]SourceConfig  `json:"configs"`
		AuditLog []AuditLogEntry          `json:"audit_log"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		logger.WithComponent("source_manager").Warn("failed to unmarshal state", "error", err)
		return
	}

	if state.Specs != nil {
		m.specs = state.Specs
	}
	if state.Statuses != nil {
		m.statuses = state.Statuses
	}
	if state.Configs != nil {
		m.configs = state.Configs
	}
	if state.AuditLog != nil {
		m.auditLog = state.AuditLog
	}
}
