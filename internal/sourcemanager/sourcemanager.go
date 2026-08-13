//go:build sourcemanager

package sourcemanager

import (
	"github.com/asscor/asscor/internal/kernel"
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

type Module struct {
	kc kernel.KernelContext

	mu       sync.RWMutex
	specs    map[string]kernel.SourceSpec
	statuses map[string]kernel.SourceStatus
	configs  map[string]kernel.SourceConfig
	auditLog []kernel.AuditLogEntry
	stateDir string
	state    kernel.PluginState
}

func New() *Module {
	return &Module{
		specs:    make(map[string]kernel.SourceSpec),
		statuses: make(map[string]kernel.SourceStatus),
		configs:  make(map[string]kernel.SourceConfig),
		auditLog: make([]kernel.AuditLogEntry, 0),
		stateDir: "data/source_manager",
	}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "source_manager",
		Version:     "1.0.0",
		Description: "External source lifecycle management — deploy, configure, enable/disable, update, uninstall",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return []kernel.PluginDependency{
		{Name: "adapter_integration", Interface: (*kernel.AdapterIntegrationInterface)(nil)},
	}
}

func (m *Module) Priority() int {
	return 55
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.state = kernel.PluginInitialized

	os.MkdirAll(m.stateDir, 0755)
	m.loadState()

	if cfg := kc.GetConfigObj(); cfg != nil {
		m.syncFromAdapterRegistry(cfg)
	}

	kc.Container().Bind((*kernel.SourceManagerInterface)(nil), m)
	logger.WithComponent("source_manager").Info("initialized", "sources", len(m.specs))
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	logger.WithComponent("source_manager").Info("started")
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	m.saveState()
	m.state = kernel.PluginStopped
	logger.WithComponent("source_manager").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) DeploySource(ctx context.Context, spec kernel.SourceSpec, cfg kernel.SourceConfig) error {
	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(ctx, "source.pre_deploy", map[string]interface{}{
			"source_id": spec.ID,
			"version":   spec.Version,
		})
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if spec.ID == "" {
		return fmt.Errorf("source id is required")
	}
	if spec.Name == "" {
		return fmt.Errorf("source name is required")
	}
	if spec.Category != kernel.SourceCategoryScanner && spec.Category != kernel.SourceCategoryManagement {
		return fmt.Errorf("invalid source category: %s", spec.Category)
	}
	if spec.Priority != kernel.SourcePriorityP0 && spec.Priority != kernel.SourcePriorityP1 && spec.Priority != kernel.SourcePriorityP2 {
		return fmt.Errorf("invalid source priority: %s", spec.Priority)
	}

	if existing, exists := m.statuses[spec.ID]; exists && existing.State != kernel.SourceStateNotInstalled {
		return fmt.Errorf("source %s already deployed (state: %s)", spec.ID, existing.State)
	}

	for _, dep := range spec.DependsOn {
		depStatus, exists := m.statuses[dep]
		if !exists || (depStatus.State != kernel.SourceStateEnabled && depStatus.State != kernel.SourceStateRunning) {
			return fmt.Errorf("dependency %s is not available (state: %s)", dep, depStatus.State)
		}
	}

	now := time.Now()
	m.specs[spec.ID] = spec
	m.statuses[spec.ID] = kernel.SourceStatus{
		ID:          spec.ID,
		State:       kernel.SourceStateInstalled,
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

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(ctx, "source.post_deploy", map[string]interface{}{
			"source_id": spec.ID,
			"version":   spec.Version,
		})
	}

	logger.WithComponent("source_manager").Info("source deployed", "id", spec.ID, "version", spec.Version)
	return nil
}

func (m *Module) UninstallSource(ctx context.Context, id string, force bool) error {
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

	if status.State == kernel.SourceStateRunning && !force {
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

func (m *Module) EnableSource(ctx context.Context, id string) error {
	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(ctx, "source.pre_enable", map[string]interface{}{
			"source_id": id,
		})
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[id]; !exists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if status.State == kernel.SourceStateEnabled || status.State == kernel.SourceStateRunning {
		return fmt.Errorf("source %s is already enabled", id)
	}
	if status.State == kernel.SourceStateNotInstalled {
		return fmt.Errorf("source %s is not installed", id)
	}

	for _, dep := range m.specs[id].DependsOn {
		depStatus, exists := m.statuses[dep]
		if !exists || !depStatus.Enabled {
			return fmt.Errorf("dependency %s is not enabled", dep)
		}
	}

	status.State = kernel.SourceStateEnabled
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

func (m *Module) DisableSource(ctx context.Context, id string) error {
	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(ctx, "source.pre_disable", map[string]interface{}{
			"source_id": id,
		})
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[id]; !exists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if !status.Enabled {
		return fmt.Errorf("source %s is already disabled", id)
	}

	status.State = kernel.SourceStateDisabled
	status.Enabled = false
	m.statuses[id] = status

	m.setAdapterEnabled(id, false)

	m.appendAuditLog("disable", id, "system", "source disabled", true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.disabled", map[string]interface{}{"source_id": id})

	logger.WithComponent("source_manager").Info("source disabled", "id", id)
	return nil
}

func (m *Module) UpdateSource(ctx context.Context, id string, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, specExists := m.specs[id]
	if !specExists {
		return fmt.Errorf("source %s not found", id)
	}

	status := m.statuses[id]
	if status.State == kernel.SourceStateNotInstalled {
		return fmt.Errorf("source %s is not installed", id)
	}

	oldVersion := spec.Version
	spec.Version = version
	m.specs[id] = spec

	status.Version = version
	status.State = kernel.SourceStateInstalled
	if status.Enabled {
		status.State = kernel.SourceStateEnabled
	}
	m.statuses[id] = status

	m.appendAuditLog("update", id, "system", fmt.Sprintf("updated %s -> %s", oldVersion, version), true)
	m.saveState()

	m.publishEvent(ctx, "source_manager.updated", map[string]interface{}{"source_id": id, "old_version": oldVersion, "new_version": version})

	logger.WithComponent("source_manager").Info("source updated", "id", id, "old", oldVersion, "new", version)
	return nil
}

func (m *Module) GetSourceStatus(id string) (*kernel.SourceStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.statuses[id]
	if !ok {
		return nil, false
	}
	cp := s
	return &cp, true
}

func (m *Module) ListSources(category kernel.SourceCategory) []kernel.SourceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []kernel.SourceStatus
	for id, status := range m.statuses {
		if spec, ok := m.specs[id]; ok && spec.Category == category {
			cp := status
			result = append(result, cp)
		}
	}
	return result
}

func (m *Module) ListAllSources() []kernel.SourceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]kernel.SourceStatus, 0, len(m.statuses))
	for _, status := range m.statuses {
		cp := status
		result = append(result, cp)
	}
	return result
}

func (m *Module) ConfigureSource(ctx context.Context, id string, cfg kernel.SourceConfig) error {
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

func (m *Module) GetSourceConfig(id string) (*kernel.SourceConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[id]
	if !ok {
		return nil, false
	}
	cp := cfg
	return &cp, true
}

func (m *Module) GetSourceSpec(id string) (*kernel.SourceSpec, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	spec, ok := m.specs[id]
	if !ok {
		return nil, false
	}
	cp := spec
	return &cp, true
}

func (m *Module) RunSourceNow(ctx context.Context, id string) error {
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
	status.State = kernel.SourceStateRunning
	m.statuses[id] = status
	m.mu.Unlock()

	if m.kc == nil {
		m.mu.Lock()
		status = m.statuses[id]
		status.State = kernel.SourceStateEnabled
		status.LastSync = time.Now()
		status.SyncCount++
		m.statuses[id] = status
		m.mu.Unlock()
		m.appendAuditLog("run", id, "system", "manual run (no kernel)", true)
		return nil
	}

	impl, ok := m.kc.Container().Resolve((*kernel.AdapterIntegrationInterface)(nil))
	if !ok {
		return fmt.Errorf("adapter integration not available")
	}
	adapterInteg, ok := impl.(kernel.AdapterIntegrationInterface)
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
				status.State = kernel.SourceStateError
				status.LastError = r.Error.Error()
				status.ErrorCount++
			} else {
				status.State = kernel.SourceStateEnabled
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

func (m *Module) GetAuditLog(sourceID string, limit int) []kernel.AuditLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []kernel.AuditLogEntry
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

func (m *Module) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	errorCount := 0
	for _, status := range m.statuses {
		if status.State == kernel.SourceStateError {
			errorCount++
		}
	}
	if errorCount > 0 {
		return fmt.Errorf("%d source(s) in error state", errorCount)
	}
	return nil
}

func (m *Module) appendAuditLog(action, sourceID, operator, detail string, success bool) {
	entry := kernel.AuditLogEntry{
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

func (m *Module) syncFromAdapterRegistry(cfg *config.Config) {
	adapters := adapter.List()
	for _, a := range adapters {
		id := a.ID()
		if _, exists := m.specs[id]; exists {
			continue
		}

		var category kernel.SourceCategory
		switch a.Category() {
		case "scanner":
			category = kernel.SourceCategoryScanner
		case "management":
			category = kernel.SourceCategoryManagement
		default:
			category = kernel.SourceCategoryScanner
		}

		var priority kernel.SourcePriority
		switch a.Priority() {
		case "P0":
			priority = kernel.SourcePriorityP0
		case "P1":
			priority = kernel.SourcePriorityP1
		case "P2":
			priority = kernel.SourcePriorityP2
		default:
			priority = kernel.SourcePriorityP1
		}

		enabled := a.IsEnabled(cfg.AdapterConfig)
		state := kernel.SourceStateInstalled
		if enabled {
			state = kernel.SourceStateEnabled
		}

		m.specs[id] = kernel.SourceSpec{
			ID:        id,
			Name:      a.Name(),
			Category:  category,
			Priority:  priority,
			Version:   a.Version(),
			AdapterID: id,
		}

		m.statuses[id] = kernel.SourceStatus{
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
		m.configs[id] = kernel.SourceConfig{ID: id, Settings: settings}
	}
}

func (m *Module) setAdapterEnabled(id string, enabled bool) {
	if m.kc == nil {
		return
	}
	if cfg := m.kc.GetConfigObj(); cfg != nil {
		val := "off"
		if enabled {
			val = "on"
		}
		cfg.AdapterConfig[id] = val
		m.kc.SetConfig("adapters."+id, val)
	}
}

func (m *Module) applyConfigToAdapter(id string, cfg kernel.SourceConfig) {
	if m.kc == nil {
		return
	}
	if kernelCfg := m.kc.GetConfigObj(); kernelCfg != nil {
		for k, v := range cfg.Settings {
			kernelCfg.AdapterConfig[id+"."+k] = v
		}
		if enabled, ok := cfg.Settings["enabled"]; ok {
			kernelCfg.AdapterConfig[id] = enabled
		}
	}
}

func (m *Module) removeConfigFromAdapter(id string, spec kernel.SourceSpec) {
	if m.kc == nil {
		return
	}
	if cfg := m.kc.GetConfigObj(); cfg != nil {
		delete(cfg.AdapterConfig, id)
		prefix := id + "."
		for k := range cfg.AdapterConfig {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				delete(cfg.AdapterConfig, k)
			}
		}
	}
}

func (m *Module) publishEvent(ctx context.Context, topic string, payload map[string]interface{}) {
	if m.kc == nil {
		return
	}
	m.kc.Bus().Publish(ctx, kernel.Message{
		Topic:     topic,
		Payload:   payload,
		Source:    "source_manager",
		Timestamp: time.Now(),
	})
}

func (m *Module) saveState() {
	state := struct {
		Specs    map[string]kernel.SourceSpec    `json:"specs"`
		Statuses map[string]kernel.SourceStatus  `json:"statuses"`
		Configs  map[string]kernel.SourceConfig  `json:"configs"`
		AuditLog []kernel.AuditLogEntry          `json:"audit_log"`
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

func (m *Module) loadState() {
	path := filepath.Join(m.stateDir, "source_manager_state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.WithComponent("source_manager").Warn("failed to read state", "error", err)
		}
		return
	}

	var state struct {
		Specs    map[string]kernel.SourceSpec    `json:"specs"`
		Statuses map[string]kernel.SourceStatus  `json:"statuses"`
		Configs  map[string]kernel.SourceConfig  `json:"configs"`
		AuditLog []kernel.AuditLogEntry          `json:"audit_log"`
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
