package extmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/engine"
	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
)

type ManagerConfig struct {
	ExtensionsDir    string
	StateDir         string
	RepositoryURLs   []string
	AutoEnable       bool
	AllowPreRelease  bool
	ExecutionPolicy  ExecutionPolicy
	ExecutionTimeout time.Duration
	WhiteListedCmds  []string
}

func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		ExtensionsDir:    "./extensions",
		StateDir:         "./extensions/state",
		AutoEnable:       false,
		AllowPreRelease:  false,
		ExecutionPolicy:  ExecPolicyWhitelist,
		ExecutionTimeout: 30 * time.Second,
		WhiteListedCmds: []string{
			"python3", "python", "node", "sh", "bash",
			"powershell", "pwsh",
		},
	}
}

type ExtensionManager struct {
	mu        sync.RWMutex
	config    ManagerConfig
	installer *ExtensionInstaller
	lifecycle *ExtensionLifecycle
	executor  *ExtensionExecutor
	assessor  *engine.Assessor
	repos     []ExtensionRepository
}

type ExtensionRepository struct {
	Name string
	URL  string
}

var (
	globalManager     *ExtensionManager
	globalManagerOnce sync.Once
)

func GetManager() *ExtensionManager {
	globalManagerOnce.Do(func() {
		cfg := DefaultManagerConfig()
		globalManager = NewExtensionManager(cfg)
	})
	return globalManager
}

func InitManager(cfg ManagerConfig) *ExtensionManager {
	globalManagerOnce.Do(func() {
		globalManager = NewExtensionManager(cfg)
	})
	return globalManager
}

func NewExtensionManager(cfg ManagerConfig) *ExtensionManager {
	os.MkdirAll(cfg.ExtensionsDir, 0755)
	os.MkdirAll(cfg.StateDir, 0755)

	installer := NewExtensionInstaller(cfg.ExtensionsDir)
	lifecycle := NewExtensionLifecycle(cfg.StateDir)

	execCfg := ExecutionConfig{
		Policy:      cfg.ExecutionPolicy,
		Timeout:     cfg.ExecutionTimeout,
		BinaryPaths: make(map[string]string),
		Environment: make(map[string]string),
	}
	executor := NewExtensionExecutor(execCfg)
	executor.SetWhitelist(cfg.WhiteListedCmds)

	mgr := &ExtensionManager{
		config:    cfg,
		installer: installer,
		lifecycle: lifecycle,
		executor:  executor,
	}

	for repoIdx, repoURL := range cfg.RepositoryURLs {
		mgr.repos = append(mgr.repos, ExtensionRepository{
			Name: fmt.Sprintf("repo-%d", repoIdx),
			URL:  repoURL,
		})
	}

	logger.With("component", "extmgr").Info("manager initialized", "repos", len(mgr.repos), "dir", cfg.ExtensionsDir)
	return mgr
}

func (m *ExtensionManager) SetAssessor(a *engine.Assessor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assessor = a
}

func (m *ExtensionManager) InstallFromSpec(spec ExtensionSpec) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}

	if existing, exists := m.lifecycle.Get(spec.ID); exists {
		existingVer, _ := ParseSemVer(existing.Version)
		newVer, _ := ParseSemVer(spec.Version)
		if newVer.Less(existingVer) || newVer.Equal(existingVer) {
			return fmt.Errorf("extension %s v%s already installed (v%s)", spec.ID, spec.Version, existing.Version)
		}
	}

	if err := m.lifecycle.ValidateDependencies(spec); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	installPath, err := m.installer.Install(spec)
	if err != nil {
		return fmt.Errorf("install %s: %w", spec.ID, err)
	}

	if err := m.lifecycle.Register(spec, installPath); err != nil {
		os.RemoveAll(installPath)
		return fmt.Errorf("register %s: %w", spec.ID, err)
	}

	if m.config.AutoEnable {
		if err := m.lifecycle.Enable(spec.ID); err != nil {
			logger.With("component", "extmgr").Warn("auto-enable failed", "extension_id", spec.ID, "error", err)
		}
	}

	m.onExtensionInstalled(spec)
	return nil
}

func (m *ExtensionManager) InstallFromJSON(jsonData []byte) error {
	var spec ExtensionSpec
	if err := json.Unmarshal(jsonData, &spec); err != nil {
		return fmt.Errorf("parse extension spec: %w", err)
	}
	return m.InstallFromSpec(spec)
}

func (m *ExtensionManager) InstallFromFile(specPath string) error {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("read spec file: %w", err)
	}
	return m.InstallFromJSON(data)
}

func (m *ExtensionManager) Enable(id string) error {
	if err := m.lifecycle.Enable(id); err != nil {
		return err
	}

	spec, ok := m.lifecycle.Get(id)
	if !ok {
		return fmt.Errorf("extension %s not found after enable", id)
	}
	m.onExtensionEnabled(spec)
	return nil
}

func (m *ExtensionManager) Disable(id string) error {
	spec, ok := m.lifecycle.Get(id)
	if ok {
		m.onExtensionDisabled(spec)
	}
	return m.lifecycle.Disable(id)
}

func (m *ExtensionManager) Delete(id string) error {
	spec, ok := m.lifecycle.Get(id)
	if ok {
		m.onExtensionDeleted(spec)
	}
	return m.lifecycle.Delete(id)
}

func (m *ExtensionManager) Execute(ctx context.Context, id string, args []string) (*ExecutionResult, error) {
	spec, ok := m.lifecycle.Get(id)
	if !ok {
		return nil, fmt.Errorf("extension %s not found", id)
	}
	return m.executor.Execute(ctx, spec, args)
}

func (m *ExtensionManager) ExecuteScript(ctx context.Context, id string, script string, args []string) (*ExecutionResult, error) {
	spec, ok := m.lifecycle.Get(id)
	if !ok {
		return nil, fmt.Errorf("extension %s not found", id)
	}
	return m.executor.ExecuteCustom(ctx, spec, script, args)
}

func (m *ExtensionManager) Get(id string) (ExtensionSpec, bool) {
	return m.lifecycle.Get(id)
}

func (m *ExtensionManager) List() []ExtensionSpec {
	return m.lifecycle.List()
}

func (m *ExtensionManager) ListEnabled() []ExtensionSpec {
	return m.lifecycle.ListEnabled()
}

func (m *ExtensionManager) UpdateConfig(id string, config map[string]string) error {
	return m.lifecycle.UpdateConfig(id, config)
}

func (m *ExtensionManager) Count() int {
	return m.lifecycle.Count()
}

func (m *ExtensionManager) IsInstalled(id string) bool {
	return m.lifecycle.IsInstalled(id)
}

func (m *ExtensionManager) AddRepository(name, url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos = append(m.repos, ExtensionRepository{Name: name, URL: url})
	logger.With("component", "extmgr").Info("added repository", "name", name, "url", url)
}

func (m *ExtensionManager) RemoveRepository(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.repos {
		if r.Name == name {
			m.repos = append(m.repos[:i], m.repos[i+1:]...)
			logger.With("component", "extmgr").Info("removed repository", "name", name)
			return
		}
	}
}

func (m *ExtensionManager) ListRepositories() []ExtensionRepository {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make([]ExtensionRepository, len(m.repos))
	copy(cp, m.repos)
	return cp
}

func (m *ExtensionManager) RefreshRepositories(ctx context.Context) error {
	m.mu.RLock()
	repos := make([]ExtensionRepository, len(m.repos))
	copy(repos, m.repos)
	m.mu.RUnlock()

	for _, repo := range repos {
		logger.With("component", "extmgr").Info("refreshing repository", "name", repo.Name, "url", repo.URL)
	}
	return nil
}

func (m *ExtensionManager) GetDependents(id string) []string {
	return m.lifecycle.GetDependents(id)
}

func (m *ExtensionManager) Installer() *ExtensionInstaller {
	return m.installer
}

func (m *ExtensionManager) Executor() *ExtensionExecutor {
	return m.executor
}

func (m *ExtensionManager) Lifecycle() *ExtensionLifecycle {
	return m.lifecycle
}

func (m *ExtensionManager) onExtensionInstalled(spec ExtensionSpec) {
	m.mu.RLock()
	a := m.assessor
	m.mu.RUnlock()

	switch spec.ExtType {
	case ExtTypeCheckModule:
		m.registerCheckModule(spec)
	case ExtTypeDomain:
		model.RegisterDomain(model.DomainMeta{
			ID:            spec.ID,
			Label:         spec.Name,
			Category:      model.CategoryExtension,
			DefaultWeight: 5,
		})
		logger.With("component", "extmgr").Info("registered domain from extension", "extension_id", spec.ID)
	case ExtTypeEdgeFactor:
		factorValue := 1.0
		if v, ok := spec.CustomConfig["factor"]; ok {
			fmt.Sscanf(v, "%f", &factorValue)
		}
		model.RegisterEdgeFactor(model.EdgeFactor{
			ID:          spec.ID,
			Name:        spec.Name,
			Description: spec.Description,
			Factor:      factorValue,
			Active:      spec.State == ExtStateEnabled,
			Priority:    50,
		})
		logger.With("component", "extmgr").Info("registered edge factor from extension", "extension_id", spec.ID)
	case ExtTypeHook:
		if a != nil {
			a.RegisterHook(spec.ID, engine.PhasePostScore, func(ctx context.Context, result *model.AssessmentResult) error {
				return m.executeHook(ctx, spec, result)
			}, 50)
			logger.With("component", "extmgr").Info("registered hook from extension", "extension_id", spec.ID)
		}
	}
}

func (m *ExtensionManager) onExtensionEnabled(spec ExtensionSpec) {
	if spec.ExtType == ExtTypeEdgeFactor {
		model.SetEdgeFactorValue(spec.ID, 1.0)
	}
}

func (m *ExtensionManager) onExtensionDisabled(spec ExtensionSpec) {
	switch spec.ExtType {
	case ExtTypeCheckModule:
		count := checks.Unregister(spec.ID)
		logger.With("component", "extmgr").Info("unregistered checks from extension", "count", count, "extension_id", spec.ID)
	case ExtTypeDomain:
		model.UnregisterDomain(spec.ID)
	case ExtTypeEdgeFactor:
		model.SetEdgeFactorValue(spec.ID, 1.0)
	}
}

func (m *ExtensionManager) onExtensionDeleted(spec ExtensionSpec) {
	m.onExtensionDisabled(spec)
}

func (m *ExtensionManager) registerCheckModule(spec ExtensionSpec) {
	checkDir := filepath.Join(spec.InstallPath, "checks")
	if _, err := os.Stat(checkDir); os.IsNotExist(err) {
		logger.With("component", "extmgr").Debug("no checks directory in extension", "extension_id", spec.ID)
		return
	}

	entries, err := os.ReadDir(checkDir)
	if err != nil {
		logger.With("component", "extmgr").Error("failed to read checks dir", "extension_id", spec.ID, "error", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainDir := filepath.Join(checkDir, entry.Name())
		files, err := os.ReadDir(domainDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".go" {
				continue
			}
			logger.With("component", "extmgr").Debug("found check source in extension", "extension_id", spec.ID, "dir", entry.Name(), "file", f.Name())
		}
	}
}

func (m *ExtensionManager) executeHook(ctx context.Context, spec ExtensionSpec, result *model.AssessmentResult) error {
	_, err := m.executor.Execute(ctx, spec, []string{"--hook", "post_score"})
	return err
}

func (m *ExtensionManager) ExportState() ([]byte, error) {
	extensions := m.lifecycle.List()
	return json.MarshalIndent(extensions, "", "  ")
}

func (m *ExtensionManager) GetConfig() ManagerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}
