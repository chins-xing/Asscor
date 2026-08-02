package extmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
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
			"python3", "node", "sh",
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

	kernelExtensions kernel.ModuleExtensions // bridge to kernel Extension Points

	// Callbacks for extension types that need external wiring.
	// Set before enabling extensions; nil means the type is skipped.
	OnCLICommand    func(spec ExtensionSpec)  // register CLI command
	OnScoringPlugin func(spec ExtensionSpec)  // register scoring formula
	OnWebPanelRoute func(spec ExtensionSpec)  // register web UI route
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

	logger.WithComponent("extmgr").Info("manager initialized", "repos", len(mgr.repos), "dir", cfg.ExtensionsDir)
	return mgr
}

func (m *ExtensionManager) SetAssessor(a *engine.Assessor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assessor = a
}

func (m *ExtensionManager) SetKernelExtensions(ext kernel.ModuleExtensions) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kernelExtensions = ext
}

func (m *ExtensionManager) InstallFromSpec(spec ExtensionSpec) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}

	m.mu.Lock()
	existing, exists := m.lifecycle.Get(spec.ID)
	if exists {
		existingVer, _ := ParseSemVer(existing.Version)
		newVer, _ := ParseSemVer(spec.Version)
		if newVer.Less(existingVer) || newVer.Equal(existingVer) {
			m.mu.Unlock()
			return fmt.Errorf("extension %s v%s already installed (v%s)", spec.ID, spec.Version, existing.Version)
		}
	}

	if err := m.lifecycle.ValidateDependencies(spec); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("dependency check failed: %w", err)
	}
	m.mu.Unlock()

	installPath, err := m.installer.Install(spec)
	if err != nil {
		m.fireExtensionEvent("extension.install_failed", spec.ID, err.Error())
		return fmt.Errorf("install %s: %w", spec.ID, err)
	}

	m.mu.Lock()
	if err := m.lifecycle.Register(spec, installPath); err != nil {
		m.mu.Unlock()
		os.RemoveAll(installPath)
		m.fireExtensionEvent("extension.install_failed", spec.ID, err.Error())
		return fmt.Errorf("register %s: %w", spec.ID, err)
	}

	autoEnable := m.config.AutoEnable
	m.mu.Unlock()

	if autoEnable {
		if err := m.lifecycle.Enable(spec.ID); err != nil {
			logger.WithComponent("extmgr").Warn("auto-enable failed", "extension_id", spec.ID, "error", err)
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
		m.fireExtensionEvent("extension.enable_failed", id, err.Error())
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
	logger.WithComponent("extmgr").Info("added repository", "name", name, "url", url)
}

func (m *ExtensionManager) RemoveRepository(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.repos {
		if r.Name == name {
			m.repos = append(m.repos[:i], m.repos[i+1:]...)
			logger.WithComponent("extmgr").Info("removed repository", "name", name)
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
		logger.WithComponent("extmgr").Info("refreshing repository", "name", repo.Name, "url", repo.URL)
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
		if m.kernelExtensions != nil {
			m.kernelExtensions.RegisterExtension(spec.ID, "assessor.pre_evaluate", func(ctx context.Context, data interface{}) error {
				return m.executeExtension(ctx, spec, "pre_evaluate")
			}, 50)
		}
	case ExtTypeDomain:
		model.RegisterDomain(model.DomainMeta{
			ID:            spec.ID,
			Label:         spec.Name,
			Category:      model.CategoryExtension,
			DefaultWeight: 5,
		})
		logger.WithComponent("extmgr").Info("registered domain from extension", "extension_id", spec.ID)
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
		logger.WithComponent("extmgr").Info("registered edge factor from extension", "extension_id", spec.ID)
	case ExtTypeHook:
		// Priority: kernel Extension Point > engine hook (backward compat)
		extPointName := spec.CustomConfig["extension_point"]
		if extPointName != "" && m.kernelExtensions != nil {
			m.kernelExtensions.RegisterExtension(spec.ID, extPointName, func(ctx context.Context, data interface{}) error {
				return m.executeHook(ctx, spec, nil)
			}, 50)
			logger.WithComponent("extmgr").Info("registered hook on kernel extension point",
				"extension_id", spec.ID, "extension_point", extPointName)
		} else if a != nil {
			a.RegisterHook(spec.ID, engine.PhasePostScore, func(ctx context.Context, result *model.AssessmentResult) error {
				return m.executeHook(ctx, spec, result)
			}, 50)
			logger.WithComponent("extmgr").Info("registered hook on engine PhasePostScore (legacy)",
				"extension_id", spec.ID)
		} else {
			logger.WithComponent("extmgr").Warn("hook installed but no assessor or extension point configured",
				"extension_id", spec.ID)
		}
	case ExtTypeCLICommand:
		if m.kernelExtensions != nil {
			m.kernelExtensions.RegisterExtension(spec.ID, "cli.command.register", func(ctx context.Context, data interface{}) error {
				return m.executeExtension(ctx, spec, "register")
			}, 50)
			logger.WithComponent("extmgr").Info("registered CLI command via extension point", "extension_id", spec.ID)
		} else if m.OnCLICommand != nil {
			m.OnCLICommand(spec)
		} else {
			logger.WithComponent("extmgr").Info("CLI command extension installed (no kernel bridge configured)", "extension_id", spec.ID)
		}
	case ExtTypeScoringPlugin:
		if m.kernelExtensions != nil {
			m.kernelExtensions.RegisterExtension(spec.ID, "assessor.pre_score", func(ctx context.Context, data interface{}) error {
				return m.executeExtension(ctx, spec, "compute_score")
			}, 45)
			logger.WithComponent("extmgr").Info("registered scoring plugin via extension point", "extension_id", spec.ID)
		} else if m.OnScoringPlugin != nil {
			m.OnScoringPlugin(spec)
		} else {
			logger.WithComponent("extmgr").Info("scoring plugin installed (no engine bridge configured)", "extension_id", spec.ID)
		}
	case ExtTypeWebPanel:
		if m.kernelExtensions != nil {
			m.kernelExtensions.RegisterExtension(spec.ID, "webui.route.register", func(ctx context.Context, data interface{}) error {
				return m.executeExtension(ctx, spec, "register_route")
			}, 50)
			logger.WithComponent("extmgr").Info("registered web panel via extension point", "extension_id", spec.ID)
		} else if m.OnWebPanelRoute != nil {
			m.OnWebPanelRoute(spec)
		} else {
			logger.WithComponent("extmgr").Info("web panel installed (no webui bridge configured)", "extension_id", spec.ID)
		}
	case ExtTypeAdapter, ExtTypeCustom:
		logger.WithComponent("extmgr").Info("extension installed (type handled by adapter registry)",
			"extension_id", spec.ID, "type", string(spec.ExtType))
	default:
		logger.WithComponent("extmgr").Warn("unknown extension type in onExtensionInstalled",
			"extension_id", spec.ID, "type", string(spec.ExtType))
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
		logger.WithComponent("extmgr").Info("unregistered checks from extension", "count", count, "extension_id", spec.ID)
	case ExtTypeDomain:
		model.UnregisterDomain(spec.ID)
	case ExtTypeEdgeFactor:
		fv := 1.0
		if v, ok := spec.CustomConfig["factor"]; ok {
			fmt.Sscanf(v, "%f", &fv)
		}
		model.SetEdgeFactorValue(spec.ID, fv)
	case ExtTypeCLICommand:
		logger.WithComponent("extmgr").Info("CLI command extension disabled", "extension_id", spec.ID)
	}
	if m.kernelExtensions != nil {
		m.kernelExtensions.UnregisterPlugin(spec.ID)
	}
}

func (m *ExtensionManager) onExtensionDeleted(spec ExtensionSpec) {
	m.onExtensionDisabled(spec)
}

func (m *ExtensionManager) registerCheckModule(spec ExtensionSpec) {
	manifestPath := filepath.Join(spec.InstallPath, "checks.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.WithComponent("extmgr").Info("check module has no checks.json, scanning for Go sources",
				"extension_id", spec.ID)
			m.scanCheckSources(spec)
		} else {
			logger.WithComponent("extmgr").Error("failed to read checks.json",
				"extension_id", spec.ID, "error", err)
		}
		return
	}

	var checkDefs []struct {
		ID          string  `json:"id"`
		Domain      string  `json:"domain"`
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Delta       float64 `json:"delta"`
		Command     string  `json:"command"`
		FilePath    string  `json:"file_path"`
		FileRegex   string  `json:"file_regex"`
		OutputMatch string  `json:"output_match"`
	}
	if err := json.Unmarshal(data, &checkDefs); err != nil {
		logger.WithComponent("extmgr").Error("invalid checks.json", "extension_id", spec.ID, "error", err)
		return
	}

	var items []model.CheckItem
	for _, def := range checkDefs {
		item := specCheckItem(def)
		items = append(items, item)
		logger.WithComponent("extmgr").Debug("registered check from extension",
			"extension_id", spec.ID, "check_id", def.ID, "domain", def.Domain)
	}
	if len(items) > 0 {
		checks.Register(items...)
	}
	logger.WithComponent("extmgr").Info("registered checks from extension",
		"extension_id", spec.ID, "count", len(items))
}

func specCheckItem(def struct {
	ID          string  `json:"id"`
	Domain      string  `json:"domain"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Delta       float64 `json:"delta"`
	Command     string  `json:"command"`
	FilePath    string  `json:"file_path"`
	FileRegex   string  `json:"file_regex"`
	OutputMatch string  `json:"output_match"`
}) model.CheckItem {
	return model.CheckItem{
		ID:          def.ID,
		Domain:      def.Domain,
		Name:        def.Name,
		Description: def.Description,
		Delta:       def.Delta,
		Check:       buildExtCheckFunc(def.Command, def.FilePath, def.FileRegex, def.OutputMatch),
	}
}

func buildExtCheckFunc(command, filePath, fileRegex, outputMatch string) model.CheckFunc {
	if command != "" {
		if !common.IsShellCommandAllowed(command) {
			logger.WithComponent("extmgr").Warn("extension check command rejected by global whitelist", "command", command)
			return func() (bool, string) {
				return false, "command rejected by global whitelist"
			}
		}
		return func() (bool, string) {
			cmd := exec.Command("sh", "-c", command)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return false, string(out)
			}
			if outputMatch != "" {
				if strings.Contains(string(out), outputMatch) {
					return true, string(out)
				}
				return false, string(out)
			}
			return true, string(out)
		}
	}
	if filePath != "" {
		return func() (bool, string) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return false, fmt.Sprintf("无法读取 %s: %v", filePath, err)
			}
			if fileRegex != "" {
				re, err := regexp.Compile(fileRegex)
				if err != nil {
					return false, fmt.Sprintf("正则表达式错误: %v", err)
				}
				if re.Match(data) {
					return true, string(data)
				}
				return false, fmt.Sprintf("%s 未匹配 %s", filePath, fileRegex)
			}
			return true, string(data)
		}
	}
	return func() (bool, string) { return false, "check has no command or file_path" }
}

func (m *ExtensionManager) scanCheckSources(spec ExtensionSpec) {
	checkDir := filepath.Join(spec.InstallPath, "checks")
	if _, err := os.Stat(checkDir); os.IsNotExist(err) {
		return
	}
	entries, err := os.ReadDir(checkDir)
	if err != nil {
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
			logger.WithComponent("extmgr").Debug("found check source in extension", "extension_id", spec.ID, "dir", entry.Name(), "file", f.Name())
		}
	}
}

func (m *ExtensionManager) executeHook(ctx context.Context, spec ExtensionSpec, result *model.AssessmentResult) error {
	_, err := m.executor.Execute(ctx, spec, []string{"--hook", "post_score"})
	return err
}

func (m *ExtensionManager) executeExtension(ctx context.Context, spec ExtensionSpec, action string) error {
	_, err := m.executor.Execute(ctx, spec, []string{"--action", action})
	if err != nil {
		m.fireExtensionEvent("extension.execution_error", spec.ID, err.Error())
	}
	return err
}

func (m *ExtensionManager) fireExtensionEvent(pointName, extID, errMsg string) {
	if m.kernelExtensions != nil {
		m.kernelExtensions.Execute(context.Background(), pointName, map[string]interface{}{
			"extension_id": extID,
			"error":        errMsg,
		})
	}
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
