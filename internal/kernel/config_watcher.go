package kernel

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/logger"
)

type ConfigWatcherModule struct {
	kernel     KernelContext
	configPath string
	interval   time.Duration

	mu       sync.RWMutex
	lastMod  time.Time
	state    PluginState
	assessor AssessorInterface
}

func NewConfigWatcherModule(configPath string) *ConfigWatcherModule {
	return &ConfigWatcherModule{
		configPath: configPath,
		interval:   30 * time.Second,
	}
}

func (m *ConfigWatcherModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "config_watcher",
		Version:     "1.0.0",
		Description: "Watches config.ini for changes and hot-reloads weights and parameters",
		Author:      "ARGUS Core Team",
	}
}

func (m *ConfigWatcherModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "assessor", Interface: (*AssessorInterface)(nil)},
	}
}

func (m *ConfigWatcherModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

	if impl, ok := kc.Container().Resolve((*AssessorInterface)(nil)); ok {
		if a, ok2 := impl.(AssessorInterface); ok2 {
			m.assessor = a
		} else {
			logger.WithComponent("config_watcher").Warn("assessor has unexpected type in DI container")
		}
	}

	cfg := kc.GetConfigObj()
	if cfg != nil && cfg.HotloadIntervalS > 0 {
		m.interval = time.Duration(cfg.HotloadIntervalS) * time.Second
	}

	m.resolveConfigPath()

	info, err := os.Stat(m.configPath)
	if err == nil {
		m.lastMod = info.ModTime()
	} else {
		logger.WithComponent("config_watcher").Warn("config file not found at resolved path", "path", m.configPath, "error", err)
	}

	return nil
}

func (m *ConfigWatcherModule) Start(ctx context.Context) error {
	m.state = PluginStarted

	hotloadEnabled := true
	if cfg := m.kernel.GetConfigObj(); cfg != nil {
		hotloadEnabled = cfg.HotloadEnabled
	}

	if hotloadEnabled {
		go m.watchLoop()
	}

	go m.sighupLoop()

	logger.WithComponent("config_watcher").Info("started",
		"config_path", m.configPath,
		"hotload_enabled", hotloadEnabled,
		"poll_interval", m.interval.String())

	return nil
}

func (m *ConfigWatcherModule) Stop(ctx context.Context) error {
	m.state = PluginStopped
	logger.WithComponent("config_watcher").Info("stopped")
	return nil
}

func (m *ConfigWatcherModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *ConfigWatcherModule) watchLoop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-ticker.C:
			m.checkAndReload()
		}
	}
}

func (m *ConfigWatcherModule) sighupLoop() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-sigCh:
			logger.WithComponent("config_watcher").Info("SIGHUP received, forcing config reload")
			m.forceReload()
		}
	}
}

func (m *ConfigWatcherModule) checkAndReload() {
	info, err := os.Stat(m.configPath)
	if err != nil {
		logger.WithComponent("config_watcher").Warn("cannot stat config file", "path", m.configPath, "error", err)
		return
	}

	m.mu.RLock()
	lastMod := m.lastMod
	m.mu.RUnlock()

	if !info.ModTime().After(lastMod) {
		return
	}

	m.forceReload()
}

func (m *ConfigWatcherModule) resolveConfigPath() {
	if filepath.IsAbs(m.configPath) {
		return
	}

	if _, err := os.Stat(m.configPath); err == nil {
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		return
	}
	exeDir := filepath.Dir(exePath)
	candidate := filepath.Join(exeDir, m.configPath)
	if _, err := os.Stat(candidate); err == nil {
		m.configPath = candidate
		logger.WithComponent("config_watcher").Info("resolved config path from executable directory", "path", m.configPath)
		return
	}

	wd, _ := os.Getwd()
	candidate = filepath.Join(wd, m.configPath)
	if abs, err := filepath.Abs(candidate); err == nil {
		m.configPath = abs
	}
}

func (m *ConfigWatcherModule) forceReload() {
	cfg, err := config.Load(m.configPath)
	if err != nil {
		logger.WithComponent("config_watcher").Error("failed to reload config", "path", m.configPath, "error", err)
		return
	}

	m.mu.Lock()
	m.lastMod = time.Now()
	m.mu.Unlock()

	m.kernel.SetConfigObj(cfg)

	if m.assessor != nil {
		m.assessor.ReloadConfig(cfg)
	}

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "config.reloaded",
		Payload: map[string]interface{}{"path": m.configPath},
		Source:  "config_watcher",
	})

	logger.WithComponent("config_watcher").Info("config reloaded",
		"path", m.configPath,
		"weights", cfg.Weights,
		"threshold", cfg.Threshold)
}
