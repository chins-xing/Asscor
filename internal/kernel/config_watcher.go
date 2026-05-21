package kernel

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/logger"
)

type ConfigWatcherModule struct {
	kernel     *Kernel
	configPath string
	interval   time.Duration

	mu       sync.RWMutex
	lastMod  time.Time
	state    PluginState
	assessor *AssessorModule
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

func (m *ConfigWatcherModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.state = PluginInitialized

	if p, ok := k.GetPlugin("assessor"); ok {
		if am, ok2 := p.(*AssessorModule); ok2 {
			m.assessor = am
		} else {
			logger.With("component", "config_watcher").Warn("assessor plugin has unexpected type")
		}
	}

	info, err := os.Stat(m.configPath)
	if err == nil {
		m.lastMod = info.ModTime()
	}

	return nil
}

func (m *ConfigWatcherModule) Start(ctx context.Context) error {
	m.state = PluginStarted

	go m.watchLoop()
	go m.sighupLoop()

	logger.With("component", "config_watcher").Info("started",
		"config_path", m.configPath,
		"poll_interval", m.interval.String())

	return nil
}

func (m *ConfigWatcherModule) Stop(ctx context.Context) error {
	m.state = PluginStopped
	logger.With("component", "config_watcher").Info("stopped")
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
			logger.With("component", "config_watcher").Info("SIGHUP received, forcing config reload")
			m.forceReload()
		}
	}
}

func (m *ConfigWatcherModule) checkAndReload() {
	info, err := os.Stat(m.configPath)
	if err != nil {
		logger.With("component", "config_watcher").Warn("cannot stat config file", "path", m.configPath, "error", err)
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

func (m *ConfigWatcherModule) forceReload() {
	cfg, err := config.Load(m.configPath)
	if err != nil {
		logger.With("component", "config_watcher").Error("failed to reload config", "path", m.configPath, "error", err)
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

	logger.With("component", "config_watcher").Info("config reloaded",
		"path", m.configPath,
		"weights", cfg.Weights,
		"threshold", cfg.Threshold)
}
