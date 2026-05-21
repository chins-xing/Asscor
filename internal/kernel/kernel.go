package kernel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/logger"
)

type Kernel struct {
	plugins   map[string]pluginRecord
	di        *Container
	bus       *Bus
	extPoints *ExtensionRegistry

	config map[string]string
	cfg    *config.Config

	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

type pluginRecord struct {
	plugin     Plugin
	registered time.Time
}

func NewKernel() *Kernel {
	ctx, cancel := context.WithCancel(context.Background())
	k := &Kernel{
		plugins:   make(map[string]pluginRecord),
		di:        NewContainer(),
		bus:       NewBus(512),
		extPoints: NewExtensionRegistry(),
		config:    make(map[string]string),
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.pre_init",
		Description: "Called before all plugins are initialized",
		Version:     "1.0",
	})
	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.post_init",
		Description: "Called after all plugins have been initialized",
		Version:     "1.0",
	})
	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.pre_start",
		Description: "Called before all plugins are started",
		Version:     "1.0",
	})
	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.post_start",
		Description: "Called after all plugins have started",
		Version:     "1.0",
	})
	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.pre_stop",
		Description: "Called before shutdown sequence begins",
		Version:     "1.0",
	})
	k.extPoints.RegisterPoint(ExtensionPoint{
		Name:        "kernel.post_stop",
		Description: "Called after all plugins have stopped",
		Version:     "1.0",
	})

	return k
}

func (k *Kernel) Container() *Container {
	return k.di
}

func (k *Kernel) Bus() *Bus {
	return k.bus
}

func (k *Kernel) Extensions() *ExtensionRegistry {
	return k.extPoints
}

func (k *Kernel) Context() context.Context {
	return k.ctx
}

func (k *Kernel) Config() map[string]string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	cp := make(map[string]string, len(k.config))
	for k, v := range k.config {
		cp[k] = v
	}
	return cp
}

func (k *Kernel) SetConfig(key, value string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.config[key] = value
}

func (k *Kernel) SetConfigObj(c *config.Config) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cfg = c
}

func (k *Kernel) RegisterPlugin(p Plugin) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	info := p.Info()
	if info.Name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}
	if _, exists := k.plugins[info.Name]; exists {
		return fmt.Errorf("plugin %s is already registered", info.Name)
	}

	k.plugins[info.Name] = pluginRecord{
		plugin:     p,
		registered: time.Now(),
	}

	logger.With("component", "kernel").Info("plugin registered", "name", info.Name, "version", info.Version)
	return nil
}

func (k *Kernel) UnregisterPlugin(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	rec, exists := k.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	if rec.plugin.State() == PluginStarted {
		go func() {
			_ = rec.plugin.Stop(k.ctx)
		}()
	}

	k.extPoints.UnregisterPlugin(name)
	k.bus.UnsubscribeAll(name)
	delete(k.plugins, name)

	logger.With("component", "kernel").Info("plugin unregistered", "name", name)
	return nil
}

func (k *Kernel) GetPlugin(name string) (Plugin, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	rec, ok := k.plugins[name]
	if !ok {
		return nil, false
	}
	return rec.plugin, true
}

func (k *Kernel) ListPlugins() []PluginInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(k.plugins))
	for _, rec := range k.plugins {
		infos = append(infos, rec.plugin.Info())
	}
	return infos
}

func (k *Kernel) Bootstrap() error {
	k.mu.RLock()
	plugins := make([]pluginRecord, 0, len(k.plugins))
	for _, rec := range k.plugins {
		plugins = append(plugins, rec)
	}
	k.mu.RUnlock()

	sort.Slice(plugins, func(i, j int) bool {
		pi, pj := plugins[i].plugin, plugins[j].plugin
		if ppi, ok := pi.(PriorityPlugin); ok {
			if ppj, ok := pj.(PriorityPlugin); ok {
				return ppi.Priority() < ppj.Priority()
			}
			return true
		}
		if _, ok := pj.(PriorityPlugin); ok {
			return false
		}
		return pi.Info().Name < pj.Info().Name
	})

	k.extPoints.Execute(k.ctx, "kernel.pre_init", nil)

	for _, rec := range plugins {
		if cfg, ok := rec.plugin.(ConfigurablePlugin); ok {
			if err := cfg.Configure(k.config); err != nil {
				logger.With("component", "kernel").Warn("configure plugin failed", "plugin", rec.plugin.Info().Name, "error", err)
			}
		}

		for _, dep := range rec.plugin.Dependencies() {
			if dep.Interface != nil {
				impl, ok := k.di.Resolve(dep.Interface)
				if ok {
					k.di.Bind(dep.Interface, impl)
				}
			} else if dep.Name != "" {
				impl, ok := k.di.ResolveNamed(dep.Name)
				if ok {
					k.di.BindNamed(dep.Name, dep.Interface, impl)
				}
			}
		}

		if err := rec.plugin.Init(k.ctx, k); err != nil {
			return fmt.Errorf("init plugin %s: %w", rec.plugin.Info().Name, err)
		}
		logger.With("component", "kernel").Info("plugin initialized", "plugin", rec.plugin.Info().Name)
	}

	k.extPoints.Execute(k.ctx, "kernel.post_init", nil)

	k.extPoints.Execute(k.ctx, "kernel.pre_start", nil)

	for _, rec := range plugins {
		if err := rec.plugin.Start(k.ctx); err != nil {
			return fmt.Errorf("start plugin %s: %w", rec.plugin.Info().Name, err)
		}
		logger.With("component", "kernel").Info("plugin started", "plugin", rec.plugin.Info().Name)
	}

	k.extPoints.Execute(k.ctx, "kernel.post_start", nil)

	slog.Info("kernel: all plugins started successfully")
	return nil
}

func (k *Kernel) Shutdown() error {
	slog.Info("kernel: shutting down")

	k.extPoints.Execute(k.ctx, "kernel.pre_stop", nil)

	k.mu.RLock()
	plugins := make([]pluginRecord, 0, len(k.plugins))
	for _, rec := range k.plugins {
		plugins = append(plugins, rec)
	}
	k.mu.RUnlock()

	sort.Slice(plugins, func(i, j int) bool {
		pi, pj := plugins[i].plugin, plugins[j].plugin
		if ppi, ok := pi.(PriorityPlugin); ok {
			if ppj, ok := pj.(PriorityPlugin); ok {
				return ppi.Priority() > ppj.Priority()
			}
			return false
		}
		if _, ok := pj.(PriorityPlugin); ok {
			return true
		}
		return pi.Info().Name > pj.Info().Name
	})

	for _, rec := range plugins {
		if rec.plugin.State() != PluginStarted {
			continue
		}
		if err := rec.plugin.Stop(k.ctx); err != nil {
			logger.With("component", "kernel").Error("error stopping plugin", "plugin", rec.plugin.Info().Name, "error", err)
		}
		logger.With("component", "kernel").Info("plugin stopped", "plugin", rec.plugin.Info().Name)
	}

	k.cancel()

	k.extPoints.Execute(k.ctx, "kernel.post_stop", nil)

	k.closeOnce.Do(func() {
		close(k.done)
	})
	slog.Info("kernel: shutdown complete")
	return nil
}

func (k *Kernel) Run() error {
	if err := k.Bootstrap(); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		slog.Info("kernel: received signal", "signal", sig.String())
	case <-k.done:
	}

	return k.Shutdown()
}

func (k *Kernel) Wait() {
	<-k.done
}

func (k *Kernel) IsRunning() bool {
	select {
	case <-k.done:
		return false
	default:
		return true
	}
}