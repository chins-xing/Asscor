package kernel

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"syscall"

	"github.com/asscor/asscor/internal/logger"
)

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
				logger.WithComponent("kernel").Warn("configure plugin failed", "plugin", rec.plugin.Info().Name, "error", err)
			}
		}

		for _, dep := range rec.plugin.Dependencies() {
			if dep.Interface != nil {
				if _, ok := k.di.Resolve(dep.Interface); !ok {
					ifaceType := reflect.TypeOf(dep.Interface)
					if ifaceType.Kind() == reflect.Ptr {
						ifaceType = ifaceType.Elem()
					}
					logger.WithComponent("kernel").Warn("dependency not resolved", "plugin", rec.plugin.Info().Name, "interface", ifaceType.String())
				}
			} else if dep.Name != "" {
				if _, ok := k.di.ResolveNamed(dep.Name); !ok {
					logger.WithComponent("kernel").Warn("named dependency not resolved", "plugin", rec.plugin.Info().Name, "name", dep.Name)
				}
			}
		}

		if err := rec.plugin.Init(k.ctx, k); err != nil {
			return fmt.Errorf("init plugin %s: %w", rec.plugin.Info().Name, err)
		}
		logger.WithComponent("kernel").Info("plugin initialized", "plugin", rec.plugin.Info().Name)
	}

	k.extPoints.Execute(k.ctx, "kernel.post_init", nil)

	k.extPoints.Execute(k.ctx, "kernel.pre_start", nil)

	for _, rec := range plugins {
		if err := rec.plugin.Start(k.ctx); err != nil {
			return fmt.Errorf("start plugin %s: %w", rec.plugin.Info().Name, err)
		}
		logger.WithComponent("kernel").Info("plugin started", "plugin", rec.plugin.Info().Name)
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
			logger.WithComponent("kernel").Error("error stopping plugin", "plugin", rec.plugin.Info().Name, "error", err)
		}
		logger.WithComponent("kernel").Info("plugin stopped", "plugin", rec.plugin.Info().Name)
	}

	k.cancel()

	k.bus.Stop()

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
