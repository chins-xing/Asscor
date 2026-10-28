package kernel

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"syscall"

	"github.com/chins-xing/asscor/internal/logger"
)

func (k *Kernel) Bootstrap() error {
	k.mu.RLock()
	plugins := make([]pluginRecord, 0, len(k.plugins))
	for _, rec := range k.plugins {
		plugins = append(plugins, rec)
	}
	k.mu.RUnlock()

	plugins = orderPlugins(plugins)

	// 记录启动顺序：Shutdown 必须反序停止（先启动的后停止）。
	k.mu.Lock()
	k.startupOrder = make([]string, 0, len(plugins))
	for _, rec := range plugins {
		k.startupOrder = append(k.startupOrder, rec.plugin.Info().Name)
	}
	k.mu.Unlock()

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

	plugins = k.shutdownOrder(plugins)

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

// priorityOf 返回插件的启动优先级（未实现 PriorityPlugin 视为 0）。
func priorityOf(p Plugin) int {
	if pp, ok := p.(PriorityPlugin); ok {
		return pp.Priority()
	}
	return 0
}

// orderPlugins 按 Dependencies().Name 做拓扑排序，Priority（升序）与名称作为
// 同级排序键；依赖缺失或出现环时回退到纯 Priority 顺序并告警。
//
// 语义：Name 依赖指向已注册插件的 Info().Name，表示"该插件必须先于本插件启动"。
// Interface 依赖仍由 Bootstrap 的 Resolve 检查（它只做校验，不参与排序）。
func orderPlugins(plugins []pluginRecord) []pluginRecord {
	n := len(plugins)
	if n <= 1 {
		return plugins
	}
	byName := make(map[string]int, n)
	for i, rec := range plugins {
		byName[rec.plugin.Info().Name] = i
	}

	deps := make([][]int, n) // deps[i] = 必须先于 i 启动的插件下标
	indeg := make([]int, n)
	for i, rec := range plugins {
		for _, dep := range rec.plugin.Dependencies() {
			if dep.Name == "" || dep.Interface != nil {
				continue
			}
			j, ok := byName[dep.Name]
			if !ok || j == i {
				continue
			}
			deps[j] = append(deps[j], i)
			indeg[i]++
		}
	}

	less := func(a, b int) bool {
		pa, pb := priorityOf(plugins[a].plugin), priorityOf(plugins[b].plugin)
		if pa != pb {
			return pa < pb
		}
		return plugins[a].plugin.Info().Name < plugins[b].plugin.Info().Name
	}

	ready := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if indeg[i] == 0 {
			ready = append(ready, i)
		}
	}
	out := make([]pluginRecord, 0, n)
	for len(ready) > 0 {
		best := 0
		for i := 1; i < len(ready); i++ {
			if less(ready[i], ready[best]) {
				best = i
			}
		}
		idx := ready[best]
		ready = append(ready[:best], ready[best+1:]...)
		out = append(out, plugins[idx])
		for _, nxt := range deps[idx] {
			indeg[nxt]--
			if indeg[nxt] == 0 {
				ready = append(ready, nxt)
			}
		}
	}

	if len(out) != n {
		// 环或缺失依赖：剩余的按纯 Priority 顺序追加，保证仍能启动。
		remaining := make([]int, 0, n-len(out))
		seen := make(map[int]bool, len(out))
		for _, rec := range out {
			seen[byName[rec.plugin.Info().Name]] = true
		}
		for i := 0; i < n; i++ {
			if !seen[i] {
				remaining = append(remaining, i)
			}
		}
		sort.Slice(remaining, func(a, b int) bool { return less(remaining[a], remaining[b]) })
		for _, i := range remaining {
			logger.WithComponent("kernel").Warn("plugin dependency cycle or unresolved dependency; falling back to priority order",
				"plugin", plugins[i].plugin.Info().Name)
			out = append(out, plugins[i])
		}
	}
	return out
}

// shutdownOrder 按启动顺序反序返回；没有记录时回退到 Priority 降序。
func (k *Kernel) shutdownOrder(plugins []pluginRecord) []pluginRecord {
	k.mu.RLock()
	order := append([]string(nil), k.startupOrder...)
	k.mu.RUnlock()
	if len(order) == 0 {
		sort.Slice(plugins, func(i, j int) bool {
			pi, pj := plugins[i].plugin, plugins[j].plugin
			return priorityOf(pi) > priorityOf(pj)
		})
		return plugins
	}
	byName := make(map[string]pluginRecord, len(plugins))
	for _, rec := range plugins {
		byName[rec.plugin.Info().Name] = rec
	}
	out := make([]pluginRecord, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		if rec, ok := byName[order[i]]; ok {
			out = append(out, rec)
		}
	}
	// 兜底：未出现在记录中的插件（理论上不会发生）追加在后。
	for _, rec := range plugins {
		found := false
		for _, name := range order {
			if rec.plugin.Info().Name == name {
				found = true
				break
			}
		}
		if !found {
			out = append(out, rec)
		}
	}
	return out
}
