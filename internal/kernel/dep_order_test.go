package kernel

import (
	"context"
	"testing"
)

type fakeDepPlugin struct {
	name string
	prio int
	deps []string
}

func (f *fakeDepPlugin) Info() PluginInfo { return PluginInfo{Name: f.name} }
func (f *fakeDepPlugin) Dependencies() []PluginDependency {
	out := make([]PluginDependency, 0, len(f.deps))
	for _, d := range f.deps {
		out = append(out, PluginDependency{Name: d})
	}
	return out
}
func (f *fakeDepPlugin) Priority() int                             { return f.prio }
func (f *fakeDepPlugin) Init(context.Context, KernelContext) error { return nil }
func (f *fakeDepPlugin) Start(context.Context) error               { return nil }
func (f *fakeDepPlugin) Stop(context.Context) error                { return nil }
func (f *fakeDepPlugin) State() PluginState                        { return PluginStarted }
func (f *fakeDepPlugin) HealthCheck(context.Context) error         { return nil }

func namesOf(recs []pluginRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.plugin.Info().Name)
	}
	return out
}

func recsOf(ps ...Plugin) []pluginRecord {
	out := make([]pluginRecord, 0, len(ps))
	for _, p := range ps {
		out = append(out, pluginRecord{plugin: p})
	}
	return out
}

// 依赖声明必须覆盖 Priority 数字：B 的 Priority 更小，但依赖 A，仍排在 A 之后。
func TestOrderPluginsDependencyOverridesPriority(t *testing.T) {
	a := &fakeDepPlugin{name: "a", prio: 90}
	b := &fakeDepPlugin{name: "b", prio: 10, deps: []string{"a"}}
	out := namesOf(orderPlugins(recsOf(a, b)))
	if out[0] != "a" || out[1] != "b" {
		t.Fatalf("dependency order failed: %v", out)
	}
}

// 无依赖时按 Priority 升序（数字越小越早启动）。
func TestOrderPluginsPriorityFallback(t *testing.T) {
	a := &fakeDepPlugin{name: "a", prio: 50}
	b := &fakeDepPlugin{name: "b", prio: 3}
	out := namesOf(orderPlugins(recsOf(a, b)))
	if out[0] != "b" || out[1] != "a" {
		t.Fatalf("priority order failed: %v", out)
	}
}

// 环依赖不能死锁/丢插件：回退到 Priority，并保留全部插件。
func TestOrderPluginsCycleFailsSafe(t *testing.T) {
	a := &fakeDepPlugin{name: "a", prio: 10, deps: []string{"b"}}
	b := &fakeDepPlugin{name: "b", prio: 20, deps: []string{"a"}}
	out := namesOf(orderPlugins(recsOf(a, b)))
	if len(out) != 2 {
		t.Fatalf("cycle lost plugins: %v", out)
	}
}
