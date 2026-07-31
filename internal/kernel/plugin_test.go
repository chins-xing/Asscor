package kernel

import (
	"context"
	"sort"
	"testing"
)

func TestPluginStateString(t *testing.T) {
	tests := []struct {
		state PluginState
		want  string
	}{
		{PluginUnregistered, "unregistered"},
		{PluginRegistered, "registered"},
		{PluginInitialized, "initialized"},
		{PluginStarted, "started"},
		{PluginStopping, "stopping"},
		{PluginStopped, "stopped"},
		{PluginFailed, "failed"},
		{PluginState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("PluginState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestPluginStateOrdering(t *testing.T) {
	states := []PluginState{
		PluginUnregistered,
		PluginRegistered,
		PluginInitialized,
		PluginStarted,
		PluginStopping,
		PluginStopped,
		PluginFailed,
	}

	names := make([]string, len(states))
	for i, s := range states {
		names[i] = s.String()
	}

	sort.Strings(names)

	expected := []string{"failed", "initialized", "registered", "started", "stopped", "stopping", "unregistered"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("sorted[%d] = %q, want %q", i, names[i], want)
		}
	}
}

type mockPlugin struct {
	name    string
	version string
	initErr error
	state   PluginState
}

func (p *mockPlugin) Info() PluginInfo {
	return PluginInfo{Name: p.name, Version: p.version}
}
func (p *mockPlugin) Dependencies() []PluginDependency { return nil }
func (p *mockPlugin) Init(ctx context.Context, kc KernelContext) error {
	p.state = PluginInitialized
	return p.initErr
}
func (p *mockPlugin) Start(ctx context.Context) error {
	p.state = PluginStarted
	return nil
}
func (p *mockPlugin) Stop(ctx context.Context) error {
	p.state = PluginStopped
	return nil
}
func (p *mockPlugin) State() PluginState { return p.state }

func TestPluginLifecycle(t *testing.T) {
	p := &mockPlugin{name: "test", version: "1.0"}
	ctx := context.Background()

	if p.State() != PluginUnregistered {
		t.Errorf("initial state = %s, want unregistered", p.State())
	}

	p.Init(ctx, nil)
	if p.State() != PluginInitialized {
		t.Errorf("after Init = %s, want initialized", p.State())
	}

	p.Start(ctx)
	if p.State() != PluginStarted {
		t.Errorf("after Start = %s, want started", p.State())
	}

	p.Stop(ctx)
	if p.State() != PluginStopped {
		t.Errorf("after Stop = %s, want stopped", p.State())
	}
}

func TestPluginInfo(t *testing.T) {
	p := &mockPlugin{name: "test-plugin", version: "2.3.4"}
	info := p.Info()

	if info.Name != "test-plugin" {
		t.Errorf("Name = %q, want test-plugin", info.Name)
	}
	if info.Version != "2.3.4" {
		t.Errorf("Version = %q, want 2.3.4", info.Version)
	}
}
