package kernel

import (
	"context"
	"testing"
)

func TestNewKernelDefaults(t *testing.T) {
	k := NewKernel()

	if k.Container() == nil {
		t.Error("Container should not be nil")
	}
	if k.Bus() == nil {
		t.Error("Bus should not be nil")
	}
	if k.Extensions() == nil {
		t.Error("Extensions should not be nil")
	}
	if k.Context() == nil {
		t.Error("Context should not be nil")
	}
	if k.GetConfigObj() != nil {
		t.Error("ConfigObj should be nil before SetConfigObj")
	}
}

func TestKernelPluginRegistration(t *testing.T) {
	k := NewKernel()

	p := &mockPlugin{name: "test-plugin", version: "1.0", state: PluginUnregistered}
	k.RegisterPlugin(p)

	list := k.ListPlugins()
	found := false
	for _, pi := range list {
		if pi.Name == "test-plugin" {
			found = true
			if pi.Version != "1.0" {
				t.Errorf("Version = %s, want 1.0", pi.Version)
			}
		}
	}
	if !found {
		t.Error("expected test-plugin in plugin list")
	}
}

func TestKernelDuplicatePluginRegistration(t *testing.T) {
	k := NewKernel()

	p1 := &mockPlugin{name: "dup", version: "1.0", state: PluginUnregistered}
	p2 := &mockPlugin{name: "dup", version: "2.0", state: PluginUnregistered}

	k.RegisterPlugin(p1)
	k.RegisterPlugin(p2)

	list := k.ListPlugins()
	count := 0
	for _, pi := range list {
		if pi.Name == "dup" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 plugin named 'dup', got %d", count)
	}
}

func TestKernelConfig(t *testing.T) {
	k := NewKernel()

	k.SetConfig("key1", "value1")
	k.SetConfig("key2", "value2")

	if v := k.Config()["key1"]; v != "value1" {
		t.Errorf("Config[key1] = %s, want value1", v)
	}
	if v := k.Config()["key2"]; v != "value2" {
		t.Errorf("Config[key2] = %s, want value2", v)
	}
}

func TestKernelHealthCheck(t *testing.T) {
	k := NewKernel()

	p := &mockPlugin{name: "health-check", version: "1.0", state: PluginUnregistered}
	k.RegisterPlugin(p)

	statuses := k.HealthCheck(context.Background())
	if len(statuses) != 1 {
		t.Fatalf("expected 1 health status, got %d", len(statuses))
	}
	// Uninitialized plugin should report error
	if statuses[0].Name != "health-check" {
		t.Errorf("Name = %s, want health-check", statuses[0].Name)
	}
}

func TestKernelGetPlugin(t *testing.T) {
	k := NewKernel()

	p := &mockPlugin{name: "find-me", version: "1.0", state: PluginUnregistered}
	k.RegisterPlugin(p)

	found, ok := k.GetPlugin("find-me")
	if !ok {
		t.Fatal("expected to find plugin")
	}
	if found.Info().Name != "find-me" {
		t.Errorf("Info().Name = %s, want find-me", found.Info().Name)
	}

	_, ok = k.GetPlugin("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent plugin")
	}
}
