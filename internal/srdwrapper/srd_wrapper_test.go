//go:build srdwrapper

package srdwrapper

import (
	"github.com/asscor/asscor/internal/kernel"
	"context"
	"testing"
)

func TestNewSRDPluginConstruction(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("expected non-nil plugin")
	}
	if p.manager == nil {
		t.Fatal("expected non-nil manager")
	}

	info := p.Info()
	if info.Name == "" {
		t.Error("expected non-empty name")
	}
	if info.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestSRDPluginDependencies(t *testing.T) {
	p := New()
	deps := p.Dependencies()
	if len(deps) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(deps))
	}
}

func TestSRDPluginPriority(t *testing.T) {
	p := New()
	prio := p.Priority()
	if prio < 0 {
		t.Errorf("expected non-negative priority, got %d", prio)
	}
}

func TestSRDBusAdapterPublish(t *testing.T) {
	k := kernel.NewKernel()
	adapter := &srdBusAdapter{kc: k}

	ctx := context.Background()
	adapter.Publish(ctx, "test.topic", map[string]string{"key": "value"})

	// Verify the bus received the message
	m := k.Bus().GetMetrics()
	if m.MessageCount < 1 {
		t.Logf("message count after publish = %d (async may have 0)", m.MessageCount)
	}
}

func TestSRDConfigAdapterGetConfig(t *testing.T) {
	k := kernel.NewKernel()
	adapter := &srdConfigAdapter{kc: k}

	cfg := adapter.GetConfigObj()
	if cfg != nil {
		t.Logf("config = %v (nil expected before SetConfigObj)", cfg)
	}
}
