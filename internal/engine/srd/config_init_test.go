//go:build engine

package srd

import (
	"context"
	"testing"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
)

type fakeBus struct{}

func (fakeBus) Publish(context.Context, string, interface{}) {}

type fakeKernelContext struct{ cfg interface{} }

func (fakeKernelContext) Context() context.Context { return context.Background() }
func (fakeKernelContext) Bus() BusAccess           { return fakeBus{} }
func (f fakeKernelContext) GetConfigObj() ConfigGetter {
	return fakeConfigGetter{inner: f.cfg}
}

// TestManagerInitAppliesConfig 是审计 A-9 要求的**集成测试**：
// 从 KernelContext（适配器）一路到 Manager.Init → loadConfig → cfg 生效，
// 覆盖 A-1（适配器解包）与 A-2（[srd] 键可达）两个缺陷的完整链路。
func TestManagerInitAppliesConfig(t *testing.T) {
	cfg := &kernelconfig.Config{AdapterConfig: map[string]string{
		"srd.layered_graph":  "false",
		"srd.transmission":   "0.42",
		"srd.max_path_depth": "7",
		"srd.aggregation":    "max",
		"srd.roles":          "domA-db=db",
	}}
	m := NewManager()
	if err := m.Init(context.Background(), fakeKernelContext{cfg: cfg}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if m.cfg.LayeredGraph {
		t.Error("layered_graph=false 未通过 Init 生效（A-1/A-9 回归）")
	}
	if m.cfg.DefaultTransmission != 0.42 || m.cfg.MaxPathDepth != 7 || m.cfg.AggregationMode != "max" {
		t.Errorf("参数未生效: %+v", m.cfg)
	}
	if m.cfg.Roles["domA-db"] != "db" {
		t.Errorf("roles 未生效: %+v", m.cfg.Roles)
	}
	if m.pipeline == nil {
		t.Fatal("Init 后 pipeline 不应为 nil")
	}
}

// 配置对象为 nil 时 Init 必须仍然成功（用默认值），不能 panic。
func TestManagerInitWithoutConfig(t *testing.T) {
	m := NewManager()
	if err := m.Init(context.Background(), fakeKernelContext{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !m.cfg.LayeredGraph {
		t.Error("无配置时应使用默认 layered_graph=true")
	}
}
