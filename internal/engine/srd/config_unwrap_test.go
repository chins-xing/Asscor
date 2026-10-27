//go:build engine

package srd

import (
	"testing"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
)

// fakeConfigGetter 模拟 srdwrapper.srdConfigAdapter 这样的适配器层：
// 它自己不是 *config.Config，只能通过 GetConfigObj() 继续解包。
type fakeConfigGetter struct{ inner interface{} }

func (f fakeConfigGetter) GetConfigObj() interface{} { return f.inner }

// TestUnwrapConfigReachesRealConfig 钉住审计 A-1 的根因：
// kc.GetConfigObj() 返回的是适配器，直接交给 loadConfig 会让所有类型断言落空。
func TestUnwrapConfigReachesRealConfig(t *testing.T) {
	cfg := &kernelconfig.Config{AdapterConfig: map[string]string{
		"srd.layered_graph":  "false",
		"srd.transmission":   "0.42",
		"srd.max_path_depth": "7",
	}}
	wrapped := fakeConfigGetter{inner: fakeConfigGetter{inner: cfg}}

	got := unwrapConfig(wrapped)
	if got != interface{}(cfg) {
		t.Fatalf("unwrapConfig 应返回真正的 *config.Config，got %T", got)
	}

	m := NewManager()
	m.loadConfig(got)
	if m.cfg.LayeredGraph {
		t.Error("layered_graph=false 未生效（A-1 未修）")
	}
	if m.cfg.DefaultTransmission != 0.42 {
		t.Errorf("transmission=%v want 0.42", m.cfg.DefaultTransmission)
	}
	if m.cfg.MaxPathDepth != 7 {
		t.Errorf("max_path_depth=%d want 7", m.cfg.MaxPathDepth)
	}
}

// 无适配器时原样返回；nil 保持 nil。
func TestUnwrapConfigPassthrough(t *testing.T) {
	cfg := &kernelconfig.Config{}
	if got := unwrapConfig(cfg); got != interface{}(cfg) {
		t.Fatalf("普通配置应原样返回，got %T", got)
	}
	if got := unwrapConfig(nil); got != nil {
		t.Fatalf("nil 应返回 nil，got %v", got)
	}
}
