//go:build engine

package srd

import (
	"testing"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
)

// TestLoadConfigParsesAllAdjustableParams 钉住 v2.2 的可调参数接线：
// config.ini [srd] 的每个参数都要能落进 Manager.cfg 并影响 prism。
func TestLoadConfigParsesAllAdjustableParams(t *testing.T) {
	cfg := &kernelconfig.Config{AdapterConfig: map[string]string{
		"srd.layered_graph":   "false",
		"srd.transmission":    "0.42",
		"srd.max_path_depth":  "7",
		"srd.path_decay":      "0.6",
		"srd.prop_cap":        "0.4",
		"srd.aggregation":     "max",
		"srd.horizon_days":    "14",
		"srd.sync_interval_sec": "120",
		"srd.roles":           "domA-db=db,domC-router=router",
	}}
	m := NewManager()
	m.loadConfig(cfg)

	if m.cfg.LayeredGraph {
		t.Error("layered_graph=false 未生效")
	}
	if m.cfg.DefaultTransmission != 0.42 {
		t.Errorf("transmission=%v want 0.42", m.cfg.DefaultTransmission)
	}
	if m.cfg.MaxPathDepth != 7 {
		t.Errorf("max_path_depth=%d want 7", m.cfg.MaxPathDepth)
	}
	if m.cfg.PathDecay != 0.6 {
		t.Errorf("path_decay=%v want 0.6", m.cfg.PathDecay)
	}
	if m.cfg.PropCap != 0.4 {
		t.Errorf("prop_cap=%v want 0.4", m.cfg.PropCap)
	}
	if m.cfg.AggregationMode != "max" {
		t.Errorf("aggregation=%q want max", m.cfg.AggregationMode)
	}
	if m.cfg.HorizonDays != 14 {
		t.Errorf("horizon_days=%d want 14", m.cfg.HorizonDays)
	}
	if m.cfg.SyncIntervalSec != 120 {
		t.Errorf("sync_interval_sec=%d want 120", m.cfg.SyncIntervalSec)
	}
	if m.cfg.Roles["domA-db"] != "db" || m.cfg.Roles["domC-router"] != "router" {
		t.Errorf("roles 未解析: %+v", m.cfg.Roles)
	}
}

// 非法值应被忽略（保持默认），不 panic、不写入垃圾。
func TestLoadConfigIgnoresInvalidValues(t *testing.T) {
	cfg := &kernelconfig.Config{AdapterConfig: map[string]string{
		"srd.transmission":    "-5",
		"srd.max_path_depth":  "abc",
		"srd.path_decay":      "2",
		"srd.prop_cap":        "-1",
		"srd.aggregation":     "bogus",
		"srd.horizon_days":    "0",
		"srd.layered_graph":   "true",
	}}
	m := NewManager()
	before := m.cfg
	m.loadConfig(cfg)
	if !m.cfg.LayeredGraph {
		t.Error("layered_graph=true 应打开")
	}
	if m.cfg.DefaultTransmission != before.DefaultTransmission ||
		m.cfg.MaxPathDepth != before.MaxPathDepth ||
		m.cfg.PathDecay != before.PathDecay ||
		m.cfg.PropCap != before.PropCap ||
		m.cfg.AggregationMode != before.AggregationMode ||
		m.cfg.HorizonDays != before.HorizonDays {
		t.Errorf("非法值不应覆盖默认: %+v", m.cfg)
	}
}

// PrismConfigFrom 必须把 SRD 参数完整映射到 prism 引擎配置。
func TestPrismConfigFromMapsParams(t *testing.T) {
	cfg := Config{
		MaxPathDepth: 9, PathDecay: 0.55, PropCap: 0.11,
		AggregationMode: "linear", HorizonDays: 21,
	}
	pc := PrismConfigFrom(cfg)
	if pc.MaxPathDepth != 9 || pc.PathDecay != 0.55 || pc.PropCap != 0.11 ||
		pc.AggregationMode != "linear" || pc.HorizonDays != 21 {
		t.Fatalf("映射不完整: %+v", pc)
	}
	// 零值/越界回落到 prism 默认
	def := PrismConfigFrom(Config{})
	if def.MaxPathDepth <= 0 || def.PathDecay <= 0 || def.AggregationMode == "" {
		t.Fatalf("零值应回落到 prism 默认: %+v", def)
	}
}
