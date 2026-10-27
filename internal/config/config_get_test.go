package config

import "testing"

// TestGetExposesSectionKeys 钉住 v2.2 的修复：
// SRD 的 loadConfig 通过 `interface{ Get(string) string }` 读配置；
// Config 之前没有 Get 方法，导致 [srd] 全部配置被静默忽略。
func TestGetExposesSectionKeys(t *testing.T) {
	cfg, err := Parse(`[srd]
layered_graph = false
transmission = 0.42
max_path_depth = 7
path_decay = 0.6
prop_cap = 0.4
aggregation = max
horizon_days = 14
roles = domA-db=db,domC-router=router
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := map[string]string{
		"srd.layered_graph": "false",
		"srd.transmission":  "0.42",
		"srd.max_path_depth": "7",
		"srd.path_decay":    "0.6",
		"srd.prop_cap":      "0.4",
		"srd.aggregation":   "max",
		"srd.horizon_days":  "14",
		"srd.roles":         "domA-db=db,domC-router=router",
	}
	for k, want := range cases {
		if got := cfg.Get(k); got != want {
			t.Errorf("Get(%q)=%q want %q", k, got, want)
		}
	}
	if got := cfg.Get("no.such.key"); got != "" {
		t.Errorf("未知键应返回空串，got %q", got)
	}
	var nilCfg *Config
	if got := nilCfg.Get("srd.layered_graph"); got != "" {
		t.Errorf("nil Config 应返回空串，got %q", got)
	}
}
