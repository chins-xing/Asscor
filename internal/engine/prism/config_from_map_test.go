//go:build engine

package prism

import "testing"

// v2.3.6：prism 的 13 个参数必须都能从配置读取。
func TestConfigFromMapAllParams(t *testing.T) {
	m := map[string]string{
		"prism.debt_alpha":          "1.8",
		"prism.prop_cap":            "0.4",
		"prism.debt_cap":            "0.5",
		"prism.debt_norm_days":      "900",
		"prism.path_decay":          "0.6",
		"prism.max_path_depth":      "8",
		"prism.score_floor":         "0.2",
		"prism.collapse_beta":       "2.2",
		"prism.aggregation":         "max",
		"prism.stable_threshold":    "0.95",
		"prism.degraded_threshold":  "0.75",
		"prism.untrusted_threshold": "0.55",
		"prism.horizon_days":        "21",
	}
	c := ConfigFromMap(m)
	if c.DebtAlpha != 1.8 || c.PropCap != 0.4 || c.DebtCap != 0.5 || c.DebtNormDays != 900 ||
		c.PathDecay != 0.6 || c.MaxPathDepth != 8 || c.ScoreFloor != 0.2 || c.CollapseBeta != 2.2 ||
		c.AggregationMode != "max" || c.StableThreshold != 0.95 ||
		c.DegradedThreshold != 0.75 || c.UntrustedThreshold != 0.55 || c.HorizonDays != 21 {
		t.Fatalf("参数未全部映射: %+v", c)
	}
}

// 非法值忽略；srd.* 作为兼容前缀也可读。
func TestConfigFromMapInvalidAndFallback(t *testing.T) {
	m := map[string]string{
		"prism.debt_alpha":     "-1",    // 越界 ⇒ 忽略
		"prism.path_decay":     "2",     // 越界 ⇒ 忽略
		"prism.aggregation":    "bogus", // 非法枚举 ⇒ 忽略
		"prism.max_path_depth": "x",     // 非数字 ⇒ 忽略
		"srd.prop_cap":         "0.31",  // srd 前缀兼容
	}
	def := ConfigFromMap(map[string]string{})
	c := ConfigFromMap(m)
	if c.DebtAlpha != def.DebtAlpha || c.PathDecay != def.PathDecay ||
		c.AggregationMode != def.AggregationMode || c.MaxPathDepth != def.MaxPathDepth {
		t.Fatalf("非法值不应覆盖默认: %+v", c)
	}
	if c.PropCap != 0.31 {
		t.Fatalf("srd.* 兼容前缀未生效: %v", c.PropCap)
	}
}

// NewEngineFromMap 不应 panic。
func TestNewEngineFromMap(t *testing.T) {
	if e := NewEngineFromMap(map[string]string{"prism.horizon_days": "3"}); e == nil {
		t.Fatal("engine 不应为 nil")
	}
}
