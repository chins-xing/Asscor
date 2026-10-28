//go:build engine

package prism

import (
	"strconv"
	"strings"

	prismlib "github.com/chins-xing/prism"
)

// ConfigFromMap 从配置键构建 Prism 引擎配置（v2.3.6）。
//
// 键名同时接受 `prism.<k>`（推荐）与 `srd.<k>`（兼容），非法值忽略并保留默认。
// 这是"整个项目可调参数补齐"的统一入口：kernel 主评分引擎与 SRD 插件共用。
func ConfigFromMap(m map[string]string) prismlib.PrismConfig {
	c := prismlib.DefaultConfig()
	get := func(key string) string {
		if v, ok := m["prism."+key]; ok && v != "" {
			return strings.TrimSpace(v)
		}
		if v, ok := m["srd."+key]; ok && v != "" {
			return strings.TrimSpace(v)
		}
		return ""
	}
	fget := func(key string, min, max float64, dst *float64) {
		if v := get(key); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f >= min && f <= max {
				*dst = f
			}
		}
	}
	iget := func(key string, min int, dst *int) {
		if v := get(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= min {
				*dst = n
			}
		}
	}

	fget("debt_alpha", 0, 10, &c.DebtAlpha)
	fget("prop_cap", 0, 1, &c.PropCap)
	fget("debt_cap", 0, 1, &c.DebtCap)
	fget("debt_norm_days", 1, 100000, &c.DebtNormDays)
	fget("path_decay", 0.0001, 1, &c.PathDecay)
	iget("max_path_depth", 1, &c.MaxPathDepth)
	fget("score_floor", 0, 1, &c.ScoreFloor)
	fget("collapse_beta", 0, 10, &c.CollapseBeta)
	fget("stable_threshold", 0, 1, &c.StableThreshold)
	fget("degraded_threshold", 0, 1, &c.DegradedThreshold)
	fget("untrusted_threshold", 0, 1, &c.UntrustedThreshold)
	iget("horizon_days", 1, &c.HorizonDays)
	switch v := get("aggregation"); v {
	case "rss", "max", "linear":
		c.AggregationMode = v
	}
	return c
}

// NewEngineFromMap 用配置映射构造 Prism 引擎（kernel 装配入口）。
func NewEngineFromMap(m map[string]string) *Engine {
	return NewEngineWithConfig(ConfigFromMap(m))
}
