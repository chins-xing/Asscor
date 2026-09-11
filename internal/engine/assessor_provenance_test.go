//go:build engine

package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// TestLegacyEdgeFactorChainLeavesProvenanceEmpty pin 住裁定 1 在 **legacy 路径** 上的形态：
// 溯源字段一律留零值（JSON 不输出），包括「配置里写了 [edge_factors.model]」的情况。
//
// 为什么连启用模型段的配置也留空：legacy 路径（本包的 evaluateEdgeFactorChain）从不构造
// edgefactor.Params、也不消费该段 —— 填一个 "graph" 会把「这次评分用了 graph 模型」写成
// 假事实。零值表达的是「走的是历史乘性路径」，这比填字符串 "legacy" 更保守：omitempty 让
// 历史输出逐位不变（裁定 1）。
func TestLegacyEdgeFactorChainLeavesProvenanceEmpty(t *testing.T) {
	withTriggerOverride := config.Default()
	withTriggerOverride.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}

	withModelSection := config.Default()
	withModelSection.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4, Lambda: map[string]float64{"attack_surface": 1.5},
	}

	cases := map[string]*config.Config{
		"默认配置":    config.Default(),
		"仅触发映射覆盖": withTriggerOverride,
		"模型段已启用":  withModelSection,
	}

	for name, cfg := range cases {
		got := evalTriggers(cfg, model.CheckResult{CheckID: "EF-001", Passed: false})

		if got.Model != "" || got.ParamsHash != "" {
			t.Errorf("%s: legacy 路径必须留空，got Model=%q ParamsHash=%q", name, got.Model, got.ParamsHash)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if strings.Contains(string(raw), "params_hash") || strings.Contains(string(raw), `"model"`) {
			t.Errorf("%s: 零值溯源字段必须被 omitempty 省略: %s", name, raw)
		}
	}
}
