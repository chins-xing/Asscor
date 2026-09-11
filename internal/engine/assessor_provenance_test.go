//go:build engine

package engine

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// assertProvenanceEmpty 断言输出层没有盖戳，且序列化后 model / params_hash 两个键都不出现。
func assertProvenanceEmpty(t *testing.T, ctx string, ef model.EdgeFactors) {
	t.Helper()
	if ef.Model != "" || ef.ParamsHash != "" {
		t.Errorf("%s: 必须留空，got Model=%q ParamsHash=%q", ctx, ef.Model, ef.ParamsHash)
	}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("%s: marshal: %v", ctx, err)
	}
	if strings.Contains(string(raw), "params_hash") || strings.Contains(string(raw), `"model"`) {
		t.Errorf("%s: 零值溯源字段必须被 omitempty 省略: %s", ctx, raw)
	}
}

// TestLegacyEdgeFactorChainLeavesProvenanceEmpty pin 住「legacy 路径一律留零值」：
// 溯源字段为空（JSON 不输出），包括「配置里写了合法 [edge_factors.model] 段」的情况。
//
// 为什么留空：legacy 路径（本包的 evaluateEdgeFactorChain）**只消费该段的 trigger.***，
// 不消费该段的合成参数（model / p_floor / vector / coupling / λ）—— 它不构造
// edgefactor.Params，因此没有「本次评分用了哪个模型、哪套参数」可言。填一个 "graph" 会把
// 「这次评分走的是历史乘性路径」写成假事实。零值表达「历史乘性路径」，比填字符串 "legacy"
// 更保守：omitempty 让历史输出逐位不变（裁定 1）。
//
// 注意「只消费 trigger.*」不是空话：下面的第三个用例断言同一份配置里的 trigger 覆盖**确实
// 生效**（部分消费），用来钉住评审 I1 指出的现场事实 —— 该配置段运维可达，所以「配置里写了
// 什么」绝不能等同于「评分用了什么」。
func TestLegacyEdgeFactorChainLeavesProvenanceEmpty(t *testing.T) {
	withTriggerOverride := config.Default()
	withTriggerOverride.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}

	withModelSection := config.Default()
	withModelSection.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model: "graph", PFloor: 0.4, Lambda: map[string]float64{"attack_surface": 1.5},
	}

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"默认配置", config.Default()},
		{"仅触发映射覆盖", withTriggerOverride},
		{"模型段已启用", withModelSection},
	}

	for _, tc := range cases {
		got := evalTriggers(tc.cfg, model.CheckResult{CheckID: "EF-001", Passed: false})
		assertProvenanceEmpty(t, tc.name, got)
	}

	t.Run("模型段的 trigger.* 覆盖生效，但仍留零值", func(t *testing.T) {
		got := evalTriggers(withTriggerOverride, model.CheckResult{CheckID: "RS-999", Passed: false})
		// 覆盖生效：EF-NO-IDS 由 RS-999 激活，权重取 legacy 默认表字面量 0.88。
		if math.Abs(got.NoIDS-0.88) > 1e-9 {
			t.Errorf("trigger.EF-NO-IDS = RS-999 在 legacy 路径未生效：NoIDS = %v, want 0.88", got.NoIDS)
		}
		assertProvenanceEmpty(t, "模型段 trigger.* 覆盖（legacy）", got)
	})
}
