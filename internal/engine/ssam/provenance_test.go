//go:build engine

package ssam

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// provenanceChecks 是溯源用例的最小检查集（两次失败 + 一次通过）。
// RS-999 只在「模型段里写了 trigger.EF-NO-IDS = RS-999」时才激活任何因子，用于证明
// [edge_factors.model] 段**今天就被消费**（部分消费）——这正是「配置里写了」不等于
// 「评分用了它」的现场证据。
func provenanceChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -10},
		{CheckID: "RS-999", Domain: model.DomainResilience, Passed: false, Delta: -10},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true},
	}
}

// scoreWithAdapter 用给定配置跑一遍 **ssam 插件路径** 的在线评分，返回结果。
func scoreWithAdapter(t *testing.T, cfg *config.Config) *model.AssessmentResult {
	t.Helper()
	result := &model.AssessmentResult{
		HostID:      "provenance-host",
		Threshold:   60,
		SPCScore:    1.0,
		ThreatCoeff: 1.0,
		Checks:      provenanceChecks(),
	}
	if err := NewEngineAdapter(cfg).ComputeScore(context.Background(), result); err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	return result
}

// assertNoProvenance 断言输出层没有盖戳，且序列化后 model / params_hash 两个键都不出现。
func assertNoProvenance(t *testing.T, ctx string, ef model.EdgeFactors) {
	t.Helper()
	if ef.Model != "" || ef.ParamsHash != "" {
		t.Errorf("%s: 评分路径不得盖戳，got Model=%q ParamsHash=%q", ctx, ef.Model, ef.ParamsHash)
	}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("%s: marshal: %v", ctx, err)
	}
	if strings.Contains(string(raw), "params_hash") || strings.Contains(string(raw), `"model"`) {
		t.Errorf("%s: 零值溯源字段必须被 omitempty 省略: %s", ctx, raw)
	}
}

// TestEngineAdapterNeverStampsProvenance 是 Task 5 Fix round 1（评审裁定 I1）的执行期守卫：
// **本任务只加字段、不盖戳**。适配器今天无法证明「本次评分用了哪套参数」—— ssam 评分仍由
// 内仓的默认乘性策略产生（edgefactor.Synthesize 在生产代码里没有调用方，ParamsFromConfig
// 的生产调用方原本只有本文件），所以任何一种配置下都不得写 model / params_hash。
//
// 覆盖四种配置形态，包括「配置了合法 [edge_factors.model] 段」——评审明确纠正过：该段是
// **运维可达**的（trigger.* 覆盖今天就生效，且解析层要求段存在必须有 model 键），因此
// 「当前不可达」这种口头保证不足以钉住行为，必须由本测试显式钉住这个「溯源超前窗口」。
func TestEngineAdapterNeverStampsProvenance(t *testing.T) {
	t.Run("出厂配置（无 [edge_factors.model] 段）", func(t *testing.T) {
		got := scoreWithAdapter(t, &config.Config{EdgeFactors: defaultTestEdgeFactors()})
		assertNoProvenance(t, "未配置模型段", got.EdgeFactors)
	})

	t.Run("模型段合法且参数齐备（graph）", func(t *testing.T) {
		cfg := graphTestConfig()
		// 前置事实：这套配置确实装配得出一套合法参数 —— 否则本用例的「留空」会退化成
		// 「因为参数坏了所以留空」，测不到想测的东西。
		if _, enabled, err := ParamsFromConfig(cfg); err != nil || !enabled {
			t.Fatalf("precondition ParamsFromConfig: enabled=%v err=%v", enabled, err)
		}
		got := scoreWithAdapter(t, cfg)
		assertNoProvenance(t, "合法 graph 模型段", got.EdgeFactors)
	})

	t.Run("模型段的 trigger.* 覆盖生效，但仍不盖戳", func(t *testing.T) {
		cfg := graphTestConfig()
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}
		if _, enabled, err := ParamsFromConfig(cfg); err != nil || !enabled {
			t.Fatalf("precondition ParamsFromConfig: enabled=%v err=%v", enabled, err)
		}

		got := scoreWithAdapter(t, cfg)

		// 该段的 trigger.* 今天就被消费：RS-999 失败 ⇒ EF-NO-IDS 被激活。
		if got.EdgeFactors.NoIDS <= 0 || got.EdgeFactors.NoIDS >= 1.0 {
			t.Errorf("trigger.EF-NO-IDS = RS-999 未生效：NoIDS = %v（应被激活，落在 (0,1)）",
				got.EdgeFactors.NoIDS)
		}
		// 部分消费 ≠ 有了溯源：合成参数（model/p_floor/vector/coupling/λ）一个都没参与计算。
		assertNoProvenance(t, "模型段 trigger.* 覆盖", got.EdgeFactors)
	})

	t.Run("模型段参数不可用时不写假指纹（宁可留空）", func(t *testing.T) {
		cfg := graphTestConfig()
		cfg.EdgeFactorModel.PFloor = 0
		if _, _, err := ParamsFromConfig(cfg); err == nil {
			t.Fatal("precondition: 缺 p_floor 的模型段必须被 ParamsFromConfig 拒绝")
		}

		got := scoreWithAdapter(t, cfg)

		assertNoProvenance(t, "模型段参数不可用", got.EdgeFactors)
	})
}
