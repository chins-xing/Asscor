//go:build engine

package ssam

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// provenanceChecks 是溯源用例的最小检查集（两次失败 + 一次通过）。
// RS-999 只在「模型段里写了 trigger.EF-NO-IDS = RS-999」时才激活任何因子，用于证明
// [edge_factors.model] 段的 trigger.* **独立于合成模型**就被消费（部分消费）——这正是
// 「配置里写了」不等于「评分用了它」的现场证据。
func provenanceChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -10},
		{CheckID: "RS-999", Domain: model.DomainResilience, Passed: false, Delta: -10},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true},
	}
}

// assertNoProvenance 断言输出层没有盖戳，且序列化后 model / params_hash 两个键都不出现。
func assertNoProvenance(t *testing.T, ctx string, ef model.EdgeFactors) {
	t.Helper()
	if ef.Model != "" || ef.ParamsHash != "" {
		t.Errorf("%s: 不得盖戳，got Model=%q ParamsHash=%q", ctx, ef.Model, ef.ParamsHash)
	}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("%s: marshal: %v", ctx, err)
	}
	if strings.Contains(string(raw), "params_hash") || strings.Contains(string(raw), `"model"`) {
		t.Errorf("%s: 零值溯源字段必须被 omitempty 省略: %s", ctx, raw)
	}
}

// TestEngineAdapterStampsProvenanceOnlyWhenModelLoaded 是 Task 5 评审 I1 的执行期守卫，
// 由 Task 7 按交接条件**启用并改写**：
//
// Task 5 时两条真实评分路径都不盖戳（字段只加不填）。Task 7 完成接线后，判据变成
// 「**engine 已装载同一套参数**」—— 从 Engine 侧取实际装载的 Params/指纹，而不是再看
// 一眼配置。因此：
//
//	配置里写了模型段、且引擎真的装载了它   ⇒ 必须盖戳（且指纹 == 装载参数的 Hash()）
//	没写模型段 / 参数不可用（引擎未装载）  ⇒ 不得盖戳，JSON 里不得出现这两个键
//
// 「参数不可用」这一条是本用例的牙齿：该配置段**今天就被部分消费**（trigger.* 生效），
// 因此「配置可解析出参数」绝不能当成「评分用了这套参数」——照配置盖戳会输出一个
// 评分并未使用的模型。
func TestEngineAdapterStampsProvenanceOnlyWhenModelLoaded(t *testing.T) {
	resetHooksForTest(t)

	t.Run("出厂配置（无 [edge_factors.model] 段）", func(t *testing.T) {
		got := scoreAdapter(t, factoryConfig(), provenanceChecks())
		assertNoProvenance(t, "未配置模型段", got.EdgeFactors)
	})

	t.Run("模型段合法且引擎已装载（graph）", func(t *testing.T) {
		cfg := graphWiringConfig(0.2, 0.5)
		// 前置事实：这套配置确实装配得出一套合法参数 —— 否则本用例的「盖戳」会退化成
		// 「因为参数坏了所以留空」，测不到想测的东西。
		adapter := NewEngineAdapter(cfg)
		want := loadedHash(t, adapter)

		result := &model.AssessmentResult{
			HostID: "provenance-host", Threshold: cfg.Threshold,
			SPCScore: 1.0, ThreatCoeff: 1.0, Checks: provenanceChecks(),
		}
		if err := adapter.ComputeScore(t.Context(), result); err != nil {
			t.Fatalf("ComputeScore: %v", err)
		}
		assertStamped(t, "引擎已装载 graph", result.EdgeFactors, "graph", want)
	})

	t.Run("显式 legacy 模型也是「已装载」形态，与未配置可区分", func(t *testing.T) {
		// Task 5 §3.2 的裁定：未配置 ⇒ 零值（键不出现）；显式 model=legacy ⇒ 真的装载了
		// 一套参数并真的参与了评分（总分乘子），所以输出 "legacy" + 指纹。两者语义不同，
		// 必须可区分 —— 否则再也分不出「没配置」与「配置为 legacy」。
		cfg := boundaryConfig()
		cfg.EdgeFactorModel = config.EdgeFactorModelConfig{Model: "legacy", PFloor: 0.5}

		adapter := NewEngineAdapter(cfg)
		want := loadedHash(t, adapter)
		result := &model.AssessmentResult{
			HostID: "provenance-host", Threshold: cfg.Threshold,
			SPCScore: 1.0, ThreatCoeff: 1.0, Checks: boundaryChecks(),
		}
		if err := adapter.ComputeScore(t.Context(), result); err != nil {
			t.Fatalf("ComputeScore: %v", err)
		}
		assertStamped(t, "显式 legacy", result.EdgeFactors, "legacy", want)
	})

	t.Run("模型段的 trigger.* 覆盖生效但参数不可用时不写假指纹", func(t *testing.T) {
		// 该配置段**运维可达**：trigger.EF-NO-IDS = RS-999 今天就生效（ConfigToEdgeFactors
		// 消费它）。但 p_floor 缺失 ⇒ ParamsFromConfig 报错 ⇒ 引擎未装载 ⇒ 评分仍走默认
		// 乘性路径。此时盖戳就是"声称一个评分并未使用的模型"。
		cfg := graphWiringConfig(0, 0.5)
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}
		if _, enabled, err := ParamsFromConfig(cfg); err == nil || enabled {
			t.Fatalf("precondition: 缺 p_floor 的模型段必须装配失败，got enabled=%v err=%v", enabled, err)
		}

		got := scoreAdapter(t, cfg, provenanceChecks())

		// 覆盖确实生效（该段被部分消费的证明）。
		if got.EdgeFactors.NoIDS <= 0 || got.EdgeFactors.NoIDS >= 1.0 {
			t.Errorf("trigger.EF-NO-IDS = RS-999 未生效：NoIDS = %v（应被激活，落在 (0,1)）",
				got.EdgeFactors.NoIDS)
		}
		assertNoProvenance(t, "模型段 trigger.* 覆盖 + 参数不可用", got.EdgeFactors)
	})
}
