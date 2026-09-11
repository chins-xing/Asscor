//go:build engine

package ssam

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// 本文件的主题是**溯源**（model.EdgeFactors.Model / ParamsHash）。判据只有一条：
// **Engine 实际装载了哪套参数**（`Engine.LoadedEdgeFactorParams`），不是"配置里写了什么"。
//
// 三种必须互相可区分、且各自被独立用例钉住的情形：
//
//	情形 A：**未配置** [edge_factors.model] 段 → 无戳记 ⇒ JSON 里**不含** model / params_hash
//	        两个键（历史输出格式逐位不变）。
//	情形 B：**显式 `model = legacy`** → 真的装载了一套参数、且真的参与了评分（总分乘子语义）
//	        ⇒ 输出 "legacy" + 指纹。这与情形 A **语义不同**（"没配置" vs "配置为 legacy"），
//	        必须可区分 —— 否则运维/审计再也分不出两者。
//	情形 C：配置段存在、但引擎**没装载**（参数不可用 / chain 在线不可执行）
//	        ⇒ 无戳记。该配置段是运维可达的（`trigger.*` 独立于合成模型就生效），所以
//	        "配置可解析出参数"绝不能当成"评分用了这套参数"。
//
// 注意区分两个都叫 "legacy" 的东西：**情形 B** 指 `[edge_factors.model]` 里显式写
// `model = legacy`（走 ssam 插件路径、装载参数、**会**盖戳）；而 legacy **评分路径**
// （`internal/engine` 的 DynamicScoringEngine / `evaluateEdgeFactorChain`）**永远**不盖戳
// （见 internal/engine/assessor_provenance_test.go）—— 那条路径压根不构造 Params。

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

// assertJSONHasProvenanceKeys 断言两个键确实出现在 JSON 里（omitempty 没被误用成"永远省略"）。
func assertJSONHasProvenanceKeys(t *testing.T, ctx string, ef model.EdgeFactors) {
	t.Helper()
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("%s: marshal: %v", ctx, err)
	}
	if !strings.Contains(string(raw), `"model"`) || !strings.Contains(string(raw), `"params_hash"`) {
		t.Errorf("%s: 必须输出 model / params_hash 两个键: %s", ctx, raw)
	}
}

// withChecks 用给定配置与检查集跑一遍生产入口（适配器 = plugin 引擎），返回结果。
func withChecks(t *testing.T, cfg *config.Config, checks []model.CheckResult) *model.AssessmentResult {
	t.Helper()
	result := &model.AssessmentResult{
		HostID:      "provenance-host",
		Threshold:   cfg.Threshold,
		SPCScore:    1.0,
		ThreatCoeff: 1.0,
		Checks:      checks,
	}
	if err := NewEngineAdapter(cfg).ComputeScore(t.Context(), result); err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	return result
}

// TestEngineAdapterLeavesProvenanceEmptyWithoutModelSection 是**情形 A**：
// 未配置模型段 ⇒ 无戳记、JSON 不含两个键（历史输出格式逐位不变），且引擎未装载参数。
func TestEngineAdapterLeavesProvenanceEmptyWithoutModelSection(t *testing.T) {
	resetHooksForTest(t)

	cfg := factoryConfig()
	got := withChecks(t, cfg, provenanceChecks())

	assertNoProvenance(t, "未配置模型段", got.EdgeFactors)
	if _, ok := NewEngineAdapter(cfg).engine.LoadedEdgeFactorParams(); ok {
		t.Error("未配置模型段时引擎不得装载参数")
	}
}

// TestEngineAdapterStampsExplicitLegacyModel 是**情形 B**：
// 显式 `model = legacy` ⇒ 输出 "legacy" + 指纹（引擎真的装载并真的参与评分），
// 与情形 A（同一份夹具去掉模型段 ⇒ 不盖戳）**必须可区分**。
func TestEngineAdapterStampsExplicitLegacyModel(t *testing.T) {
	resetHooksForTest(t)

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

	assertStamped(t, "显式 model=legacy", result.EdgeFactors, "legacy", want)
	assertJSONHasProvenanceKeys(t, "显式 model=legacy", result.EdgeFactors)

	// 对照：同一份夹具去掉模型段 ⇒ 不盖戳（两种形态分得开）。
	plainResult := withChecks(t, boundaryConfig(), boundaryChecks())
	assertNoProvenance(t, "同一夹具未配置模型段", plainResult.EdgeFactors)
}

// TestEngineAdapterStampsOnlyWhatTheEngineLoaded 是**情形 C**（Task 5 评审 I1 的原始牙齿，
// Task 7 保留并扩展）：判据是"引擎已装载"，所以
//
//   - 已装载的 graph ⇒ 必须盖戳，且指纹 == **引擎实际装载参数**的 Hash()；
//   - 参数不可用（未装载）⇒ 不盖戳 —— 哪怕该配置段的 `trigger.*` 确实生效
//     （配置可达 ≠ 评分用了它）；
//   - chain 在线不可执行（未装载）⇒ 同样不盖戳。
func TestEngineAdapterStampsOnlyWhatTheEngineLoaded(t *testing.T) {
	resetHooksForTest(t)

	t.Run("模型段合法且引擎已装载（graph）", func(t *testing.T) {
		cfg := graphWiringConfig(0.2, 0.5)
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

	t.Run("模型段的 trigger.* 覆盖生效但参数不可用时不写假指纹", func(t *testing.T) {
		// 该配置段**运维可达**：trigger.EF-NO-IDS = RS-999 独立于合成模型就生效
		// （ConfigToEdgeFactors 消费它）。但 p_floor 缺失 ⇒ ParamsFromConfig 报错 ⇒ 引擎
		// 未装载 ⇒ 评分仍走默认乘性路径。此时盖戳就是"声称一个评分并未使用的模型"。
		cfg := graphWiringConfig(0, 0.5)
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}
		if _, enabled, err := ParamsFromConfig(cfg); err == nil || enabled {
			t.Fatalf("precondition: 缺 p_floor 的模型段必须装配失败，got enabled=%v err=%v", enabled, err)
		}

		got := withChecks(t, cfg, provenanceChecks())

		// 覆盖确实生效（该段被部分消费的证明）。
		if got.EdgeFactors.NoIDS <= 0 || got.EdgeFactors.NoIDS >= 1.0 {
			t.Errorf("trigger.EF-NO-IDS = RS-999 未生效：NoIDS = %v（应被激活，落在 (0,1)）",
				got.EdgeFactors.NoIDS)
		}
		assertNoProvenance(t, "模型段 trigger.* 覆盖 + 参数不可用", got.EdgeFactors)
	})

	t.Run("chain 在线不可执行（未装载）时不盖戳", func(t *testing.T) {
		cfg := graphWiringConfig(0.2, 0.5)
		cfg.EdgeFactorModel = config.EdgeFactorModelConfig{
			Model: "chain", PFloor: 0.2,
			Lambda:             map[string]float64{"attack_surface": 1.0},
			ChainWindowSeconds: 300,
		}
		if _, enabled, err := ParamsFromConfig(cfg); err != nil || !enabled {
			t.Fatalf("precondition: chain 必须能通过装配层校验，got enabled=%v err=%v", enabled, err)
		}

		got := withChecks(t, cfg, provenanceChecks())
		assertNoProvenance(t, "chain 在线不可执行", got.EdgeFactors)
	})
}
