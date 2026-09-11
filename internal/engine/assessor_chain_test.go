//go:build engine

package engine

import (
	"math"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// 本文件是 **legacy 评分路径**（DynamicScoringEngine / evaluateEdgeFactorChain）的输出层观测链
// 门禁（spec §5.1 的 observed.edge_factor_chain[]）。
//
// 为什么要 legacy 也写链：M0（现状乘性）是四条候选模型里的基线，基线记录没有链就无法与
// V/G/C 在同一份数据上比较 —— 采集器只能拿到六个数值权重，重建不出"哪个检查触发了它、
// 可信度多少"。
//
// 与插件路径（internal/engine/ssam）的差别只有"值从哪来"：本路径的 EffectiveFactor 取
// legacy 实际乘上去的那个值（attenuate 之后），legacy 不消费合成参数，故也没有第二次衰减。

// legacyChainConfig 是 legacy 链用例的夹具：出厂配置 + EF-002FA 的权重（出厂值 1.0 不产生
// 惩罚，无法形成链），检查集覆盖三种激活来源：
//
//	EF-001                 → 内置分支触发 EF-002FA（值 = 权重按可信度衰减）
//	EF-SYNCOOKIE           → identity 分支（检查 ID 恰好是因子 ID）
//	EF-002                 → 内置分支触发 EF-3FA，并经**级联**把 EF-002FA 压到 0.82
func legacyChainConfig() *config.Config {
	cfg := config.Default()
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	return cfg
}

// legacyChainChecks 给每次失败都带**显式可信度 0.5**：出厂 policy 关闭时
// ResolveChecks 不动它，legacy 的 attenuate 用它 —— 这正是"链上 c_trigger 与 effective_factor
// 必须同源"的观测点（1−(1−0.85)·0.5 = 0.925）。
func legacyChainChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10, Confidence: 0.5},
		{CheckID: "EF-SYNCOOKIE", Domain: model.DomainAttackSurface, Passed: false, Delta: -10, Confidence: 0.5},
		{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false, Delta: -10, Confidence: 0.5},
	}
}

// evalChain 走**真实的 legacy 评分路径**（runLegacyScoring：域分 → 因子链 → 总分），
// 返回整份结果 —— 既有 evalTriggers 只返回六个权重，看不到链。
func evalChain(t *testing.T, cfg *config.Config, checks ...model.CheckResult) (*Assessor, *model.AssessmentResult) {
	t.Helper()
	a := NewAssessor(cfg)
	result := &model.AssessmentResult{
		HostID:    "legacy-chain-host",
		Threshold: cfg.Threshold,
		Checks:    checks,
	}
	a.runLegacyScoring(result)
	return a, result
}

func TestLegacyAssessmentEmitsObservedFactorChain(t *testing.T) {
	a, res := evalChain(t, legacyChainConfig(), legacyChainChecks()...)

	if len(res.EdgeFactorChain) == 0 {
		t.Fatal("legacy 路径也要输出观测链（M0 基线记录需要它）")
	}
	for i, ob := range res.EdgeFactorChain {
		if ob.EffectiveFactor <= 0 || ob.EffectiveFactor > 1 {
			t.Errorf("legacy 链[%d] effective_factor = %v 越界（应当是 legacy 实际乘上去的那个值）",
				i, ob.EffectiveFactor)
		}
		if ob.CTrigger < 0 || ob.CTrigger > 1 {
			t.Errorf("legacy 链[%d] c_trigger = %v 越界", i, ob.CTrigger)
		}
		if _, err := time.Parse(time.RFC3339, ob.TS); err != nil {
			t.Errorf("legacy 链[%d] 的 ts 不是 RFC3339: %q（%v）", i, ob.TS, err)
		}
	}

	// 链的内容：两个真的产生了惩罚的因子（顺序 = legacy 实际相乘的顺序 = 六字段序）。
	want := []model.EdgeFactorObservation{
		{Factor: "EF-002FA", TriggerCheck: "EF-001", CTrigger: 0.5, EffectiveFactor: 0.82},
		{Factor: "EF-SYNCOOKIE", TriggerCheck: "RS-005", CTrigger: 0.5, EffectiveFactor: 0.875},
	}
	if len(res.EdgeFactorChain) != len(want) {
		t.Fatalf("链 = %+v, want %+v", res.EdgeFactorChain, want)
	}
	for i, ob := range res.EdgeFactorChain {
		if ob.Factor != want[i].Factor || ob.TriggerCheck != want[i].TriggerCheck ||
			ob.CTrigger != want[i].CTrigger || ob.EffectiveFactor != want[i].EffectiveFactor {
			t.Errorf("链[%d] = %+v, want %+v", i, ob, want[i])
		}
	}

	// EF-3FA 只作级联入口：它被 legacy 记进了内部因子表，但**从未乘进总分**
	// （六字段里没有它的槽位），故不得出现在链上 —— 写进去会让离线重算凭空多一次惩罚。
	for _, ob := range res.EdgeFactorChain {
		if ob.Factor == "EF-3FA" {
			t.Error("EF-3FA 不得出现在 legacy 链上：它的影响已经体现在 EF-002FA 的观测值（0.82，级联）上")
		}
	}

	// 链 ↔ 输出层六个权重的双向一致：凡权重 < 1 的因子都必须在链上，且值逐位相同。
	// （这是"链写的就是实际乘上去的值"最直接的可判定形式。）
	fields := []struct {
		id    string
		value float64
	}{
		{"EF-002FA", res.EdgeFactors.TwoFactorFailure},
		{"EF-SYNCOOKIE", res.EdgeFactors.SYNCookieDisabled},
		{"EF-SELINUX", res.EdgeFactors.SELinuxDisabled},
		{"EF-APPARMOR", res.EdgeFactors.AppArmorDisabled},
		{"EF-NO-SIEM", res.EdgeFactors.NoSIEM},
		{"EF-NO-IDS", res.EdgeFactors.NoIDS},
	}
	byID := make(map[string]model.EdgeFactorObservation, len(res.EdgeFactorChain))
	for _, ob := range res.EdgeFactorChain {
		byID[ob.Factor] = ob
	}
	for _, f := range fields {
		ob, ok := byID[f.id]
		if f.value < 1.0 && !ok {
			t.Errorf("%s 的权重 = %v（已产生惩罚）却不在链上", f.id, f.value)
			continue
		}
		if f.value >= 1.0 && ok {
			t.Errorf("%s 未产生惩罚（权重 = 1.0）却在链上: %+v", f.id, ob)
			continue
		}
		if ok && ob.EffectiveFactor != f.value {
			t.Errorf("%s 链上值 = %v, want %v（必须逐位等于 legacy 实际乘上去的值）",
				f.id, ob.EffectiveFactor, f.value)
		}
	}

	// **链复现总分**：只用链重建六个因子，再走引擎自己的层内公式，必须与 final_score 逐位相同。
	// （legacy 的权重向量是 DynamicScoringEngine 的动态权重、不随记录写出，故这里复用引擎的
	// 域分与层内公式；被钉住的正是"因子集来自链"这一步 —— 链错一位，分数就变。）
	rebuilt := *res
	rebuilt.EdgeFactors = edgeFactorsFromChain(t, res.EdgeFactorChain)
	got := a.computeDynamicFinalScore(a.computeDynamicDomainScores(res), &rebuilt)
	if got != res.FinalScore {
		t.Fatalf("用链重建因子后总分 = %v, want %v（链必须与评分同源）\n链: %+v",
			got, res.FinalScore, res.EdgeFactorChain)
	}

	// 反向：把链**清空**则总分必须变（否则上面那条断言是恒真的）。
	withoutChain := *res
	withoutChain.EdgeFactors = model.EdgeFactors{
		TwoFactorFailure: 1.0, SYNCookieDisabled: 1.0, SELinuxDisabled: 1.0,
		AppArmorDisabled: 1.0, NoSIEM: 1.0, NoIDS: 1.0,
	}
	if a.computeDynamicFinalScore(a.computeDynamicDomainScores(res), &withoutChain) == res.FinalScore {
		t.Fatal("清空因子后总分不变 —— 夹具无法分辨'链被用上了'，上面的复现断言会退化成恒真")
	}
}

// TestLegacyChainMarksCascadeOnlyActivation：legacy 里"仅由级联激活"（EF-3FA → EF-002FA）
// 时 c_trigger = 0、effective_factor = 0.82，与插件路径同形（spec §5.1 的合法取值 0）。
func TestLegacyChainMarksCascadeOnlyActivation(t *testing.T) {
	cfg := legacyChainConfig()
	_, res := evalChain(t, cfg, model.CheckResult{
		CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false, Delta: -10,
	})

	if len(res.EdgeFactorChain) != 1 {
		t.Fatalf("链 = %+v, want 单条 EF-002FA（EF-3FA 无输出槽位，不上链）", res.EdgeFactorChain)
	}
	ob := res.EdgeFactorChain[0]
	if ob.Factor != "EF-002FA" || ob.EffectiveFactor != 0.82 {
		t.Fatalf("链[0] = %+v, want EF-002FA / effective_factor 0.82（级联值）", ob)
	}
	if ob.CTrigger != 0 {
		t.Errorf("仅由级联激活时 c_trigger = %v, want 0（自身触发检查未失败）", ob.CTrigger)
	}
	if ob.TriggerCheck != "EF-001" {
		t.Errorf("trigger_check = %q, want EF-001（该因子登记的触发检查，不是级联入口 EF-002）", ob.TriggerCheck)
	}
	// 与六个权重一致：级联把 EF-002FA 压到 0.82（legacy 真的乘 0.82，与 V/G/C 的 c=0 ⇒ 不惩罚不同）。
	if res.EdgeFactors.TwoFactorFailure != 0.82 {
		t.Errorf("EdgeFactors.TwoFactorFailure = %v, want 0.82", res.EdgeFactors.TwoFactorFailure)
	}
}

// edgeFactorsFromChain 只从观测链重建输出层的六个因子权重（不看 result.EdgeFactors）。
func edgeFactorsFromChain(t *testing.T, chain []model.EdgeFactorObservation) model.EdgeFactors {
	t.Helper()
	ef := model.EdgeFactors{
		TwoFactorFailure: 1.0, SYNCookieDisabled: 1.0, SELinuxDisabled: 1.0,
		AppArmorDisabled: 1.0, NoSIEM: 1.0, NoIDS: 1.0,
	}
	for _, ob := range chain {
		switch ob.Factor {
		case "EF-002FA":
			ef.TwoFactorFailure = ob.EffectiveFactor
		case "EF-SYNCOOKIE":
			ef.SYNCookieDisabled = ob.EffectiveFactor
		case "EF-SELINUX":
			ef.SELinuxDisabled = ob.EffectiveFactor
		case "EF-APPARMOR":
			ef.AppArmorDisabled = ob.EffectiveFactor
		case "EF-NO-SIEM":
			ef.NoSIEM = ob.EffectiveFactor
		case "EF-NO-IDS":
			ef.NoIDS = ob.EffectiveFactor
		default:
			t.Errorf("链上出现 legacy 输出层没有槽位的因子 %q —— 它不可能被 legacy 乘进总分", ob.Factor)
		}
	}
	return ef
}

// TestLegacyChainTriggerCheckComesFromResolvedMap：链上的 trigger_check 取自**解析后的**
// 触发表（默认表 + trigger.* 覆盖），而不是出厂默认值；未激活的因子不上链。
func TestLegacyChainTriggerCheckComesFromResolvedMap(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-006"}

	resolved := config.ResolveEdgeFactorTriggerMap(cfg)

	_, res := evalChain(t, cfg, model.CheckResult{
		CheckID: "RS-006", Domain: model.DomainResilience, Passed: false, Delta: -10,
	})

	if len(res.EdgeFactorChain) != 1 {
		t.Fatalf("链 = %+v, want 单条 EF-NO-IDS（只有该因子的显式覆盖被触发）", res.EdgeFactorChain)
	}
	ob := res.EdgeFactorChain[0]
	if ob.Factor != "EF-NO-IDS" {
		t.Fatalf("链[0].Factor = %q, want EF-NO-IDS", ob.Factor)
	}
	if ob.TriggerCheck != resolved["EF-NO-IDS"] || ob.TriggerCheck != "RS-006" {
		t.Errorf("链上 EF-NO-IDS 的 trigger_check = %q, want %q（解析表）", ob.TriggerCheck, resolved["EF-NO-IDS"])
	}
	if want := 0.88; ob.EffectiveFactor != want {
		t.Errorf("链上 EF-NO-IDS 的 effective_factor = %v, want %v（legacy 默认表权重）",
			ob.EffectiveFactor, want)
	}
	if math.Abs(ob.CTrigger-1.0) > 1e-12 {
		t.Errorf("链上 EF-NO-IDS 的 c_trigger = %v, want 1.0（未指定可信度 ⇒ 1.0）", ob.CTrigger)
	}
}
