//go:build engine

package ssam

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	"github.com/chins-xing/asscor/internal/model"
	ssamlib "github.com/chins-xing/ssam"
)

// 本文件是 Task 7 的接线验收：把内仓的两个钩子（合成策略 + 域级修正）真正接到
// 生产评分链（SSAMV20Formula）上，并守住「默认逐位一致」。逐条验收条件见各用例注释。

// ---------------------------------------------------------------------------
// 夹具与助手
// ---------------------------------------------------------------------------

// resetHooksForTest 把进程级钩子恢复成内仓默认（nil == 未注册），并在用例结束时复原。
//
// 两个钩子都是**进程级全局状态**，用例之间必须自己收拾干净：本包的 engine_test.go
// 期望默认乘性路径，任何残留的注入策略都会让那些用例读到别人的模型。
func resetHooksForTest(t *testing.T) {
	t.Helper()
	ssamlib.RegisterEdgeFactorStrategy(nil)
	ssamlib.RegisterDomainAdjust(nil)
	t.Cleanup(func() {
		ssamlib.RegisterEdgeFactorStrategy(nil)
		ssamlib.RegisterDomainAdjust(nil)
	})
}

// scoreAdapter 走**生产入口**（EngineAdapter = plugin 引擎）跑一遍在线评分。
// 注意它每次都新建适配器：构造期装配（Task 7 的接线点）因此也在被测范围内。
func scoreAdapter(t *testing.T, cfg *config.Config, checks []model.CheckResult) *model.AssessmentResult {
	t.Helper()
	result := &model.AssessmentResult{
		HostID:      "integration-host",
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

// scoringOutput 是「评分输出」的可比较切片：逐位一致的门禁比较它，而不是比较
// Timestamp 之类的运行时噪声字段。
type scoringOutput struct {
	FinalScore         float64
	Acceptable         bool
	DomainScores       model.DomainScores
	EdgeFactors        model.EdgeFactors
	ThreatCoeff        float64
	SPCScore           float64
	FinalSigma         float64
	Lower95            float64
	Upper95            float64
	EvidenceConfidence float64
}

// snapshot 只取「评分数值」：溯源戳记（Model/ParamsHash）由专门的用例断言，不参与
// 逐位一致比较 —— 启用路径必然带戳、默认路径必然不带，混在一起比会掩盖真正的数值差异。
func snapshot(r *model.AssessmentResult) scoringOutput {
	ef := r.EdgeFactors
	ef.Model = ""
	ef.ParamsHash = ""
	return scoringOutput{
		FinalScore:         r.FinalScore,
		Acceptable:         r.Acceptable,
		DomainScores:       r.DomainScores,
		EdgeFactors:        ef,
		ThreatCoeff:        r.ThreatCoeff,
		SPCScore:           r.SPCScore,
		FinalSigma:         r.FinalSigma,
		Lower95:            r.ScoreLower95,
		Upper95:            r.ScoreUpper95,
		EvidenceConfidence: r.EvidenceConfidence,
	}
}

// factoryConfig 是「未配置 [edge_factors.model] 段」的出厂形态（与 config.Default() 逐字一致）。
func factoryConfig() *config.Config { return config.Default() }

// factoryChecks 触发四条不同的因子链：EF-001→EF-002FA、OT-005→SELinux/AppArmor、
// RS-006→NoIDS、RS-007→NoSIEM（RS-006/RS-007 的 delta 为 0，只为激活因子）。
func factoryChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
		{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -10},
		{CheckID: "RS-006", Domain: model.DomainResilience, Passed: false},
		{CheckID: "RS-007", Domain: model.DomainResilience, Passed: false},
	}
}

// boundaryConfig 是「取整半格边界」夹具：单域权重 1，AS-001 的 delta 使域分落在
// 0.005 取整边界上，四个自定义因子（0.537/0.887/0.915/0.622）由 CHK-A..CHK-D 激活。
//
// 它存在的理由（门禁的牙齿）：IEEE754 乘法不满足结合律，
//
//	「逐次相乘」base*=f1; base*=f2; …   → 总分 50.31
//	「单次乘积」base*(f1*f2*f3*f4)      → 总分 50.32
//
// 两者在本夹具上**可观测地不同**。因此只要接线把默认路径换成「注册一个语义等价的
// 默认策略」（内仓 ast.go 的 edgeFactorStrategyIsDefault 判定会把算术顺序换掉），
// 本夹具立刻变红 —— 这是「默认逐位一致」门禁的牙齿，而不是恒真断言。
func boundaryConfig() *config.Config {
	return &config.Config{
		Weights:     model.Weights{AttackSurface: 1},
		Threshold:   60,
		ThreatCoeff: 1.0,
		EdgeFactors: defaultTestEdgeFactors(),
		EdgeFactorsCustom: map[string]config.CustomEdgeFactorConfig{
			"EF-A": {Factor: 0.537, TriggerCheck: "CHK-A"},
			"EF-B": {Factor: 0.887, TriggerCheck: "CHK-B"},
			"EF-C": {Factor: 0.915, TriggerCheck: "CHK-C"},
			"EF-D": {Factor: 0.622, TriggerCheck: "CHK-D"},
		},
	}
}

// boundaryDelta 使域分 = 100-97.694470767953561 = 2.305529232046439，
// 恰好落在 0.005 的取整半格边界上。
const boundaryDelta = -97.694470767953561

func boundaryChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "CHK-B", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "CHK-C", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "CHK-D", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: boundaryDelta},
	}
}

const (
	// 夹具在「逐次相乘」下的总分（历史行为 = 内仓默认路径）。
	boundarySequentialTotal = 50.31
	// 同一夹具在「单次乘积」下的总分 —— 显式注入策略（含「等价默认策略」）才会得到它。
	boundarySingleProductTotal = 50.32

	// graphWiringConfig(0.2, 0.5)：逐域系数修正后的总分（推导见对应用例注释）。
	enabledGraphTotal = 87.04
	// graphWiringConfig(0.3, 0.5)：热重载后的总分。
	reloadedGraphTotal = 88.03
	// 两域 graph 夹具：逐域 P_d 修正后的总分。
	perDomainGraphTotal = 86.51
	// graphWiringConfig 夹具在**未启用**（默认乘性路径 / M0 乘子语义）下的总分：
	// base·∏eff = 90·0.5 = 45 → ic=0.45 → wa=0.725 → 72.5。
	plainGraphFixtureTotal = 72.5
	// 反例：若链式模型的错误被闭包吞掉（惩罚全丢），同一夹具会给出 95（域分 90 不被缩放）。
	// 用于把"失败模式"写成断言，而不是只写在注释里。
	swallowedPenaltyTotal = 95
)

// ---------------------------------------------------------------------------
// 验收条件 3：逐位一致硬门禁（有牙齿）
// ---------------------------------------------------------------------------

// TestDefaultConfigKeepsBitIdenticalScoring 是「未配置新模型段时评分与历史逐位一致」的门禁。
//
// 三层证据：
//  1. 生产入口（适配器）在出厂夹具上的评分等于 Task 7 之前实测捕获的**历史冻结值**
//     （73.9）—— 接线若改变了默认路径，这里就红；
//  2. **在同一个引擎实例上**比较 `ApplyEdgeFactorModel(未启用配置)` 前后的整份评分输出
//     （域分/因子/后验统计/可接受判定，`reflect.DeepEqual`，float64 走 `==`）—— 这一层
//     观测的是**装配动作本身的副作用**；若改用"再新建一个适配器评分"，装配动作就被
//     新适配器的构造覆盖了，测不到任何东西；
//  3. 边界夹具的算术顺序仍是「逐次相乘」：总分 50.31 而非 50.32 —— 这一条专门抓
//     「注册了一个语义等价的默认策略」这种把默认算术顺序换掉的坏接线。
func TestDefaultConfigKeepsBitIdenticalScoring(t *testing.T) {
	resetHooksForTest(t)

	// (1) 出厂夹具的冻结历史值。
	baseline := scoreAdapter(t, factoryConfig(), factoryChecks())
	if baseline.FinalScore != 73.9 {
		t.Fatalf("出厂配置评分 = %v, want 73.9（Task 7 之前的历史值，逐位一致门禁）", baseline.FinalScore)
	}
	assertNoProvenance(t, "出厂配置", baseline.EdgeFactors)

	// (2) 装配动作的副作用：**同一个引擎实例**，装配前 vs 装配后。
	e := NewEngine()
	e.SetWeights(ConfigToWeights(factoryConfig()))
	e.SetEdgeFactors(ConfigToEdgeFactors(factoryConfig()))
	e.SetConfidencePolicy(ConfigToConfidencePolicy(factoryConfig()))
	before := scoreEngineOutput(t, e, factoryChecks())

	if err := e.ApplyEdgeFactorModel(factoryConfig()); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	after := scoreEngineOutput(t, e, factoryChecks())

	if !reflect.DeepEqual(after, before) {
		t.Fatalf("未启用装配改变了评分输出:\n got %+v\nwant %+v", after, before)
	}
	// 同一实例的装配后数值也必须落在历史冻结值上（与生产入口互证）。
	if after.FinalScore != 73.9 {
		t.Fatalf("未启用装配后总分 = %v, want 73.9（历史冻结值）", after.FinalScore)
	}

	// (3) 算术顺序门禁（牙齿）。
	if got := scoreAdapter(t, boundaryConfig(), boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("默认路径边界夹具总分 = %v, want %v（逐次相乘的历史算术顺序）", got, boundarySequentialTotal)
	}
}

// TestEquivalentDefaultStrategyIsObservablyDifferent（Minor 1）把「门禁有牙齿」本身固化成
// 常驻用例：**显式注册一个非 nil 的等价默认策略**后，边界夹具必须给出 50.32 而不是 50.31。
//
// 两个作用：
//   - 它是"夹具仍落在取整半格边界上"的**自检** —— 未来若有人改了夹具的 delta 或因子取值，
//     使两种算术顺序重新变得不可分辨，本用例会立刻变红，从而防止
//     `TestDefaultConfigKeepsBitIdenticalScoring` 悄悄退化成恒真断言；
//   - 它把"等价默认策略 = 可观测的坏接线"这条结论钉进代码，而不只是留在 Task 6b/7 的报告里。
func TestEquivalentDefaultStrategyIsObservablyDifferent(t *testing.T) {
	resetHooksForTest(t)

	e := NewEngine()
	e.SetWeights(ConfigToWeights(boundaryConfig()))
	e.SetEdgeFactors(ConfigToEdgeFactors(boundaryConfig()))

	// 装配「未启用」配置 ⇒ 逐次相乘 ⇒ 50.31。
	if err := e.ApplyEdgeFactorModel(boundaryConfig()); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	if got := scoreEngineOutput(t, e, boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("默认路径总分 = %v, want %v", got, boundarySequentialTotal)
	}

	// 显式注册内仓导出的默认策略句柄（非 nil ⇒ 内仓判定为"已注入"）⇒ 单次乘积 ⇒ 50.32。
	ssamlib.RegisterEdgeFactorStrategy(ssamlib.DefaultEdgeFactorStrategy)
	got := scoreEngineOutput(t, e, boundaryChecks()).FinalScore
	if got == boundarySequentialTotal {
		t.Fatalf("注册等价默认策略后总分仍为 %v：夹具已失去分辨两种算术顺序的能力"+
			"（取整半格边界被破坏）—— 条件 3 的逐位一致门禁会退化成恒真断言", got)
	}
	if got != boundarySingleProductTotal {
		t.Fatalf("注册等价默认策略后总分 = %v, want %v（单次乘积）", got, boundarySingleProductTotal)
	}

	// 装配「未启用」配置把它拆掉 ⇒ 回到 50.31（装配动作是幂等的"恢复默认"）。
	if err := e.ApplyEdgeFactorModel(boundaryConfig()); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	if got := scoreEngineOutput(t, e, boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("再次装配未启用配置后总分 = %v, want %v", got, boundarySequentialTotal)
	}
}

// ---------------------------------------------------------------------------
// 验收条件 2：未启用即零注册
// ---------------------------------------------------------------------------

// scoreEngineOutput 用**给定的引擎实例**评分（不新建适配器），返回可比较的评分数值切片。
// 专门用来观察 ApplyEdgeFactorModel / ReloadWeights 在**进程级全局钩子**上留下的状态：
// 每次 NewEngineAdapter 都会按自己的配置重装钩子，因此"用新适配器评分"永远看不到
// 前一次装配残留了什么。
func scoreEngineOutput(t *testing.T, e *Engine, checks []model.CheckResult) scoringOutput {
	t.Helper()
	out, err := e.ComputeScore(t.Context(), &AssessmentInput{
		HostID:      "integration-engine",
		Threshold:   60,
		ThreatCoeff: 1.0,
		SPCScore:    1.0,
		Checks:      CheckResultsToInputs(checks),
	})
	if err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	domains := model.DomainScores{}
	for _, d := range out.DomainScores {
		domains.Set(d.Domain, d.Score)
	}
	return scoringOutput{
		FinalScore:         out.FinalScore,
		Acceptable:         out.Acceptable,
		DomainScores:       domains,
		EdgeFactors:        EdgeFactorsToModel(out.EdgeFactors),
		ThreatCoeff:        out.ThreatCoeff,
		SPCScore:           out.SPCScore,
		FinalSigma:         out.FinalSigma,
		Lower95:            out.Lower95,
		Upper95:            out.Upper95,
		EvidenceConfidence: out.EvidenceConfidence,
	}
}

// TestDisabledConfigRegistersNoHook 钉住「未启用 ⇒ 零注册」：
//
//	既不安装合成策略/域级修正，也**不安装「语义等价的默认策略」**——后者会让内仓
//	applyEdgeFactorStrategyToBase 走注入分支（base×单次乘积），默认算术顺序被换掉。
//
// 两条独立观测，各自的牙齿：
//
//	①「钩子真的被拆掉了」（走生产热重载路径）：装载 graph 模型后总分 87.04（域级修正），
//	   热重载到「同一份配置但没有模型段」⇒ 总分必须回到 72.5（默认乘性路径）且不再盖戳。
//	②「装的是"没有钩子"而不是"等价默认策略"」：用**同一个引擎实例**装配未启用配置后，
//	   在边界夹具上必须给 50.31（逐次相乘）而不是 50.32（单次乘积）。
func TestDisabledConfigRegistersNoHook(t *testing.T) {
	resetHooksForTest(t)

	enabledCfg := graphWiringConfig(0.2, 0.5)
	plainCfg := graphWiringConfig(0.2, 0.5)
	plainCfg.EdgeFactorModel = config.EdgeFactorModelConfig{}

	// ① 生产路径上的拆除证据（同一适配器，只换配置）。
	adapter := NewEngineAdapter(enabledCfg)
	if got := computeWith(t, adapter, graphWiringChecks()).FinalScore; got != enabledGraphTotal {
		t.Fatalf("启用 graph 模型后总分 = %v, want %v（域级修正生效）", got, enabledGraphTotal)
	}
	adapter.ReloadWeights(plainCfg)
	after := computeWith(t, adapter, graphWiringChecks())
	if after.FinalScore != plainGraphFixtureTotal {
		t.Fatalf("热重载到未启用后总分 = %v, want %v（钩子必须被拆除；残留会给出 %v）",
			after.FinalScore, plainGraphFixtureTotal, enabledGraphTotal)
	}
	assertNoProvenance(t, "热重载到未启用", after.EdgeFactors)

	// ② 默认算术顺序证据：用装了「未启用」配置的同一个引擎实例在边界夹具上评分。
	e := NewEngine()
	e.SetWeights(ConfigToWeights(boundaryConfig()))
	e.SetEdgeFactors(ConfigToEdgeFactors(boundaryConfig()))
	if err := e.ApplyEdgeFactorModel(boundaryConfig()); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	if _, ok := e.LoadedEdgeFactorParams(); ok {
		t.Error("未启用时不得留下装载状态")
	}
	if err := ssamlib.ValidateStrategy(); err != nil {
		t.Fatalf("默认策略必须仍可调用: %v", err)
	}
	if got := scoreEngineOutput(t, e, boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("未启用装配后边界夹具总分 = %v, want %v —— 不得注册「等价默认策略」"+
			"（那会把算术顺序换成单次乘积 = %v）", got, boundarySequentialTotal, boundarySingleProductTotal)
	}
}

// ---------------------------------------------------------------------------
// 验收条件 4：查表与激活项的口径（经 ActivationFromResult + 归一 ID）
// ---------------------------------------------------------------------------

// graphWiringConfig 是单域 graph 夹具：自定义因子以**小写 ID**产出（parseSections 会把
// [edge_factors.custom] 的键小写化），向量以规范大写键声明 —— 这正是 Task 4 记录的
// 「查表口径」陷阱现场：不归一就会静默回落到「全强度默认向量」。
func graphWiringConfig(pFloor float64, vectorAttackSurface float64) *config.Config {
	return &config.Config{
		Weights:     model.Weights{AttackSurface: 1},
		Threshold:   60,
		ThreatCoeff: 1.0,
		EdgeFactors: defaultTestEdgeFactors(),
		EdgeFactorsCustom: map[string]config.CustomEdgeFactorConfig{
			"ef-a": {Factor: 0.5, TriggerCheck: "CHK-A"},
		},
		EdgeFactorModel: config.EdgeFactorModelConfig{
			Model:  "graph",
			PFloor: pFloor,
			Lambda: map[string]float64{"attack_surface": 1.0},
			Vectors: map[string]map[string]float64{
				"EF-A": {
					"attack_surface": vectorAttackSurface, "business_continuity": 0,
					"operation_trust": 0, "resilience": 0, "kernel_security": 0,
				},
			},
		},
	}
}

func graphWiringChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
	}
}

// TestEdgeFactorLookupUsesNormalizedActivation 钉住查表口径：激活项必须由
// ActivationFromResult 构造（内部归一 ID），否则小写产出的自定义因子查不到
// Params.Vectors["EF-A"]，会**静默回落**到「作用于全部域、强度 1」的默认向量。
//
// 手算（p_floor=0.2、λ_AS=1.0、eff=EffectiveFactor(0.5, c=1)=0.5、域分=100-10=90）：
//
//	正确：v=0.5 → a=(1-0.5)·0.5=0.25 → L=0.25
//	      P=0.2+0.8·exp(-0.25)=0.8230406264571239 → 90·P=74.07365638114115
//	      → 取整 74.07 → ic=0.7407 → wa=(0.7407·50+30+20)/100=0.87035 → 总分 ≈87.04
//	回落：v=1.0 → a=0.5 → L=0.5
//	      P=0.2+0.8·exp(-0.5)=0.6852245277701067 → 90·P=61.6702074993096
//	      → 取整 61.67 → ic=0.6167 → wa=0.80835 → 总分 ≈80.84
func TestEdgeFactorLookupUsesNormalizedActivation(t *testing.T) {
	resetHooksForTest(t)

	got := scoreAdapter(t, graphWiringConfig(0.2, 0.5), graphWiringChecks())
	if got.FinalScore == 80.84 || got.FinalScore == 80.83 {
		t.Fatalf("评分 = %v：合成层回落到「全强度默认向量」（L=0.5 而非 0.25）——"+
			"激活项没经 ActivationFromResult / NormalizeFactorID 构造", got.FinalScore)
	}
	if got.FinalScore != enabledGraphTotal {
		t.Fatalf("评分 = %v, want %v（向量命中 EF-A 的归一键，L=0.25）", got.FinalScore, enabledGraphTotal)
	}
}

// TestInactiveFactorsDoNotPenalize 钉住「激活项必须经 ActivationFromResult 构造，并处理其
// bool」：未激活的因子不得进入合成输入。L=0 ⇒ P_d = p_floor+(1-p_floor)·exp(0) = 1，
// 因此「启用了模型但没有因子激活」必须与「未启用」逐位同分。
func TestInactiveFactorsDoNotPenalize(t *testing.T) {
	resetHooksForTest(t)

	// CHK-A 通过 ⇒ 因子不激活；域分仍是 90。
	checks := []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: true},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
	}

	enabled := scoreAdapter(t, graphWiringConfig(0.2, 0.5), checks)

	// 未启用参照：同一份权重/因子/检查，只是没有模型段（钩子被清空）。
	plain := graphWiringConfig(0.2, 0.5)
	plain.EdgeFactorModel = config.EdgeFactorModelConfig{}
	disabled := scoreAdapter(t, plain, checks)

	// 域分 90 且无因子惩罚：base=90 → ic=0.9 → wa=(0.9·50+30+20)/100=0.95 → 总分 95
	if enabled.FinalScore != 95 {
		t.Fatalf("无激活因子时总分 = %v, want 95（P_d=1，不得把未激活因子计入惩罚）", enabled.FinalScore)
	}
	if !reflect.DeepEqual(snapshot(enabled), snapshot(disabled)) {
		t.Fatalf("无激活因子时启用/未启用必须逐位同分:\n got %+v\nwant %+v",
			snapshot(enabled), snapshot(disabled))
	}
}

// ---------------------------------------------------------------------------
// 验收条件 1：生产公式路径 + 域级修正语义
// ---------------------------------------------------------------------------

// TestGraphModelAppliesPerDomainCoefficient 钉住「V/G/C 走域级修正 Score_d' = Base_d · P_d」：
// 两个域、两条不同的 λ，逐域系数不同 —— 任何「总分乘子」实现都无法复现这个数。
//
// 手算（域分 AS=90、OT=80；eff=0.5；vector EF-A = AS 0.6 / OT 0.3；λ_AS=1.0、λ_OT=0.5；
// p_floor=0.2；权重 AS=35、OT=25）：
//
//	a_AS=(1-0.5)·0.6=0.3   → L_AS=0.3  → P_AS=0.2+0.8·exp(-0.3)  =0.7926545765453743
//	a_OT=(1-0.5)·0.3=0.15  → L_OT=0.15 → P_OT=0.2+0.8·exp(-0.075)=0.9421947890628424
//	修正后域分：90·P_AS=71.33891188908369；80·P_OT=75.37558312502739
//	base=(71.33891188908369·35+75.37558312502739·25)/60=73.02085823739356 → 取整 73.02
//	ic=0.7302 → wa=(0.7302·50+30+20)/100=0.8651 → 总分 ≈86.51
//
// 对照（同一夹具的两种错误接线）：
//
//	「总分乘子」语义（把 P 当成一个总乘子）：85.8333…·0.5 → ≈71.46
//	完全不修正：85.8333… → ≈92.92
func TestGraphModelAppliesPerDomainCoefficient(t *testing.T) {
	resetHooksForTest(t)

	cfg := &config.Config{
		Weights:     model.Weights{AttackSurface: 35, OperationTrust: 25},
		Threshold:   60,
		ThreatCoeff: 1.0,
		EdgeFactors: defaultTestEdgeFactors(),
		EdgeFactorsCustom: map[string]config.CustomEdgeFactorConfig{
			"EF-A": {Factor: 0.5, TriggerCheck: "CHK-A"},
		},
		EdgeFactorModel: config.EdgeFactorModelConfig{
			Model:  "graph",
			PFloor: 0.2,
			Lambda: map[string]float64{"attack_surface": 1.0, "operation_trust": 0.5},
			Vectors: map[string]map[string]float64{
				"EF-A": {
					"attack_surface": 0.6, "business_continuity": 0,
					"operation_trust": 0.3, "resilience": 0, "kernel_security": 0,
				},
			},
		},
	}
	checks := []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
		{CheckID: "OT-001", Domain: model.DomainOperationTrust, Passed: false, Delta: -20},
	}

	got := scoreAdapter(t, cfg, checks)
	switch got.FinalScore {
	case 71.46, 71.45:
		t.Fatalf("评分 = %v：域级修正退化成了「总分乘子」", got.FinalScore)
	case 92.92, 92.91:
		t.Fatalf("评分 = %v：域级修正根本没生效", got.FinalScore)
	}
	if got.FinalScore != perDomainGraphTotal {
		t.Fatalf("评分 = %v, want %v（逐域 P_d 修正）", got.FinalScore, perDomainGraphTotal)
	}
}

// TestLegacyModelKeepsMultiplierSemantics 钉住 M0/legacy 候选的语义：**现状乘性连乘**
// （内仓默认路径，不注册任何钩子），域级修正不参与。
//
// 与 TestGraphModelAppliesPerDomainCoefficient **同一份夹具、只换 model**，因此两个断言
// 值的差别完全来自语义差别：
//
//	legacy：base·∏f = 90·0.5 = 45 → ic=0.45 → wa=(0.45·50+30+20)/100=0.725 → 总分 72.5
//	graph ：域分被 P_AS 修正（90·0.8230…=74.07）→ 总分 87.04
//
// legacy 的 72.5 与「未启用」同值，因为两者**就是同一条路径**（Fix round 2 裁定：
// 显式 legacy 零注册）。它与"未配置"的逐位一致由
// TestExplicitLegacyModelScoresBitIdenticallyToUnconfigured 在取整半格夹具上钉住。
func TestLegacyModelKeepsMultiplierSemantics(t *testing.T) {
	resetHooksForTest(t)

	cfg := graphWiringConfig(0.2, 0.5)
	cfg.EdgeFactorModel.Model = "legacy"

	got := scoreAdapter(t, cfg, graphWiringChecks())
	if got.FinalScore == enabledGraphTotal {
		t.Fatalf("model=legacy 总分 = %v：走成了域级修正（legacy 不参与逐域 P_d）", got.FinalScore)
	}
	if got.FinalScore != plainGraphFixtureTotal {
		t.Fatalf("model=legacy 总分 = %v, want %v（现状乘性连乘）",
			got.FinalScore, plainGraphFixtureTotal)
	}
}

// TestExplicitLegacyModelScoresBitIdenticallyToUnconfigured 是 Fix round 2（主控裁定）的用例：
//
// **显式 `model = legacy` 必须与「未配置」逐位一致** —— 它的语义就是内仓默认路径（现状乘性
// 连乘），因此**不得注册任何钩子**。此前实现给它注册了一个返回 ∏effective_f 的"等价乘子"，
// 于是内仓从"逐次相乘"切成"base×单次乘积"，因 IEEE754 不满足结合律，在取整半格边界上
// 产生 1 ulp 的可观测差异（未配置 50.31 vs 显式 legacy 50.32）。
//
// 两条断言：
//   - 同一边界夹具下，显式 legacy 与未配置的整份评分数值**逐位相同**，且都等于默认路径的
//     50.31（并显式排除 50.32 —— 若谁把"等价乘子"加回来，这里立刻红）；
//   - 生产入口（适配器）走完管线后**仍输出** "legacy" + 引擎装载参数的 Hash()：评分路径相同、
//     溯源输出不同，这正是 I1 裁定要保留的区分能力（详细断言见
//     TestEngineAdapterStampsExplicitLegacyModel）。
func TestExplicitLegacyModelScoresBitIdenticallyToUnconfigured(t *testing.T) {
	resetHooksForTest(t)

	legacyCfg := boundaryConfig()
	legacyCfg.EdgeFactorModel = config.EdgeFactorModelConfig{Model: "legacy", PFloor: 0.5}
	plainCfg := boundaryConfig()

	// 同一个引擎实例上比较两种装配（配置只差"有没有模型段"）。
	e := NewEngine()
	e.SetWeights(ConfigToWeights(boundaryConfig()))
	e.SetEdgeFactors(ConfigToEdgeFactors(boundaryConfig()))

	if err := e.ApplyEdgeFactorModel(legacyCfg); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(legacy): %v", err)
	}
	if _, loaded := e.LoadedEdgeFactorParams(); !loaded {
		t.Error("显式 legacy 必须保留「已装载」标记（溯源要输出 legacy + 指纹）")
	}
	legacyOut := scoreEngineOutput(t, e, boundaryChecks())
	if legacyOut.FinalScore == boundarySingleProductTotal {
		t.Fatalf("显式 model=legacy 总分 = %v：注册了「等价乘子」，把默认逐次相乘换成了单次乘积",
			legacyOut.FinalScore)
	}

	if err := e.ApplyEdgeFactorModel(plainCfg); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	plainOut := scoreEngineOutput(t, e, boundaryChecks())

	if !reflect.DeepEqual(legacyOut, plainOut) {
		t.Fatalf("显式 legacy 与未配置必须逐位一致:\n legacy %+v\n 未配置 %+v", legacyOut, plainOut)
	}
	if plainOut.FinalScore != boundarySequentialTotal {
		t.Fatalf("边界夹具总分 = %v, want %v（逐次相乘）", plainOut.FinalScore, boundarySequentialTotal)
	}

	// 生产入口同样逐位一致，且**仍**盖 legacy 戳（评分相同、溯源不同）。
	adapter := NewEngineAdapter(legacyCfg)
	wantHash := loadedHash(t, adapter)
	got := computeWith(t, adapter, boundaryChecks())
	if got.FinalScore != boundarySequentialTotal {
		t.Fatalf("生产入口显式 legacy 总分 = %v, want %v", got.FinalScore, boundarySequentialTotal)
	}
	assertStamped(t, "显式 legacy（生产入口）", got.EdgeFactors, "legacy", wantHash)
	if plain := withChecks(t, plainCfg, boundaryChecks()); plain.FinalScore != got.FinalScore {
		t.Fatalf("生产入口：显式 legacy = %v 与未配置 = %v 必须同分",
			got.FinalScore, plain.FinalScore)
	} else {
		assertNoProvenance(t, "同夹具未配置（对照）", plain.EdgeFactors)
	}
}

// ---------------------------------------------------------------------------
// 验收条件 7：装配点
// ---------------------------------------------------------------------------

// TestApplyEdgeFactorModelInstallsHooksOnlyWhenEnabled 钉住装配方法的开关语义：
// 未启用 → 可调用且未装载参数；启用 → 真的装载参数并安装钩子（后果在生产入口可观测）。
func TestApplyEdgeFactorModelInstallsHooksOnlyWhenEnabled(t *testing.T) {
	resetHooksForTest(t)
	e := NewEngine()

	if err := e.ApplyEdgeFactorModel(factoryConfig()); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(未启用): %v", err)
	}
	if _, ok := e.LoadedEdgeFactorParams(); ok {
		t.Error("未启用时不得装载模型参数（ok=false 是「未装载」的判据）")
	}
	if err := ssamlib.ValidateStrategy(); err != nil {
		t.Fatalf("未启用时默认策略必须仍可调用: %v", err)
	}

	cfg := graphWiringConfig(0.2, 0.5)
	if err := e.ApplyEdgeFactorModel(cfg); err != nil {
		t.Fatalf("ApplyEdgeFactorModel(graph): %v", err)
	}
	p, ok := e.LoadedEdgeFactorParams()
	if !ok {
		t.Fatal("启用后必须装载参数")
	}
	if p.Model != "graph" {
		t.Fatalf("装载的模型 = %q, want graph", p.Model)
	}
	if p.Hash() == "" {
		t.Fatal("装载参数的指纹不得为空")
	}
	// 装载参数就是本次评分所用的参数：评分必须随之改变（87.04 而非 95）。
	if got := scoreAdapter(t, cfg, graphWiringChecks()).FinalScore; got != enabledGraphTotal {
		t.Fatalf("启用后评分 = %v, want %v（钩子已接到生产评分链上）", got, enabledGraphTotal)
	}
}

// TestApplyEdgeFactorModelRejectsUnusableParams：参数不可用时必须**不注册任何钩子**
// 且不装载参数 —— 宁可回落默认乘性路径，也不带着半套参数评分。
func TestApplyEdgeFactorModelRejectsUnusableParams(t *testing.T) {
	resetHooksForTest(t)

	cfg := graphWiringConfig(0, 0.5) // p_floor=0 ⇒ ParamsFromConfig 必须拒绝
	e := NewEngine()
	if err := e.ApplyEdgeFactorModel(cfg); err == nil {
		t.Fatal("坏参数必须被拒绝（p_floor 越界）")
	}
	if _, ok := e.LoadedEdgeFactorParams(); ok {
		t.Error("装配失败时不得留下装载状态")
	}
	if got := scoreAdapter(t, boundaryConfig(), boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("装配失败后总分 = %v, want %v（必须停在默认乘性路径）", got, boundarySequentialTotal)
	}
}

// TestChainModelIsOfflineOnly 钉住 C1 的裁定：`model=chain` 在**在线**评分里不可执行，
// 必须在装配期 fail-fast（能力缺口），不得"装载并盖戳"。
//
// 为什么不能装：内仓 `Synthesize` 对 chain 要求每个激活因子带**非零时间戳**（刻意 fail-fast，
// 不允许静默退化成 vector），而在线评分的源头类型 `ssam.EdgeFactorResult` 根本没有时间字段
// ⇒ chain 在当前数据流下**永远**合成不出来。若照常装载，两个闭包的兜底会把错误吞掉
// （策略返回恒等乘子 1、域级修正原样返回入参）⇒ 惩罚全部消失、评分比未启用**更宽松**，
// 却仍然盖着 `model="chain"` 的戳：既是静默失效，又是假溯源。
//
// 四类断言（缺一不可）：
//
//	① 配置层认为 chain 合法（`ParamsFromConfig` 给 enabled=true）—— 所以问题在接线层；
//	② 装配**失败**且错误明确指向"离线/时间戳"这条能力缺口；
//	③ 不装载（`LoadedEdgeFactorParams` ok=false）⇒ 输出无戳记；
//	④ 评分与未启用路径**逐位一致**（72.5），而**不是**"惩罚被吞掉"的 95。
//
// chain 的时间戳在离线 JSONL（spec §5.1 的 `edge_factor_chain[].ts`）里是有的，
// 因此 chain 由 cmd/edgecompare 离线评估 —— 与 spec「离线重算为主」一致。
func TestChainModelIsOfflineOnly(t *testing.T) {
	resetHooksForTest(t)

	chainCfg := graphWiringConfig(0.2, 0.5)
	chainCfg.EdgeFactorModel = config.EdgeFactorModelConfig{
		Model:              "chain",
		PFloor:             0.2,
		Lambda:             map[string]float64{"attack_surface": 1.0},
		ChainWindowSeconds: 300,
	}
	plainCfg := graphWiringConfig(0.2, 0.5)
	plainCfg.EdgeFactorModel = config.EdgeFactorModelConfig{}

	// ① 前置事实：chain 在**配置/装配层**是合法模型（问题不在解析层，而在在线数据流）。
	if _, enabled, err := ParamsFromConfig(chainCfg); err != nil || !enabled {
		t.Fatalf("precondition: chain 必须能通过装配层校验，got err=%v enabled=%v", err, enabled)
	}

	// ② 装配必须失败，且错误点明"离线"这条能力缺口。
	e := NewEngine()
	err := e.ApplyEdgeFactorModel(chainCfg)
	if err == nil {
		t.Fatal("chain 在线不可执行（引擎结果类型无时间戳），装配必须 fail-fast")
	}
	if !strings.Contains(err.Error(), "chain") || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("装配错误必须点明 chain 只能离线评估，got: %v", err)
	}

	// ③ 不装载 ⇒ 不盖戳。
	if _, ok := e.LoadedEdgeFactorParams(); ok {
		t.Error("chain 装配失败时不得留下装载状态（否则会盖一个它根本没用过的模型戳）")
	}
	if err := ssamlib.ValidateStrategy(); err != nil {
		t.Fatalf("chain 被拒后默认策略必须仍可调用: %v", err)
	}

	// ④ 评分与未启用**逐位一致**，且不是"惩罚被吞掉"的 95。
	got := scoreAdapter(t, chainCfg, graphWiringChecks())
	assertNoProvenance(t, "chain 装配失败后", got.EdgeFactors)
	if got.FinalScore == swallowedPenaltyTotal {
		t.Fatalf("chain 配置评分 = %v：惩罚被静默丢弃（比未启用更宽松）—— "+
			"装配必须在装载前就失败", got.FinalScore)
	}
	if !reflect.DeepEqual(snapshot(got), snapshot(scoreAdapter(t, plainCfg, graphWiringChecks()))) {
		t.Fatalf("chain 被拒后必须与未启用路径逐位一致：got %+v want %+v",
			snapshot(got), snapshot(scoreAdapter(t, plainCfg, graphWiringChecks())))
	}
	if got.FinalScore != plainGraphFixtureTotal {
		t.Fatalf("chain 被拒后总分 = %v, want %v（未启用路径）", got.FinalScore, plainGraphFixtureTotal)
	}
}

// ---------------------------------------------------------------------------
// 验收条件 5 + 7：盖戳与热重载同源
// ---------------------------------------------------------------------------

func assertStamped(t *testing.T, ctx string, ef model.EdgeFactors, wantModel, wantHash string) {
	t.Helper()
	if ef.Model != wantModel || ef.ParamsHash != wantHash {
		t.Errorf("%s: 戳记 = (%q,%q), want (%q,%q)", ctx, ef.Model, ef.ParamsHash, wantModel, wantHash)
	}
	raw, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("%s: marshal: %v", ctx, err)
	}
	if !strings.Contains(string(raw), `"model"`) || !strings.Contains(string(raw), `"params_hash"`) {
		t.Errorf("%s: 启用后两个键必须出现在 JSON 里: %s", ctx, raw)
	}
}

func loadedHash(t *testing.T, a *EngineAdapter) string {
	t.Helper()
	p, ok := a.engine.LoadedEdgeFactorParams()
	if !ok {
		t.Fatal("引擎未装载边缘因子参数")
	}
	return p.Hash()
}

func computeWith(t *testing.T, a *EngineAdapter, checks []model.CheckResult) *model.AssessmentResult {
	t.Helper()
	result := &model.AssessmentResult{
		HostID: "reload-host", Threshold: 60, SPCScore: 1.0, ThreatCoeff: 1.0, Checks: checks,
	}
	if err := a.ComputeScore(t.Context(), result); err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	return result
}

// TestReloadWeightsReinstallsModelAndKeepsProvenanceConsistent 是验收条件 5 的核心：
// 戳记的判据是「**engine 已装载同一套参数**」，且热重载后必须同步更新。
//
// 四步：装 A → 戳 A；热重载到 B（只有 p_floor 变）→ 戳 B（≠A）且评分随之变；
// 热重载到「未启用」→ 不戳、评分回到默认乘性；热重载到坏参数 → 不戳、不残留旧参数。
func TestReloadWeightsReinstallsModelAndKeepsProvenanceConsistent(t *testing.T) {
	resetHooksForTest(t)

	cfgA := graphWiringConfig(0.2, 0.5)
	checks := graphWiringChecks()

	adapter := NewEngineAdapter(cfgA)
	got := computeWith(t, adapter, checks)
	hashA := loadedHash(t, adapter)
	assertStamped(t, "首次装配", got.EdgeFactors, "graph", hashA)
	if got.FinalScore != enabledGraphTotal {
		t.Fatalf("A 配置评分 = %v, want %v", got.FinalScore, enabledGraphTotal)
	}

	// 热重载到 B：p_floor 0.2 → 0.3（P_A=0.8230406264571239 → P_B=0.8451605481499834）
	cfgB := graphWiringConfig(0.3, 0.5)
	adapter.ReloadWeights(cfgB)
	hashB := loadedHash(t, adapter)
	if hashB == hashA {
		t.Fatalf("热重载后指纹必须变化（%q == %q）—— 参数集不同", hashB, hashA)
	}
	gotB := computeWith(t, adapter, checks)
	assertStamped(t, "热重载到 B", gotB.EdgeFactors, "graph", hashB)
	// B 的域分 = 90·(0.3+0.7·exp(-0.25)) = 76.0644493334985 → 总分 ≈88.03
	if gotB.FinalScore != reloadedGraphTotal {
		t.Fatalf("B 配置评分 = %v, want %v（热重载后的参数必须真的生效）",
			gotB.FinalScore, reloadedGraphTotal)
	}

	// 热重载到「未启用」：钩子拆除 + 不再盖戳。
	adapter.ReloadWeights(factoryConfig())
	if _, ok := adapter.engine.LoadedEdgeFactorParams(); ok {
		t.Error("热重载到未启用后必须清空装载状态")
	}
	gotOff := computeWith(t, adapter, checks)
	assertNoProvenance(t, "热重载到未启用", gotOff.EdgeFactors)
	if got := scoreAdapter(t, boundaryConfig(), boundaryChecks()).FinalScore; got != boundarySequentialTotal {
		t.Fatalf("热重载到未启用后总分 = %v, want %v（钩子必须拆除）", got, boundarySequentialTotal)
	}

	// 热重载到坏参数：不盖戳、不留旧参数。
	adapter.ReloadWeights(graphWiringConfig(0, 0.5))
	if _, ok := adapter.engine.LoadedEdgeFactorParams(); ok {
		t.Error("坏参数不得留下旧装载状态（否则戳记会与新配置不同源）")
	}
	gotBad := computeWith(t, adapter, checks)
	assertNoProvenance(t, "热重载到坏参数", gotBad.EdgeFactors)
}

// ---------------------------------------------------------------------------
// 验收条件 6：入口级守卫（Assessor → plugin 引擎 = 适配器）
// ---------------------------------------------------------------------------

// TestAssessorEntryPointKeepsProvenance 走 **Assessor 入口**（plugin 引擎 = 适配器）跑完整
// 评分管线，断言：
//   - 戳记在管线末端仍然存在，且等于**引擎实际装载参数**的指纹；
//   - 不会被后续的 EdgeFactors 映射（OutputToModel / legacy 的 evaluateEdgeFactorChain）
//     静默覆盖 —— 若把盖戳挪到 OutputToModel 之前，本用例立刻变红。
func TestAssessorEntryPointKeepsProvenance(t *testing.T) {
	resetHooksForTest(t)

	cfg := graphWiringConfig(0.2, 0.5)
	adapter := NewEngineAdapter(cfg)

	a := engine.NewAssessor(cfg)
	a.SetPluginEngine(adapter)

	want := loadedHash(t, adapter)
	result := a.AssessFromResults("integration-entry-host", "integration-entry-host", graphWiringChecks())

	assertStamped(t, "Assessor 入口", result.EdgeFactors, "graph", want)
	if result.FinalScore != enabledGraphTotal {
		t.Fatalf("Assessor 入口评分 = %v, want %v（plugin 引擎的域级修正必须生效）",
			result.FinalScore, enabledGraphTotal)
	}
}
