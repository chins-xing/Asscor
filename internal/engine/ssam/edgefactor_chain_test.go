//go:build engine

package ssam

import (
	"math"
	"sort"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
	"github.com/chins-xing/asscor/internal/model"
)

// 本文件是**输出层观测链**（model.AssessmentResult.EdgeFactorChain，spec §5.1 的
// observed.edge_factor_chain[]）在插件路径（EngineAdapter）上的门禁。
//
// 三条硬约束，各有独立用例：
//
//	① 配置了模型且引擎真的装载了参数 ⇒ 链必须写出，且每条都合法（规范 ID、出厂/解析触发表、
//	   值域、非零 RFC3339 时间戳）；
//	② 未配置 / 装配失败（引擎没装载）⇒ 链必须为空 —— 判据与溯源戳记**同一处**：
//	   「引擎实际装载了什么」，不是「配置里写了什么」；
//	③ 链上的观测值必须**就是**评分乘上去的那个值 —— 用链自己重算总分，必须与 final_score
//	   逐位相同（见 TestChainReproducesTheScoreItDescribes）。这条比"字段非空"强得多。

// chainFixtureConfig 是「内置因子 + 出厂触发表」的 V/G/C 夹具。
//
// OT-005 失败同时激活 EF-SELINUX 与 EF-APPARMOR —— 出厂表里两者**共用** OT-005，
// 正是 S2 组要建模的同源耦合先验；再给出一条耦合边，让 graph 的耦合项也进入复算。
func chainFixtureConfig() *config.Config {
	cfg := graphTestConfig() // graph / λ_AS = 1.5 / p_floor = 0.4
	cfg.Weights = model.Weights{AttackSurface: 1}
	// graphTestConfig 是装配层夹具（不带 Threshold / Weights），生产入口 scoreAdapter
	// 要求 threshold ∈ (0,100]，这里补齐这两项（权重见上）。
	cfg.Threshold = 60
	cfg.EdgeFactorModel.Coupling = map[string]map[string]float64{
		"EF-APPARMOR": {"EF-SELINUX": 0.35},
	}
	return cfg
}

// TestComputeScoreEmitsObservedFactorChain 断言：配置了模型时输出链非空、每条都命中出厂
// 触发表、值域合法。
func TestComputeScoreEmitsObservedFactorChain(t *testing.T) {
	resetHooksForTest(t)

	cfg := chainFixtureConfig()
	got := scoreAdapter(t, cfg, provenanceChecks()) // OT-005 失败 ⇒ 两个共用该检查的因子同时激活
	if len(got.EdgeFactorChain) == 0 {
		t.Fatal("配置了模型却没有输出观测链 —— 采集器将无法写 spec §5.1 的记录")
	}
	triggers := config.DefaultEdgeFactorTriggerMap()
	for i, ob := range got.EdgeFactorChain {
		if edgefactor.NormalizeFactorID(ob.Factor) != ob.Factor {
			t.Errorf("链上因子 %q 不是规范 ID", ob.Factor)
		}
		if want := triggers[ob.Factor]; ob.TriggerCheck != want {
			t.Errorf("链[%d] %s 的 trigger_check = %q，出厂表是 %q", i, ob.Factor, ob.TriggerCheck, want)
		}
		if ob.CTrigger < 0 || ob.CTrigger > 1 {
			t.Errorf("链[%d] c_trigger = %v 越界", i, ob.CTrigger)
		}
		if ob.EffectiveFactor <= 0 || ob.EffectiveFactor > 1 {
			t.Errorf("链[%d] effective_factor = %v 越界", i, ob.EffectiveFactor)
		}
		if ob.TS == "" {
			t.Errorf("链[%d] 缺时间戳 —— chain 模型离线评估要求非零 ts", i)
		}
		if _, err := time.Parse(time.RFC3339, ob.TS); err != nil {
			t.Errorf("链[%d] 的 ts 不是 RFC3339: %q", i, ob.TS)
		}
	}

	// 夹具级断言：内容也必须是"引擎真的看到的那两个因子"（顺序 = 引擎的因子结果序 = ID 序）。
	want := []model.EdgeFactorObservation{
		{Factor: "EF-APPARMOR", TriggerCheck: "OT-005", CTrigger: 1.0, EffectiveFactor: 0.82},
		{Factor: "EF-SELINUX", TriggerCheck: "OT-005", CTrigger: 1.0, EffectiveFactor: 0.80},
	}
	if len(got.EdgeFactorChain) != len(want) {
		t.Fatalf("链长度 = %d, want %d: %+v", len(got.EdgeFactorChain), len(want), got.EdgeFactorChain)
	}
	for i, ob := range got.EdgeFactorChain {
		if ob.Factor != want[i].Factor || ob.TriggerCheck != want[i].TriggerCheck ||
			ob.CTrigger != want[i].CTrigger || ob.EffectiveFactor != want[i].EffectiveFactor {
			t.Errorf("链[%d] = %+v, want %+v", i, ob, want[i])
		}
	}

	// 口径 2（TS = 评分时刻，不是检查的采集时刻）：必须是**本次评分**写出的时间戳。
	ts, err := time.Parse(time.RFC3339, got.EdgeFactorChain[0].TS)
	if err != nil {
		t.Fatalf("ts: %v", err)
	}
	if d := time.Since(ts); d < 0 || d > time.Minute {
		t.Errorf("ts = %s 不在本次评分时刻附近（差 %v）—— TS 必须取评分时刻", got.EdgeFactorChain[0].TS, d)
	}

	// 未激活的项一律不上链：EF-3FA 只作级联入口（CascadeOnly ⇒ Active=false），
	// 它的影响已经体现在 EF-002FA 的观测值上，写进链会让离线重算凭空多出一次惩罚。
	for _, ob := range got.EdgeFactorChain {
		if ob.Factor == ef3FAFactorID {
			t.Error("EF-3FA（CascadeOnly、从未 Active）不得出现在链上 —— 它没有产生任何惩罚")
		}
	}
}

// TestComputeScoreEmitsNoChainWhenUnconfigured 反向对照一：未配置模型段（或装配失败）时
// 不得输出链（"零值不输出"这条硬门禁）。
func TestComputeScoreEmitsNoChainWhenUnconfigured(t *testing.T) {
	resetHooksForTest(t)

	// 情形 A：配置里**没有** [edge_factors.model] 段（与 provenance_test 情形 A 同款；
	// 生产入口要求 threshold ∈ (0,100]，故补齐这一项，其余与 brief 一致）。
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors(), Threshold: 60}
	if got := scoreAdapter(t, cfg, provenanceChecks()); len(got.EdgeFactorChain) != 0 {
		t.Fatalf("未配置模型段却输出了观测链: %+v", got.EdgeFactorChain)
	}

	// 出厂形态（生产默认配置）同样不得出现链。
	if got := scoreAdapter(t, factoryConfig(), factoryChecks()); len(got.EdgeFactorChain) != 0 {
		t.Fatalf("出厂配置却输出了观测链: %+v", got.EdgeFactorChain)
	}

	// 情形 C：模型段存在、但引擎**没装载**（p_floor 缺失 ⇒ 装配失败）⇒ 同样不得输出链。
	// 判据与溯源戳记同一处：不是"配置里写了模型段"，而是"引擎真的装载了参数"。
	broken := chainFixtureConfig()
	broken.EdgeFactorModel.PFloor = 0
	if got := scoreAdapter(t, broken, provenanceChecks()); len(got.EdgeFactorChain) != 0 {
		t.Fatalf("装配失败（引擎未装载）却输出了观测链: %+v", got.EdgeFactorChain)
	}
}

// TestComputeScoreEmitsNoChainWhenNoFactorActivates：装载了模型但**一个因子都没激活**时链为空。
//
// 它也解释了本文件夹具的取舍：brief 草图里的 `graphTestConfig()` + `graphWiringChecks()` 恰好落在
// 这个情形（graphTestConfig 不含 [edge_factors.custom]，而 CHK-A / AS-001 都不是出厂触发表里的
// 检查 ⇒ 没有任何因子激活），所以"链必须非空"那条断言改用 chainFixtureConfig()（OT-005 同时
// 激活 EF-SELINUX + EF-APPARMOR）。空链不等于零值：它是"这次真的没有因子产生惩罚"的事实；
// 未激活项若被写进链，离线重算会凭空产生惩罚。
func TestComputeScoreEmitsNoChainWhenNoFactorActivates(t *testing.T) {
	resetHooksForTest(t)

	// CHK-A 通过 ⇒ 自定义因子 EF-A 不激活（与 TestInactiveFactorsDoNotPenalize 同款检查集）。
	passing := []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: true},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
	}
	got := scoreAdapter(t, graphWiringConfig(0.2, 0.5), passing)
	if len(got.EdgeFactorChain) != 0 {
		t.Fatalf("没有因子激活却输出了链（离线重算会凭空产生惩罚）: %+v", got.EdgeFactorChain)
	}
	if got.FinalScore != 95 {
		t.Fatalf("无激活因子时总分 = %v, want 95（P_d = 1）", got.FinalScore)
	}

	// 反向对照：同一配置 + 让 CHK-A 失败 ⇒ 链立刻出现（证明上面那条不是"链永远为空"）。
	if n := len(scoreAdapter(t, graphWiringConfig(0.2, 0.5), graphWiringChecks()).EdgeFactorChain); n != 1 {
		t.Fatalf("CHK-A 失败时链长度 = %d, want 1", n)
	}

	// brief 草图的原样组合（graphTestConfig + graphWiringChecks）落在同一个"无激活"情形。
	plain := graphTestConfig()
	plain.Threshold = 60 // graphTestConfig 是装配层夹具，不带 threshold
	if n := len(scoreAdapter(t, plain, graphWiringChecks()).EdgeFactorChain); n != 0 {
		t.Fatalf("graphTestConfig + graphWiringChecks 的链长度 = %d, want 0（该组合不激活任何因子）", n)
	}
}

// TestChainRecordsCascadeOnlyActivationWithZeroConfidence：**仅由级联激活**（EF-3FA → EF-002FA）
// 时链上 c_trigger = 0、effective_factor = 级联值。
//
// spec §5.1 明确把 c_trigger = 0 列为"仅由级联激活、自身触发检查未失败"的**既有合法取值**
// （S5 级联组会产出）。链必须如实记录它：内仓的 TriggerConfidence 只在该因子**自己**被触发
// 时才有值，级联覆盖不写可信度（级联值的来源是配置）。配套后果见本用例的分数断言 ——
// V/G/C 下 EffectiveFactor(0.82, c=0) = 1 ⇒ 该因子不产生惩罚（在线behavior，Task 1 只记录，
// 不改它）；legacy 下它乘 0.82。这一条口径差与 S5 组的设计直接相关，务必在标定报告里标注。
func TestChainRecordsCascadeOnlyActivationWithZeroConfidence(t *testing.T) {
	resetHooksForTest(t)

	cfg := chainFixtureConfig()
	checks := []model.CheckResult{
		{CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: true},
	}
	got := scoreAdapter(t, cfg, checks)

	if len(got.EdgeFactorChain) != 1 {
		t.Fatalf("链 = %+v, want 单条 EF-002FA（EF-3FA 是 CascadeOnly，Active=false，不上链）", got.EdgeFactorChain)
	}
	ob := got.EdgeFactorChain[0]
	if ob.Factor != "EF-002FA" {
		t.Errorf("链[0].Factor = %q, want EF-002FA", ob.Factor)
	}
	if ob.CTrigger != 0 {
		t.Errorf("仅由级联激活时 c_trigger = %v, want 0（内仓不记级联的可信度）", ob.CTrigger)
	}
	if ob.EffectiveFactor != 0.82 {
		t.Errorf("effective_factor = %v, want 0.82（级联值，且级联不做可信度衰减）", ob.EffectiveFactor)
	}
	if ob.TriggerCheck != "EF-001" {
		t.Errorf("trigger_check = %q, want EF-001（该因子**登记的**触发检查，不是级联入口 EF-002）", ob.TriggerCheck)
	}
	// V/G/C 下 c_trigger = 0 ⇒ EffectiveFactor(f, 0) = 1 ⇒ 该因子不产生**因子惩罚**
	// （域分 90 = 100 − EF-002 的 −10 仍在，故总分 = 与"无因子激活"同款的 95，而不是更低）。
	if got.FinalScore != 95 {
		t.Errorf("级联激活在 V/G/C 下的总分 = %v, want 95（c_trigger=0 ⇒ 因子不产生惩罚；"+
			"域分仍按检查项 −10 计）", got.FinalScore)
	}
}

// TestChainTriggerCheckComesFromResolvedMap 钉住触发检查的来源（spec §5.1 的"记录构造要求"）：
//
//	① 被 trigger.<factor> 覆盖的因子，链上必须是**解析后**的检查，而不是出厂默认值；
//	② 解析表里查不到的自定义因子留空 —— 不得凭空编造一个触发检查。
func TestChainTriggerCheckComesFromResolvedMap(t *testing.T) {
	resetHooksForTest(t)

	cfg := chainFixtureConfig()
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-SELINUX": "OT-099"}
	checks := append(provenanceChecks(),
		model.CheckResult{CheckID: "OT-099", Domain: model.DomainOperationTrust, Passed: false, Delta: -10})

	got := scoreAdapter(t, cfg, checks)
	resolved := config.ResolveEdgeFactorTriggerMap(cfg)

	byID := make(map[string]model.EdgeFactorObservation, len(got.EdgeFactorChain))
	for _, ob := range got.EdgeFactorChain {
		byID[ob.Factor] = ob
	}

	sel, ok := byID["EF-SELINUX"]
	if !ok {
		t.Fatalf("EF-SELINUX 未出现在链上: %+v", got.EdgeFactorChain)
	}
	if sel.TriggerCheck != "OT-099" {
		t.Errorf("链上 EF-SELINUX 的 trigger_check = %q, want 覆盖后的 %q（出厂表是 %q）",
			sel.TriggerCheck, "OT-099", config.DefaultEdgeFactorTriggerMap()["EF-SELINUX"])
	}
	app, ok := byID["EF-APPARMOR"]
	if !ok {
		t.Fatalf("EF-APPARMOR 未出现在链上: %+v", got.EdgeFactorChain)
	}
	if app.TriggerCheck != resolved["EF-APPARMOR"] {
		t.Errorf("链上 EF-APPARMOR 的 trigger_check = %q, want 解析表 %q", app.TriggerCheck, resolved["EF-APPARMOR"])
	}

	// ② 自定义因子（graphWiringConfig 的 ef-a）在解析表里没有条目 ⇒ trigger_check 留空。
	custom := scoreAdapter(t, graphWiringConfig(0.2, 0.5), graphWiringChecks())
	if len(custom.EdgeFactorChain) != 1 || custom.EdgeFactorChain[0].Factor != "EF-A" {
		t.Fatalf("自定义因子夹具的链 = %+v, want 单条 EF-A", custom.EdgeFactorChain)
	}
	if tc := custom.EdgeFactorChain[0].TriggerCheck; tc != "" {
		t.Errorf("自定义因子 EF-A 的 trigger_check = %q —— 解析表里没有它，必须留空（不得编造）", tc)
	}
}

// ---------------------------------------------------------------------------
// 反向对照二：链必须能复现它自己描述的那个总分
// ---------------------------------------------------------------------------

// TestChainReproducesTheScoreItDescribes 钉住「链与评分同源」：只用**本次评分的输出链**
// （effective_factor / c_trigger）、记录里的域分与配置里的合成参数，手算总分，必须与
// final_score **逐位相同**。链上任一处的口径错位（记成配置权重而非观测值、漏掉/多加一次
// 衰减、顺序错位、把未激活因子写进去）都会在这里变成分数差 —— 这正是它比"字段非空"强的
// 地方。
//
// 两个子例对应两种乘算口径（spec §10.2 的已知差异）：
//
//	M0 legacy：观测值**已经**是策略层衰减一次的结果 ⇒ 直接逐次相乘（单次衰减）；
//	V/G/C   ：装配层会对同一个观测值**再**衰减一次 ⇒ 每条先过 edgefactor.EffectiveFactor
//	          （第二次衰减），再逐域累加 L_d、算 P_d、修正域分后聚合。
func TestChainReproducesTheScoreItDescribes(t *testing.T) {
	resetHooksForTest(t)

	t.Run("M0 legacy：观测值逐次相乘（单次衰减）", func(t *testing.T) {
		cfg := boundaryConfig()
		cfg.EdgeFactorModel = config.EdgeFactorModelConfig{Model: "legacy", PFloor: 0.5}

		got := scoreAdapter(t, cfg, boundaryChecks())
		// 前置事实：显式 legacy 与未配置逐位同分（里程碑 A 的取整半格门禁仍绿）。
		if got.FinalScore != boundarySequentialTotal {
			t.Fatalf("显式 legacy 总分 = %v, want %v（逐次相乘的历史算术顺序）",
				got.FinalScore, boundarySequentialTotal)
		}
		if len(got.EdgeFactorChain) == 0 {
			t.Fatal("显式 legacy 也必须输出观测链（M0 基线记录需要它）")
		}
		if len(got.EdgeFactorChain) != 4 {
			t.Fatalf("链长度 = %d, want 4（CHK-A..CHK-D 激活的四个自定义因子）: %+v",
				len(got.EdgeFactorChain), got.EdgeFactorChain)
		}

		recomputed := recomputeTotalFromRecord(t, cfg, got)
		if recomputed != got.FinalScore {
			t.Fatalf("用链重算的总分 = %v, want %v（必须逐位相同）\n链: %+v\n域分: %+v",
				recomputed, got.FinalScore, got.EdgeFactorChain, got.DomainScores)
		}
	})

	t.Run("V/G/C graph：EffectiveFactor 再衰减一次 + 逐域 P_d", func(t *testing.T) {
		cfg := chainFixtureConfig()
		got := scoreAdapter(t, cfg, provenanceChecks())
		if len(got.EdgeFactorChain) != 2 {
			t.Fatalf("链 = %+v, want EF-APPARMOR + EF-SELINUX", got.EdgeFactorChain)
		}

		// 手算（域分 AS=100；eff 取观测值再衰减一次 = 观测值本身，因 c_trigger = 1）：
		//
		//	a_APPARMOR = (1−0.82)·1 = 0.18
		//	a_SELINUX  = (1−0.80)·1 = 0.20
		//	耦合项（EF-APPARMOR → EF-SELINUX = 0.35）：0.35·0.18·0.20 = 0.0126
		//	L = 0.18 + 0.20 + 0.0126 = 0.3926
		//	P = 0.4 + 0.6·exp(−1.5·0.3926) = 0.732962…  → AS' = 100·P = 73.2962…
		//	base = 取整 73.30 → ic = 0.733 → wa = (0.733·50+30+20)/100 = 0.8665 → 总分 86.65
		if got.FinalScore != 86.65 {
			t.Fatalf("V/G/C 夹具总分 = %v, want 86.65（手算见用例注释）", got.FinalScore)
		}

		recomputed := recomputeTotalFromRecord(t, cfg, got)
		if recomputed != got.FinalScore {
			t.Fatalf("用链重算的总分 = %v, want %v（必须逐位相同）\n链: %+v\n域分: %+v",
				recomputed, got.FinalScore, got.EdgeFactorChain, got.DomainScores)
		}
	})
}

// ---------------------------------------------------------------------------
// 复算辅助：**只**用记录（链 + 域分）与配置参数手算总分，不调用评分链本身
// ---------------------------------------------------------------------------

// recomputeTotalFromRecord 用记录复现最终总分（引擎公式 SSAMV20Formula + 其调用方的
// 取整口径）：
//
//	base = round2(域分修正后的加权平均 [× 因子乘子])   ← 见 recomputedBase
//	ic   = base / 100
//	wa   = (ic·50 + spc·30 + threat·20) / 100
//	总分 = round(wa·100·100) / 100，再由调用方 round(总分·100)/100
//
// spc/threat 直接取记录里的观测值：它们已是引擎**归一化后**的系数（0 ⇒ 1.0、下限 0.60），
// 与 spec §5.1 把 `spc_score` / `threat_coefficient` 列为记录输入的口径一致。
func recomputeTotalFromRecord(t *testing.T, cfg *config.Config, res *model.AssessmentResult) float64 {
	t.Helper()

	base := recomputedBase(t, cfg, res)

	ic := base / 100.0
	wa := (ic*50 + res.SPCScore*30 + res.ThreatCoeff*20) / 100
	total := math.Round(wa*100*100) / 100
	return math.Round(total*100) / 100
}

// recomputedBase 复现「域分修正 → 加权聚合 →（M0）因子连乘 → 取整」这一步。
//
// 口径说明（两条都在实现里钉死，不是"顺手"）：
//   - **单正权重域夹具**：加权平均按引擎的累加顺序（域名字典序）进行，但"某域是否出现在
//     引擎输出的域分切片里"在记录中不可辨（model.DomainScores 的四个核心域字段恒存在），
//     故本辅助只在"至多一个正权重域"的夹具上逐位成立。多域口径由离线工具
//     （cmd/edgecompare）的用例负责。
func recomputedBase(t *testing.T, cfg *config.Config, res *model.AssessmentResult) float64 {
	t.Helper()

	p, _, err := ParamsFromConfig(cfg)
	if err != nil {
		t.Fatalf("ParamsFromConfig: %v", err)
	}

	if p.Model == edgefactor.ModelLegacy {
		// M0：因子作用于**聚合后**的基分，逐次相乘。观测值已是单次衰减后的值 ⇒ 不再衰减。
		// 顺序 = 链的写出顺序 = 引擎的因子结果序（内仓按 ID 排序），故逐位一致。
		acc := observedWeightedBase(t, cfg, res.DomainScores, nil)
		for _, ob := range res.EdgeFactorChain {
			if ob.EffectiveFactor > 0 && ob.EffectiveFactor < 1.0 {
				acc *= ob.EffectiveFactor
			}
		}
		return math.Round(acc*100) / 100
	}

	// V/G/C：先按 P_d 修正域分再聚合；总分乘子恒为 1（装配层注册的恒等乘子抵消了
	// 内仓默认的逐次相乘），故此处不再乘任何因子。
	return math.Round(observedWeightedBase(t, cfg, res.DomainScores, domainCorrections(t, p, res.EdgeFactorChain))*100) / 100
}

// observedWeightedBase 按域名字典序（与内仓 ComputeDomainScoresBayes 输出的排序一致）对
// 记录里的域分做加权平均；adjust 里的域先乘上修正系数（V/G/C 的 Score_d' = Base_d·P_d）。
func observedWeightedBase(t *testing.T, cfg *config.Config, ds model.DomainScores, adjust map[string]float64) float64 {
	t.Helper()

	weights := make(map[string]float64)
	for _, w := range ConfigToWeights(cfg) {
		weights[w.Domain] = w.Weight
	}

	scores := ds.GetAllDomainScores()
	domains := make([]string, 0, len(scores))
	for d := range scores {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	sum, totalWeight := 0.0, 0.0
	for _, d := range domains {
		w := weights[d]
		if w <= 0 {
			continue
		}
		s := scores[d]
		if pd, ok := adjust[d]; ok {
			s *= pd
		}
		sum += s * w
		totalWeight += w
	}
	if totalWeight == 0 {
		t.Fatal("夹具没有任何正权重域 —— 复算无法进行")
	}
	return sum / totalWeight
}

// domainCorrections 用链复现 V/G/C 的逐域系数 P_d（spec §3.1）：
//
//	eff_i   = edgefactor.EffectiveFactor(观测值, c_trigger)   ← **第二次衰减**（spec §10.2）
//	a_i[d]  = (1 − eff_i) · v_i[d]
//	L_d     = Σ_i a_i[d] + Σ_{i<j} c_ij · a_i[d] · a_j[d]     （graph 对称，只计一次）
//	P_d     = p_floor + (1 − p_floor) · exp(−λ_d · L_d)
//
// 累加顺序刻意与内仓 Synthesize 一致（贡献项按因子 ID 序、耦合项按 (i,j) 序），
// 否则浮点加法不满足结合律，逐位一致会变成偶然。
func domainCorrections(t *testing.T, p edgefactor.Params, chain []model.EdgeFactorObservation) map[string]float64 {
	t.Helper()

	req := edgefactor.RequestedDomains(p)
	if len(req) == 0 {
		t.Fatal("夹具的 λ 没有覆盖任何默认域 —— 复算无法进行")
	}

	ids := make([]string, 0, len(chain))
	contribs := make([][]float64, 0, len(chain))
	for _, ob := range chain {
		id := edgefactor.NormalizeFactorID(ob.Factor)
		eff := edgefactor.EffectiveFactor(ob.EffectiveFactor, ob.CTrigger)
		vec := factorVector(p, id, req)
		row := make([]float64, len(req))
		for k := range req {
			row[k] = (1 - eff) * vec[k]
		}
		ids = append(ids, id)
		contribs = append(contribs, row)
	}

	L := make([]float64, len(req))
	for i := range contribs {
		for k := range req {
			L[k] += contribs[i][k]
		}
	}
	for i := 0; i < len(contribs); i++ {
		for j := i + 1; j < len(contribs); j++ {
			c := graphCoupling(p, ids[i], ids[j])
			if c == 0 {
				continue
			}
			for k := range req {
				L[k] += c * contribs[i][k] * contribs[j][k]
			}
		}
	}

	P := make(map[string]float64, len(req))
	for k, d := range req {
		P[d] = p.PFloor + (1-p.PFloor)*math.Exp(-p.Lambda[d]*L[k])
	}
	return P
}

// factorVector 取因子 i 在各请求域上的向量分量；未声明向量的因子按"作用于全部域、强度 1"
// 处理（与内仓 Synthesize 的默认语义一致）。
func factorVector(p edgefactor.Params, id string, domains []string) []float64 {
	out := make([]float64, len(domains))
	vec, ok := p.Vectors[id]
	if !ok {
		for i := range out {
			out[i] = 1.0
		}
		return out
	}
	for i, d := range domains {
		out[i] = vec[d]
	}
	return out
}

// graphCoupling 取耦合系数：graph 对称，任一方向配置均可（与内仓 couplingValue 同口径）。
func graphCoupling(p edgefactor.Params, from, to string) float64 {
	if tos, ok := p.Coupling[from]; ok {
		if c, ok := tos[to]; ok {
			return c
		}
	}
	if tos, ok := p.Coupling[to]; ok {
		if c, ok := tos[from]; ok {
			return c
		}
	}
	return 0
}
