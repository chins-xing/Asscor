//go:build edgeexp

package main

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// legacyParams 是样例记录配的 legacy 候选：模型权重 EF-SELINUX = 0.8（config.ini 出厂值）。
func legacyParams() edgefactor.Params {
	return edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5,
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
}

// twoDomainWeights 与样例记录的两个域一一对应。
func twoDomainWeights() map[string]float64 {
	return map[string]float64{"attack_surface": 1, "operation_trust": 1}
}

// assemblyDecay 是在线装配层 `ActivationFromResult` 的换算口径：对**已经过 ssam-lib 策略
// 衰减一次**的因子值再衰减一次 ⇒ 合计 1−(1−f)·c²（spec §10.2 的既有口径，本任务复用它，
// 不修正）。样例记录：f=0.8、c=0.9 ⇒ 策略层 0.82 ⇒ 装配层 0.838。
//
// **它只适用于 V/G/C**（合成层在域级修正前做这次换算）；legacy 走引擎默认策略，
// 直接乘记录里的 `effective_factor`（单次衰减），见 engineEdgeFactors 的注释。
func assemblyDecay(chainValue, cTrigger float64) float64 {
	return edgefactor.EffectiveFactor(chainValue, cTrigger)
}

// engineTotalOf 按 `ssam.SSAMV20Formula` 的式子**手算期望总分**（夹具期望值的推导，
// 不是对拍用的第二实现 —— 对拍由 consistency_test.go 直接调用内仓的真公式完成）：
//
//	base_adj = round2(base)            // 内仓公式先对 base 取整到两位
//	总分     = round2(0.5·base_adj + 30·E + 20·T)
//
// 式子与内仓逐项对齐（含两次取整的位置），断言失败时能一眼看出是哪一项算错了。
func engineTotalOf(base, spc, threat float64) float64 {
	rounded := math.Round(base*100) / 100
	weightedAvg := (rounded/100*50 + spc*30 + threat*20) / 100
	return math.Round(weightedAvg*100*100) / 100
}

func TestEvaluateFalseNegativeCounted(t *testing.T) {
	recs, _ := LoadRecords(writeSample(t))
	// 样例记录（域分 90/90、因子观测值 0.82、spc 0.8、threat 0.7、阈值 60）：
	// 引擎总分 = round2(0.5×73.8 + 30×0.8 + 20×0.7) = 74.9 ≥ 60 ⇒ acceptable，
	// 而客观被攻陷 ⇒ 漏判（FN）。
	m, err := Evaluate(recs, legacyParams(), twoDomainWeights())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if m.N != 1 || m.FalseNegativeRate != 1 {
		t.Errorf("expected FN rate 1.0 for an accepted-but-compromised scenario, got %+v", m)
	}
	if m.DecisionAgreement != 0 || m.FalsePositiveRate != 0 {
		t.Errorf("expected disagreement 1.0 / FP rate 0 for a missed detection, got %+v", m)
	}
}

// TestOfflineScoreUsesTheObservedFactorLikeTheEngine 钉住 C1 之后 legacy 的因子口径：
// **直接用记录里的 `effective_factor`**（策略层已按 c_trigger 衰减一次的观测值），
// 因为引擎的默认策略乘的就是 `EdgeFactorResult.Factor`。
//
// 旧实现在这里再衰减一次（0.82 → 0.838），于是离线分数比引擎**高**（惩罚更轻、更乐观），
// 与部署行为不是同一个量 —— 这正是 C1 要消除的口径差。本用例把两个方向都钉住：
// 分数必须等于单次衰减的引擎总分，且**不得**等于双衰减的那个值。
func TestOfflineScoreUsesTheObservedFactorLikeTheEngine(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	chain := recs[0].Observed.EdgeFactorChain[0]
	if chain.EffectiveFactor != 0.82 || chain.CTrigger != 0.9 {
		t.Fatalf("fixture changed: %+v", chain)
	}

	score, err := OfflineScoreWithWeights(legacyParams(), recs[0], twoDomainWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	spc, threat := recs[0].Observed.SPCScore, recs[0].Observed.ThreatCoeff
	// 单次衰减（引擎口径）：base = 90 × 0.82 = 73.8。
	if want := engineTotalOf(90*chain.EffectiveFactor, spc, threat); score != want {
		t.Errorf("score = %v, want %v（90 × 记录里的 effective_factor 0.82 的引擎总分）", score, want)
	}
	// 双衰减（旧口径）：base = 90 × 0.838 —— 必须**不**等于它。
	doubleDecay := assemblyDecay(chain.EffectiveFactor, chain.CTrigger)
	if double := engineTotalOf(90*doubleDecay, spc, threat); score == double {
		t.Errorf("score = %v 等于双衰减口径（%v）—— legacy 又走上了装配层换算", score, double)
	}
	if score == engineTotalOf(90, spc, threat) {
		t.Errorf("score = %v: 因子惩罚没有生效", score)
	}
	// 与在线观测的 final_score 逐位一致：这是"同一个量"的最直接证据。
	if score != recs[0].Observed.FinalScore {
		t.Errorf("离线重算 %v ≠ 在线观测 final_score %v", score, recs[0].Observed.FinalScore)
	}
}

// TestLegacyAppliesMultiplierToAggregatedTotal 钉住 legacy 的层次：域分不被逐域修正，
// ∏effective_f 作用于**聚合之后的 base**（内仓默认的逐次相乘路径）；
// 同一条记录上 vector 走的是"先逐域修正再聚合"的另一支，两者必须给出不同的分数。
func TestLegacyAppliesMultiplierToAggregatedTotal(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{"attack_surface": 2, "operation_trust": 1}
	spc, threat := recs[0].Observed.SPCScore, recs[0].Observed.ThreatCoeff

	legacyScore, err := OfflineScoreWithWeights(legacyParams(), recs[0], weights)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	mult := recs[0].Observed.EdgeFactorChain[0].EffectiveFactor // 0.82（引擎侧直接乘它）
	if want := engineTotalOf((90*2+90*1)/3.0*mult, spc, threat); legacyScore != want {
		t.Errorf("legacy score = %v, want 加权聚合 × 观测因子 = %v", legacyScore, want)
	}

	vec := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
	vecScore, err := OfflineScoreWithWeights(vec, recs[0], weights)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	// 域级系数 P_d（λ=1、v=0.5）：有效因子经**装配层**换算（双衰减 0.838），
	// 惩罚作用在**每个域**上，聚合发生在修正之后。
	eff := assemblyDecay(mult, recs[0].Observed.EdgeFactorChain[0].CTrigger)
	p := 0.5 + 0.5*math.Exp(-1.0*((1-eff)*0.5))
	if want := engineTotalOf((90*p*2+90*p*1)/3.0, spc, threat); math.Abs(vecScore-want) > 1e-12 {
		t.Errorf("vector score = %v, want 逐域修正后聚合再进公式 = %v", vecScore, want)
	}
	if vecScore == legacyScore {
		t.Errorf("legacy 与 vector 走了同一条聚合支路（%v）", vecScore)
	}
}

// TestVectorTrimsToLambdaDomainsAndPassesThroughOthers 钉住裁剪口径「DefaultDomains ∩ λ」：
// 未配 λ 的域**不做**域级修正，但它在聚合里仍应使用**观测值**
// （在线 DomainAdjust 对不在计划内的域原样放行），不能被当成 0。
func TestVectorTrimsToLambdaDomainsAndPassesThroughOthers(t *testing.T) {
	const rec = `{"scenario_id":"S2-partial","factors":["EF-SELINUX"],"observed":{"domain_scores":{"attack_surface":90,"operation_trust":60,"resilience":30},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true}}`
	recs, err := LoadRecords(writeJSONL(t, "partial.jsonl", rec+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1, "resilience": 1}

	score, err := OfflineScoreWithWeights(p, recs[0], weights)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	spc, threat := recs[0].Observed.SPCScore, recs[0].Observed.ThreatCoeff
	eff := assemblyDecay(0.82, 0.9)
	pd := 0.5 + 0.5*math.Exp(-1.0*((1-eff)*0.5))
	want := engineTotalOf((90*pd+60*pd+30*1)/3.0, spc, threat)
	if math.Abs(score-want) > 1e-12 {
		t.Errorf("score = %v, want %v (未配 λ 的域必须原样参与聚合)", score, want)
	}
	if zeroed := engineTotalOf((90*pd+60*pd+0)/3.0, spc, threat); math.Abs(score-zeroed) < 1e-12 {
		t.Errorf("score = %v: 未配 λ 的域被当成 0 参与聚合", score)
	}
}

// TestVectorWithoutAnyDefaultLambdaFailsFast：λ 一个默认域都没覆盖 ⇒ 任何域都不会被修正，
// 与在线装配期的同款 fail-fast 一致（禁止"戳记写着某模型、评分分毫未变"的假溯源）。
func TestVectorWithoutAnyDefaultLambdaFailsFast(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"not_a_domain": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"not_a_domain": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
	if _, err := Evaluate(recs, p, twoDomainWeights()); err == nil {
		t.Fatal("expected a fail-fast error when no default domain has a lambda")
	} else if !strings.Contains(err.Error(), "lambda") {
		t.Errorf("error should name the missing lambda coverage: %v", err)
	}
}

// chainJSONL 是 chain 场景（spec §5 的 S5 级联组）的样例：两个因子共用触发检查 OT-005，
// EF-SELINUX 级联到 EF-APPARMOR，时间戳由参数给出（离线 chain 的唯一时间来源）。
// 与其它夹具一样必须是**一行**（JSONL：一行一条记录）。
func chainJSONL(secondTS string) string {
	return fmt.Sprintf(`{"scenario_id":"S5-cascade","factors":["EF-SELINUX","EF-APPARMOR"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90},"final_score":80,"acceptable":true,"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:00Z"},{"factor":"EF-APPARMOR","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":%q}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3},"meta":{"env":"wsl-clab-14","run":1}}`, secondTS)
}

func chainParams() edgefactor.Params {
	return edgefactor.Params{Model: edgefactor.ModelChain, PFloor: 0.5, ChainWindowSeconds: 60,
		Lambda: map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{
			"EF-SELINUX":  {"attack_surface": 0.5},
			"EF-APPARMOR": {"attack_surface": 0.5},
		},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}},
		Factors:  map[string]float64{"EF-SELINUX": 0.8, "EF-APPARMOR": 0.8}}
}

// TestChainUsesJSONLTimestampsOffline 钉住 mandate 口径 3：chain 是离线专用模型，它的时间戳
// 来自 JSONL 的 `edge_factor_chain[].ts`——窗口内的级联必须生效，窗口外必须不生效。
func TestChainUsesJSONLTimestampsOffline(t *testing.T) {
	within, err := LoadRecords(writeJSONL(t, "within.jsonl", chainJSONL("2026-09-08T10:00:30Z")+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords(within): %v", err)
	}
	outside, err := LoadRecords(writeJSONL(t, "outside.jsonl", chainJSONL("2026-09-08T10:05:00Z")+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords(outside): %v", err)
	}
	weights := map[string]float64{"attack_surface": 1}
	spc, threat := within[0].Observed.SPCScore, within[0].Observed.ThreatCoeff

	// c_trigger=1 ⇒ 两次衰减恒等，有效值 = 0.8；a_i = (1−0.8)·0.5 = 0.1。
	gotWithin, err := OfflineScoreWithWeights(chainParams(), within[0], weights)
	if err != nil {
		t.Fatalf("chain(within): %v", err)
	}
	lWithin := 0.1 + 0.1 + 0.35*0.1*0.1 // 级联项 c·a_i·a_j
	pWithin := 0.5 + 0.5*math.Exp(-1.0*lWithin)
	if want := engineTotalOf(90*pWithin, spc, threat); math.Abs(gotWithin-want) > 1e-12 {
		t.Errorf("chain(within) = %v, want %v (窗口内级联应生效)", gotWithin, want)
	}

	gotOutside, err := OfflineScoreWithWeights(chainParams(), outside[0], weights)
	if err != nil {
		t.Fatalf("chain(outside): %v", err)
	}
	pOutside := 0.5 + 0.5*math.Exp(-1.0*0.2)
	if want := engineTotalOf(90*pOutside, spc, threat); math.Abs(gotOutside-want) > 1e-12 {
		t.Errorf("chain(outside) = %v, want %v (超出窗口不应级联)", gotOutside, want)
	}
	if gotWithin == gotOutside {
		t.Errorf("时间戳没有影响结果（%v）：chain 的时序语义未生效", gotWithin)
	}
}

// TestChainWithoutTimestampFailsFast：JSONL 缺 ts 时 chain 必须 fail-fast（内仓 Synthesize 的
// 既有约定），绝不静默退化成 vector —— 那样"用了 chain 模型"就是假溯源。
func TestChainWithoutTimestampFailsFast(t *testing.T) {
	recs, err := LoadRecords(writeSample(t)) // 样例记录的 chain 条目没有 ts
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if _, err := Evaluate(recs, chainParams(), twoDomainWeights()); err == nil {
		t.Fatal("expected a fail-fast error for a chain record without timestamps")
	} else if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error should name the missing timestamps: %v", err)
	}
}

// TestActivationsOfNormalizesAndConverts：链条目 → 合成层输入的换算点。
// ID 归一（消费侧口径，须与 ssam.NormalizeFactorID 一致）与可信度双衰减都在这里发生。
func TestActivationsOfNormalizesAndConverts(t *testing.T) {
	const rec = `{"scenario_id":"S1-lowercase","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"  ef-selinux  ","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82,"ts":"2026-09-08T10:00:03Z"}]},"ground_truth":{"compromised":true}}`
	recs, err := LoadRecords(writeJSONL(t, "lower.jsonl", rec+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	acts := activationsOf(recs[0])
	if len(acts) != 1 {
		t.Fatalf("got %d activations, want 1: %+v", len(acts), acts)
	}
	if acts[0].FactorID != "EF-SELINUX" {
		t.Errorf("FactorID = %q, want EF-SELINUX (消费侧归一)", acts[0].FactorID)
	}
	if want := assemblyDecay(0.82, 0.9); acts[0].EffectiveFactor != want {
		t.Errorf("EffectiveFactor = %v, want %v", acts[0].EffectiveFactor, want)
	}
	if acts[0].TS.IsZero() {
		t.Errorf("TS not parsed: %+v", acts[0])
	}
}

// TestEvaluateThreeLayers 用四条记录同时钉住三层指标的手算值。
// 决策层：引擎总分 = round2(0.5·round2(域分×0.82) + 30×0.8 + 20×0.7)，阈值 50。
//
//	R1 90 → 74.9 ≥50 接受 / 客观被攻陷 ⇒ 漏判（FN）
//	R2 10 → 42.1 <50 拒绝 / 客观被攻陷 ⇒ 正确
//	R3 90 → 74.9 ≥50 接受 / 客观未被攻陷 ⇒ 正确
//	R4 10 → 42.1 <50 拒绝 / 客观未被攻陷 ⇒ 误阻断（FP）
//
// 排序层：本组记录刻意包含一例漏判与一例误阻断（模型是**失败**的），R1 与 R3 的模型分数
// 完全相同而客观结果相反 ⇒ 分数与严重度呈**正**相关（秩：分数 [3.5,1.5,3.5,1.5]、
// 严重度 [4,3,1.5,1.5]）：
//
//	Spearman = 4/√288 ≈ +0.2357，Kendall = +1/3。
//
// 正常情况下「分数越高越安全」应给出**负**相关（见 severityOf 的注释）；这里为正恰好说明
// 排序层能如实反映"同一份真实数据下这个候选没有把两类场景分开"。
// 数值层：AUC 以 (100−score) 为危险度 ⇒ 0.5（两类各两例、且危险度完全重合）。
func TestEvaluateThreeLayers(t *testing.T) {
	rec := func(id string, as float64, compromised bool, ttc float64, ttps, nodes int) string {
		return fmt.Sprintf(`{"scenario_id":%q,"factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":%v},"final_score":0,"acceptable":true,"threshold":50,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":%t,"time_to_compromise_s":%v,"ttps_achieved":%d,"nodes_affected":%d,"block_effective":false},"meta":{"env":"test","run":1}}`, id, as, compromised, ttc, ttps, nodes)
	}
	content := strings.Join([]string{
		rec("R1", 90, true, 213, 4, 3),
		rec("R2", 10, true, 600, 2, 1),
		rec("R3", 90, false, 0, 0, 0),
		rec("R4", 10, false, 0, 0, 0),
	}, "\n") + "\n"
	recs, err := LoadRecords(writeJSONL(t, "layers.jsonl", content))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	m, err := Evaluate(recs, legacyParams(), map[string]float64{"attack_surface": 1})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if m.N != 4 {
		t.Fatalf("N = %d, want 4", m.N)
	}
	close := func(name string, got, want float64) {
		t.Helper()
		if math.Abs(got-want) > 1e-12 {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	// 决策层：FN/FP 都是「占样本比」（brief 给定的定义），不是条件率。
	close("DecisionAgreement", m.DecisionAgreement, 0.5)
	close("FalseNegativeRate", m.FalseNegativeRate, 0.25)
	close("FalsePositiveRate", m.FalsePositiveRate, 0.25)
	// 排序层：本组记录下模型未能把两类场景分开，故为正相关（符号见上方逐条推导）。
	close("Spearman", m.Spearman, 4/math.Sqrt(288))
	close("Kendall", m.Kendall, 1.0/3.0)
	// 数值层。
	close("AUC", m.AUC, 0.5)
}

// TestUnmodeledFactorIsDropped 钉住"候选未建模的因子不进合成输入"这条口径（与在线消费者
// `ssam.activationsFromResults` 一致）：否则 Params.Vectors 查表落空后会**静默**按
// "作用于全部域、强度 1"计入惩罚，让一个未建模的因子凭空产生比配置更强的惩罚。
// 对照组（EF-SYNCOOKIE 在候选的 Factors 里）必须**改变**分数，证明过滤器不是把因子全丢了。
func TestUnmodeledFactorIsDropped(t *testing.T) {
	const content = `{"scenario_id":"A","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8}]},"ground_truth":{"compromised":true}}
{"scenario_id":"B","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8},{"factor":"EF-3FA","c_trigger":1.0,"effective_factor":0.5}]},"ground_truth":{"compromised":true}}
{"scenario_id":"C","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8},{"factor":"EF-SYNCOOKIE","c_trigger":1.0,"effective_factor":0.5}]},"ground_truth":{"compromised":true}}
`
	recs, err := LoadRecords(writeJSONL(t, "unmodeled.jsonl", content))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5,
		Factors: map[string]float64{"EF-SELINUX": 0.8, "EF-SYNCOOKIE": 0.75}}
	weights := map[string]float64{"attack_surface": 1}

	scoreA, err := OfflineScoreWithWeights(p, recs[0], weights)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	// 引擎公式：base = round2(90×0.8) = 72 ⇒ 总分 = round2(0.5×72 + 30×0.8 + 20×0.7) = 74。
	spc, threat := recs[0].Observed.SPCScore, recs[0].Observed.ThreatCoeff
	if want := engineTotalOf(90*0.8, spc, threat); scoreA != want {
		t.Fatalf("A = %v, want %v", scoreA, want)
	}
	scoreB, err := OfflineScoreWithWeights(p, recs[1], weights)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if scoreB != scoreA {
		t.Errorf("EF-3FA 不在候选 Factors 里，必须被丢弃：B = %v, A = %v", scoreB, scoreA)
	}
	scoreC, err := OfflineScoreWithWeights(p, recs[2], weights)
	if err != nil {
		t.Fatalf("C: %v", err)
	}
	if want := engineTotalOf(90*0.8*0.5, spc, threat); scoreC != want {
		t.Errorf("C = %v, want %v（在途因子必须计入）", scoreC, want)
	}
}

// TestEvaluateEmptyRecordsIsZero：空数据集不是错误（工具需要能对空 JSONL 出报告）。
func TestEvaluateEmptyRecordsIsZero(t *testing.T) {
	m, err := Evaluate(nil, legacyParams(), twoDomainWeights())
	if err != nil {
		t.Fatalf("Evaluate(nil): %v", err)
	}
	if m.N != 0 || m.DecisionAgreement != 0 || m.Spearman != 0 || m.AUC != 0 {
		t.Errorf("expected zero metrics for an empty dataset, got %+v", m)
	}
}

// TestOfflineScoreEqualWeights：OfflineScore 是"等权"便捷入口；权重表里出现的域若在记录里
// 缺失，会以 0 计入并仍占一份权重（内仓公式 `SSAMV20Formula` 对权重表内的域一律计入分母）。
// 真实记录含全部 5 个域（spec §5.1），故该情形只出现在合成/最小夹具里。
//
// 样例记录只有 2 个域有观测（90/90），等权表给 5 个默认域各 1 份 ⇒ 聚合分 = 180/5 = 36。
func TestOfflineScoreEqualWeights(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	score, err := OfflineScore(legacyParams(), recs[0])
	if err != nil {
		t.Fatalf("OfflineScore: %v", err)
	}
	if want := engineTotalOf((90.0+90.0)/5.0*0.82, recs[0].Observed.SPCScore, recs[0].Observed.ThreatCoeff); score != want {
		t.Errorf("score = %v, want %v", score, want)
	}
}

// TestDomainAggregationIsBitwiseDeterministic（原 TestWeightedSumIsBitwiseDeterministic）：
// 域聚合必须**逐位可复现**。
//
// 为什么这是硬契约而不是"精度洁癖"：本方向的主门禁是「离线重算 ↔ 在线评分逐位一致」，
// 在线侧的域聚合顺序由**引擎**决定（`ssam.ComputeDomainScoresBayes` 输出的字典序，见
// `orderedDomains`）；若离线按 map 迭代序装域分切片，末位 1 ulp 会随机抖动
// ⇒ 门禁"偶然绿、偶然红"，同一份数据两次跑出不同结论时报告数字无法归因。
//
// 夹具刻意选 order-sensitive 的组合（宽动态范围 1e16/1e-16 + 不可精确表示的十进制
// 0.1/0.2/0.3），让"累加顺序不同的实现"必然在不同次调用间抖出差异；比较用
// reflect.DeepEqual，**不用容差** —— 容差会正好掩盖要抓的 1 ulp。
func TestDomainAggregationIsBitwiseDeterministic(t *testing.T) {
	scores := map[string]float64{
		"attack_surface":      0.1,
		"business_continuity": 0.2,
		"operation_trust":     0.3,
		"resilience":          1e16,
		"kernel_security":     1e-16,
		"zzz_custom":          7,
	}
	weights := map[string]float64{
		"attack_surface":      1,
		"business_continuity": 3,
		"operation_trust":     5,
		"resilience":          2,
		"kernel_security":     1,
		"zzz_custom":          4,
	}
	first := engineDomainScores(scores, weights)
	for i := 0; i < 100; i++ {
		got := engineDomainScores(scores, weights)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("第 %d 次装出的域分切片与首次不同（聚合不可复现）：%v vs %v", i+1, got, first)
		}
	}
	// 切片顺序契约本身：**域名字典序**（= 引擎 `ComputeDomainScoresBayes` 输出的顺序 ——
	// Task 3B Step 2 改掉了旧的"DefaultDomains 在前、其余按字典序追加"，理由见 orderedDomains）；
	// 权重 ≤ 0 的域不进切片（与内仓公式 `w > 0` 的判据同义）。
	wantOrder := []string{"attack_surface", "business_continuity", "kernel_security", "operation_trust", "resilience", "zzz_custom"}
	if got := orderedDomains(weights); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("orderedDomains = %v, want %v（必须与引擎的域分切片同序：字典序）", got, wantOrder)
	}
	if len(first) != len(wantOrder) || first[0].Domain != "attack_surface" || first[5].Domain != "zzz_custom" {
		t.Errorf("域分切片顺序不对：%+v", first)
	}
	zero := map[string]float64{"attack_surface": 1, "resilience": 0}
	if got := engineDomainScores(scores, zero); len(got) != 1 || got[0].Domain != "attack_surface" {
		t.Errorf("权重为 0 的域不得进入域分切片：%+v", got)
	}
	// 非默认键与默认键**混在同一个字典序里**（实现按整表排序，不区分"默认/非默认"）——
	// 旧的"其余键追加在末尾"在这一组上会给出 operation_trust/aaa/zzz。
	rest := map[string]float64{"operation_trust": 1, "zzz": 1, "aaa": 1}
	if got, want := orderedDomains(rest), []string{"aaa", "operation_trust", "zzz"}; !reflect.DeepEqual(got, want) {
		t.Errorf("orderedDomains(含非默认键) = %v, want %v", got, want)
	}
}

// TestEvaluateIsBitwiseDeterministic：整条离线重算路径（引擎公式 + 钩子注入 + 三层指标）
// 也必须逐位可复现 —— 报告与门禁都建立在这个契约上。
func TestEvaluateIsBitwiseDeterministic(t *testing.T) {
	const rec = `{"scenario_id":"S2-all-domains","factors":["EF-SELINUX"],"observed":{"domain_scores":{"attack_surface":0.1,"business_continuity":0.2,"operation_trust":0.3,"resilience":71.7,"kernel_security":55.1},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3}}`
	recs, err := LoadRecords(writeJSONL(t, "determinism.jsonl", rec+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		weights[d] = 1
	}
	firstScore, err := OfflineScoreWithWeights(legacyParams(), recs[0], weights)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	firstMetrics, err := Evaluate(recs, legacyParams(), weights)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for i := 0; i < 100; i++ {
		score, err := OfflineScoreWithWeights(legacyParams(), recs[0], weights)
		if err != nil {
			t.Fatalf("第 %d 次 OfflineScoreWithWeights: %v", i+1, err)
		}
		if !reflect.DeepEqual(firstScore, score) {
			t.Fatalf("第 %d 次总分与首次逐位不同：%v vs %v", i+1, score, firstScore)
		}
		m, err := Evaluate(recs, legacyParams(), weights)
		if err != nil {
			t.Fatalf("第 %d 次 Evaluate: %v", i+1, err)
		}
		if !reflect.DeepEqual(firstMetrics, m) {
			t.Fatalf("第 %d 次三层指标与首次逐位不同：%+v vs %+v", i+1, m, firstMetrics)
		}
	}
}

// TestEvaluateRejectsWeightsForMissingDomains（Fix round 2 / 评审 I2 的另一半）：
// 「有权重、却无观测域分」的记录会以 0 参与聚合（仍占一份权重）⇒ 静默压低总分、翻转
// `acceptable` 判定，而报告看不出异常；决策层入口必须拒绝，并点名场景与域。
func TestEvaluateRejectsWeightsForMissingDomains(t *testing.T) {
	recs, err := LoadRecords(writeSample(t)) // 该记录只有 attack_surface / operation_trust
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	// 对照：两个域都有 ⇒ 正常评估。
	if _, err := Evaluate(recs, legacyParams(), twoDomainWeights()); err != nil {
		t.Fatalf("覆盖完整的权重表不应报错：%v", err)
	}
	// 反例：给一个记录里没有的域权重。
	_, err = Evaluate(recs, legacyParams(), map[string]float64{"attack_surface": 1, "operation_trust": 1, "resilience": 1})
	if err == nil {
		t.Fatal("expected a fail-fast error for a weighted domain missing from the record")
	}
	msg := err.Error()
	for _, want := range []string{"S1-selinux", "resilience"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must name %q: %v", want, err)
		}
	}
	// 权重为 0（或负）的域不参与聚合，故不要求覆盖 —— 否则"只想算一个域"的调用会被误拒。
	if _, err := Evaluate(recs, legacyParams(), map[string]float64{"attack_surface": 1, "resilience": 0}); err != nil {
		t.Errorf("权重为 0 的域不应要求覆盖：%v", err)
	}
}

// recordWeightsJSONL 是"记录自带生效权重"的夹具（Task 3B Step 1）。
//
// 域分 90/30，**记录自带** `effective_weights` = attack_surface:3 / operation_trust:1（比例 3:1，
// 即引擎归一后的生效表），而调用方给的是**另一张**等权表：
//
//	记录表  ⇒ (90×3 + 30×1)/4 = 75
//	调用方表 ⇒ (90×1 + 30×1)/2 = 60
//
// 两个数刻意不同 ⇒ "谁赢"是可观测的，而不是"两张表恰好同值"。
const recordWeightsJSONL = `{"scenario_id":"S2-record-weights","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90,"operation_trust":30},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"effective_weights":{"attack_surface":3,"operation_trust":1},"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","run":1}}`

// recordWeightsRecords 读回上面的夹具。
func recordWeightsRecords(t *testing.T) []Record {
	t.Helper()
	recs, err := LoadRecords(writeJSONL(t, "record-weights.jsonl", recordWeightsJSONL+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 1 || len(recs[0].Observed.EffectiveWeights) == 0 {
		t.Fatalf("夹具失效（记录必须自带生效权重表）: %+v", recs)
	}
	return recs
}

// callerWeightsForRecordWeights 是"命令行 `-weights`"那一侧的表：与记录自带的表**比例不同**。
func callerWeightsForRecordWeights() map[string]float64 {
	return map[string]float64{"attack_surface": 1, "operation_trust": 1}
}

// TestRecordEffectiveWeightsWinOverTheCallerTable（Task 3B Step 1 / spec §5.1 前提 2）：
// 记录**自带**的生效权重表是权威 —— 它决定"哪些域参与聚合、各占多少权重"。
//
// 为什么必须由记录决定（而不是 `-weights` 覆盖它）：引擎交付的是**归一化之后**的生效权重
// （`DynamicScoringEngine` 给 0 权重域填默认值再 `Normalize(100)`），归一化**不可逆** ——
// 计划里那串 `-weights`（35/25/25/15/10，和 110）与引擎归一后的比例本就不同，于是"以
// `-weights` 为准"会让 round-trip 门禁在**合法记录**上变红，看起来像数据缺陷。
//
// 两个方向都钉住：①记录表在场时必须赢；②把该字段抹掉后必须**回到**调用方表（= 本字段引入
// 之前的行为，既有数据集不破）。
func TestRecordEffectiveWeightsWinOverTheCallerTable(t *testing.T) {
	rec := recordWeightsRecords(t)[0]
	spc, threat := rec.Observed.SPCScore, rec.Observed.ThreatCoeff
	caller := callerWeightsForRecordWeights()

	got, err := OfflineScoreWithWeights(legacyParams(), rec, caller)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	wantRecord := engineTotalOf((90*3+30*1)/4.0*0.82, spc, threat)
	if got != wantRecord {
		t.Errorf("离线总分 = %v, want %v（记录自带的生效权重 (90×3+30×1)/4 决定聚合）", got, wantRecord)
	}
	wantCaller := engineTotalOf((90*1+30*1)/2.0*0.82, spc, threat)
	if got == wantCaller {
		t.Errorf("离线总分 = %v 等于按调用方 `-weights` 算出的值（%v）—— 记录自带的权重表被忽略了", got, wantCaller)
	}

	// 反向对照：记录**没有**该字段时必须回退到调用方表（既有夹具/历史数据集的行为不变）。
	recWithout := rec
	recWithout.Observed.EffectiveWeights = nil
	gotFallback, err := OfflineScoreWithWeights(legacyParams(), recWithout, caller)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights(无 effective_weights): %v", err)
	}
	if gotFallback != wantCaller {
		t.Errorf("回退分支 = %v, want %v（记录没带权重表时必须用调用方那张，且算术逐位不变）",
			gotFallback, wantCaller)
	}
	if gotFallback == wantRecord {
		t.Errorf("回退分支得出了记录表的结果（%v）—— 反向对照失效", gotFallback)
	}
}

// TestEvaluateDomainCoverageFollowsTheRecordWeights（Task 3B Step 1，门禁① 的落点）：
// 域覆盖判据必须与实际参与聚合的域集**同源**。
//
// 危害（Task 3 复审实测）：`validateDomainsCovered` 要求记录的 `domain_scores` 覆盖 `-weights`
// 的每个域，于是 `-weights` 里多写一个部署根本没聚合的域（例如该部署没有 resilience 检查），
// 就会让门禁① 在**合法记录**上以"缺域"报错 —— 而记录里明明写着它自己的域集。
func TestEvaluateDomainCoverageFollowsTheRecordWeights(t *testing.T) {
	recs := recordWeightsRecords(t)
	// 调用方表多一个部署没有聚合的域：以记录为准时它根本不参与聚合，不该报覆盖错误。
	caller := map[string]float64{"attack_surface": 1, "operation_trust": 1, "resilience": 1}

	if _, err := Evaluate(recs, legacyParams(), caller); err != nil {
		t.Fatalf("记录自带的生效权重决定参与聚合的域集，`-weights` 里多出的域不该触发覆盖错误: %v", err)
	}

	// 反向对照：同一条记录**没有**该字段时，同一张调用方表必须照旧报错 ——
	// 否则本用例只证明了"判据被删掉了"，而不是"判据跟着权重来源走"。
	recs[0].Observed.EffectiveWeights = nil
	_, err := Evaluate(recs, legacyParams(), caller)
	if err == nil {
		t.Fatal("记录没带生效权重表时必须回退到调用方表并报覆盖错误（= 本字段引入前的行为）")
	}
	if !strings.Contains(err.Error(), "resilience") {
		t.Errorf("覆盖错误必须点名那个域: %v", err)
	}
}

// vgcJSONL 是 V/G/C 确定性断言用的 5 域记录：两个因子共用触发检查 OT-005，
// EF-SELINUX → EF-APPARMOR 级联（带时间戳，chain 候选要用），时间间隔 30s。
const vgcJSONL = `{"scenario_id":"S5-cascade-vgc","factors":["EF-SELINUX","EF-APPARMOR"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":0.1,"business_continuity":0.2,"operation_trust":0.3,"resilience":71.7,"kernel_security":55.1},"final_score":0,"acceptable":true,"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:00Z"},{"factor":"EF-APPARMOR","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82,"ts":"2026-09-08T10:00:30Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","run":1}}`

// vgcParams 返回同一套参数下的 graph / chain 两个候选。
func vgcParams() []struct {
	name string
	p    edgefactor.Params
} {
	base := edgefactor.Params{
		Model: edgefactor.ModelGraph, PFloor: 0.5,
		Lambda: map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{
			"EF-SELINUX":  {"attack_surface": 0.5, "operation_trust": 0.5},
			"EF-APPARMOR": {"attack_surface": 0.5, "operation_trust": 0.5},
		},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}},
		Factors:  map[string]float64{"EF-SELINUX": 0.8, "EF-APPARMOR": 0.82},
	}
	chain := base
	chain.Model = edgefactor.ModelChain
	chain.ChainWindowSeconds = 60
	return []struct {
		name string
		p    edgefactor.Params
	}{{"graph", base}, {"chain", chain}}
}

// TestEvaluateIsBitwiseDeterministicForVGC（Fix round 2 顺手项 M5 扩展）：把确定性断言从
// legacy + 单因子扩到 **graph / chain** 候选。
//
// `Synthesize` 内部对因子贡献项已按 ID 定序（那是内仓性质测试的范围），但"域级修正后的聚合"
// 与"chain 的时序窗口判定"仍要经过本工具的代码路径（钩子注入与拆除、权重定序、阈值判定），
// 故这里用 5 域记录 + 两个共触发且级联的因子把 V/G/C 也钉住：同一输入必须逐位可复现。
func TestEvaluateIsBitwiseDeterministicForVGC(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "vgc.jsonl", vgcJSONL+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1}

	for _, cand := range vgcParams() {
		t.Run(cand.name, func(t *testing.T) {
			firstScore, err := OfflineScoreWithWeights(cand.p, recs[0], weights)
			if err != nil {
				t.Fatalf("OfflineScoreWithWeights: %v", err)
			}
			firstMetrics, err := Evaluate(recs, cand.p, weights)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			for i := 0; i < 100; i++ {
				score, err := OfflineScoreWithWeights(cand.p, recs[0], weights)
				if err != nil {
					t.Fatalf("第 %d 次 OfflineScoreWithWeights: %v", i+1, err)
				}
				if !reflect.DeepEqual(firstScore, score) {
					t.Fatalf("第 %d 次总分与首次逐位不同：%v vs %v", i+1, score, firstScore)
				}
				m, err := Evaluate(recs, cand.p, weights)
				if err != nil {
					t.Fatalf("第 %d 次 Evaluate: %v", i+1, err)
				}
				if !reflect.DeepEqual(firstMetrics, m) {
					t.Fatalf("第 %d 次三层指标与首次逐位不同：%+v vs %+v", i+1, m, firstMetrics)
				}
			}
		})
	}
}

// TestOfflineRejectsNonDefaultDomainKeys（Task 8 评审 M6 的收口）：离线重算必须**拒绝**
// 非默认域的 λ / 向量键，而不是静默裁掉它们。
//
// 为什么这条重要：在线装配期对这类配置是**硬报错**（`edgefactor.Validate` 的
// `lambda for unknown domain`，`ssam.ParamsFromConfig` 在完整默认域列表上跑），而离线此前
// 直接按 `DefaultDomains ∩ λ` 裁剪 ⇒ 一个把 `operation_trust` 拼错的配置会在离线拿到一份
// 看起来有效的报告，而它**永远装不上**。Task 10 的"离线↔在线一致"门禁在这类数据上无法归因
// （两侧一个报错、一个出数）。
//
// 反向对照是必需的：把同一个键改回默认域后必须能正常算分 —— 否则上面两条断言只证明了
// "这个候选什么都算不了"。
func TestOfflineRejectsNonDefaultDomainKeys(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1}

	newCandidate := func() edgefactor.Params {
		return edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
			Lambda:  map[string]float64{"attack_surface": 1.0},
			Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 1.0}},
			Factors: map[string]float64{"EF-SELINUX": 0.8}}
	}

	// 反向对照（先做）：未被打错的候选必须能算。
	if _, err := OfflineScoreWithWeights(newCandidate(), recs[0], weights); err != nil {
		t.Fatalf("对照候选（键都在默认域上）应当能算分: %v", err)
	}

	t.Run("lambda 的域拼错", func(t *testing.T) {
		p := newCandidate()
		p.Lambda["operaton_trust"] = 1.0 // 拼错：operation_trust
		_, err := OfflineScoreWithWeights(p, recs[0], weights)
		if err == nil {
			t.Fatal("非默认域的 lambda 键被静默裁掉并照常算分 —— 会产出一份「永远装不上」的候选的报告")
		}
		if !strings.Contains(err.Error(), "operaton_trust") {
			t.Errorf("错误信息必须点名那个键，实际是: %v", err)
		}
	})

	t.Run("向量的分量域拼错", func(t *testing.T) {
		p := newCandidate()
		p.Vectors["EF-SELINUX"]["operaton_trust"] = 0.5
		_, err := OfflineScoreWithWeights(p, recs[0], weights)
		if err == nil {
			t.Fatal("非默认域的向量分量被静默裁掉并照常算分")
		}
		if !strings.Contains(err.Error(), "operaton_trust") {
			t.Errorf("错误信息必须点名那个域，实际是: %v", err)
		}
	})
}
