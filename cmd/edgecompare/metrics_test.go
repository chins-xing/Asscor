//go:build edgeexp

package main

import (
	"fmt"
	"math"
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
func assemblyDecay(chainValue, cTrigger float64) float64 {
	return edgefactor.EffectiveFactor(chainValue, cTrigger)
}

func TestEvaluateFalseNegativeCounted(t *testing.T) {
	recs, _ := LoadRecords(writeSample(t))
	// legacy 候选 + 现状乘性路径：域分不被逐域修正，∏effective_f 作用于聚合总分。
	// 本记录聚合分 90、乘子 0.838（双衰减口径）⇒ 75.42 ≥ 阈值 60 ⇒ 判 acceptable，
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

// TestOfflineScoreUsesAssemblyConfidenceDecay 钉住 mandate 口径 2：离线必须复用在线装配层
// 的换算（1−(1−f)·c，配合 ssam-lib 策略层已衰减过一次 ⇒ 合计 1−(1−f)c²），而不是把记录里
// 的 effective_factor 直接用掉（那会少衰减一次，也是 Task 7 评审 I2 记录在案的口径差）。
func TestOfflineScoreUsesAssemblyConfidenceDecay(t *testing.T) {
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
	doubleDecay := assemblyDecay(chain.EffectiveFactor, chain.CTrigger) // 0.838
	singleDecay := chain.EffectiveFactor                                // 0.82

	if score != 90*doubleDecay {
		t.Errorf("score = %v, want aggregate(90) × 1-(1-f)c² = %v", score, 90*doubleDecay)
	}
	if score == 90*singleDecay {
		t.Errorf("score = %v equals the single-decay value — 未复用在线的装配层换算", score)
	}
	if score == 90 {
		t.Errorf("score = %v: 因子惩罚没有生效", score)
	}
}

// TestLegacyAppliesMultiplierToAggregatedTotal 钉住 mandate 口径 4：legacy 的域分不被逐域
// 修正，乘子只作用于**聚合后的总分**；同一条记录上 vector 走的是"先逐域修正再聚合"的另一支，
// 两者必须给出不同的分数。
func TestLegacyAppliesMultiplierToAggregatedTotal(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{"attack_surface": 2, "operation_trust": 1}

	legacyScore, err := OfflineScoreWithWeights(legacyParams(), recs[0], weights)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	mult := assemblyDecay(0.82, 0.9)
	if want := (90*2 + 90*1) / 3.0 * mult; legacyScore != want {
		t.Errorf("legacy score = %v, want weighted aggregate × mult = %v", legacyScore, want)
	}

	vec := edgefactor.Params{Model: edgefactor.ModelVector, PFloor: 0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
	vecScore, err := OfflineScoreWithWeights(vec, recs[0], weights)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	p := 0.5 + 0.5*math.Exp(-1.0*((1-mult)*0.5)) // 域级系数 P_d（λ=1、v=0.5）
	if want := (90*p*2 + 90*p*1) / 3.0; math.Abs(vecScore-want) > 1e-9 {
		t.Errorf("vector score = %v, want per-domain adjustment then aggregate = %v", vecScore, want)
	}
	if vecScore == legacyScore {
		t.Errorf("legacy 与 vector 走了同一条聚合支路（%v）", vecScore)
	}
}

// TestVectorTrimsToLambdaDomainsAndPassesThroughOthers 钉住 mandate 口径 1：离线必须复用在线的
// 域裁剪口径「DefaultDomains ∩ λ」——未配 λ 的域**不做**域级修正，但它在聚合里仍应使用**观测值**
// （在线 DomainAdjust 对不在计划内的域原样放行），不能被当成 0。
func TestVectorTrimsToLambdaDomainsAndPassesThroughOthers(t *testing.T) {
	const rec = `{"scenario_id":"S2-partial","factors":["EF-SELINUX"],"observed":{"domain_scores":{"attack_surface":90,"operation_trust":60,"resilience":30},"threshold":60,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true}}`
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
	eff := assemblyDecay(0.82, 0.9)
	pd := 0.5 + 0.5*math.Exp(-1.0*((1-eff)*0.5))
	want := (90*pd + 60*pd + 30*1) / 3.0
	if math.Abs(score-want) > 1e-9 {
		t.Errorf("score = %v, want %v (未配 λ 的域必须原样参与聚合)", score, want)
	}
	if math.Abs(score-(90*pd+60*pd+0)/3.0) < 1e-9 {
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
	return fmt.Sprintf(`{"scenario_id":"S5-cascade","factors":["EF-SELINUX","EF-APPARMOR"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90},"final_score":80,"acceptable":true,"threshold":60,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:00Z"},{"factor":"EF-APPARMOR","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":%q}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3},"meta":{"env":"wsl-clab-14","run":1}}`, secondTS)
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

	// c_trigger=1 ⇒ 两次衰减恒等，有效值 = 0.8；a_i = (1−0.8)·0.5 = 0.1。
	gotWithin, err := OfflineScoreWithWeights(chainParams(), within[0], weights)
	if err != nil {
		t.Fatalf("chain(within): %v", err)
	}
	lWithin := 0.1 + 0.1 + 0.35*0.1*0.1 // 级联项 c·a_i·a_j
	if want := 90 * (0.5 + 0.5*math.Exp(-1.0*lWithin)); math.Abs(gotWithin-want) > 1e-12 {
		t.Errorf("chain(within) = %v, want %v (窗口内级联应生效)", gotWithin, want)
	}

	gotOutside, err := OfflineScoreWithWeights(chainParams(), outside[0], weights)
	if err != nil {
		t.Fatalf("chain(outside): %v", err)
	}
	if want := 90 * (0.5 + 0.5*math.Exp(-1.0*0.2)); math.Abs(gotOutside-want) > 1e-12 {
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
	const rec = `{"scenario_id":"S1-lowercase","observed":{"domain_scores":{"attack_surface":90},"edge_factor_chain":[{"factor":"  ef-selinux  ","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82,"ts":"2026-09-08T10:00:03Z"}]}}`
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
// 决策层：分数 = 聚合分 × 0.838（legacy），阈值 50。
//
//	R1 90 → 75.42 ≥50 接受 / 客观被攻陷 ⇒ 漏判（FN）
//	R2 10 →  8.38 <50 拒绝 / 客观被攻陷 ⇒ 正确
//	R3 90 → 75.42 ≥50 接受 / 客观未被攻陷 ⇒ 正确
//	R4 10 →  8.38 <50 拒绝 / 客观未被攻陷 ⇒ 误阻断（FP）
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
		return fmt.Sprintf(`{"scenario_id":%q,"factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":%v},"final_score":0,"acceptable":true,"threshold":50,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":%t,"time_to_compromise_s":%v,"ttps_achieved":%d,"nodes_affected":%d,"block_effective":false},"meta":{"env":"test","run":1}}`, id, as, compromised, ttc, ttps, nodes)
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
	const content = `{"scenario_id":"A","observed":{"domain_scores":{"attack_surface":90},"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8}]}}
{"scenario_id":"B","observed":{"domain_scores":{"attack_surface":90},"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8},{"factor":"EF-3FA","c_trigger":1.0,"effective_factor":0.5}]}}
{"scenario_id":"C","observed":{"domain_scores":{"attack_surface":90},"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":1.0,"effective_factor":0.8},{"factor":"EF-SYNCOOKIE","c_trigger":1.0,"effective_factor":0.5}]}}
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
	// c_trigger=1 ⇒ 两次衰减恒等 ⇒ 乘子 = 0.8（与在线单次衰减逐位相同）。
	if scoreA != 90*0.8 {
		t.Fatalf("A = %v, want %v", scoreA, 90*0.8)
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
	if scoreC != 90*0.8*0.5 {
		t.Errorf("C = %v, want %v（在途因子必须计入）", scoreC, 90*0.8*0.5)
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
// 缺失，会以 0 计入并仍占一份权重（brief 给定的 weightedSum 语义）。真实记录含全部 5 个域
// （spec §5.1），故该情形只出现在合成/最小夹具里。
func TestOfflineScoreEqualWeights(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	score, err := OfflineScore(legacyParams(), recs[0])
	if err != nil {
		t.Fatalf("OfflineScore: %v", err)
	}
	if want := (90.0 + 90.0) / 5.0 * assemblyDecay(0.82, 0.9); score != want {
		t.Errorf("score = %v, want %v", score, want)
	}
}
