//go:build edgeexp

package main

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// Task 9 夹具（前缀 t9 以区别于 Task 8 的 sample/legacyParams/chainParams 等）
// ============================================================================
//
// 主控裁定 1：brief 的 `Best == "vector"` 断言与它给的夹具在推算下不成立，必须重新设计
// 夹具与断言。本夹具的设计目标有三条，缺一不可：
//
//	(1) 至少两个候选在**决策层**给出不同判定（不是分数差一点、而是 acceptable 翻转）；
//	(2) 差异**只**出现在决策层 —— 这样 Best 只可能由主判据（漏判率）决定，
//	    选优判据的每一层分界才各自可测、可归因；
//	(3) 每条记录的分数化简成 `base × k_候选`（k 与记录无关），使推算可以逐条手算复核。
//
// 为此夹具取**单域 + 单因子**（attack_surface + EF-SELINUX）：
//
//	域分只有 attack_surface（权重 1）⇒ 聚合分 = base，不受加权平均干扰；
//	因子只有一个 ⇒ 无耦合项、无级联，V/G/C 在本夹具下退化（耦合语义另由 Task 8 的
//	TestEvaluateIsBitwiseDeterministicForVGC 与 internal/edgefactor 的性质测试钉住）；
//	c_trigger = 1.0 ⇒ EffectiveFactor(f,1) = f，两条候选的有效因子值都等于 0.8，
//	推算里没有「可信度被衰减两次」这层（Task 8 的 TestOfflineScoreUsesAssemblyConfidenceDecay
//	已在 c = 0.9 上钉住该口径）。
//
// 两条候选（k 的推导见 t9LegacyMultiplier / t9VectorPenalty）：
//
//	legacy  k = ∏ f_i = 0.8                              ⇒ 接受 iff base·0.8 ≥ 50 ⇔ base ≥ 62.5
//	vector  k = P_floor + (1−P_floor)·exp(−λ·L)
//	          = 0.2 + 0.8·exp(−5·(1−0.8)·0.5) = 0.6852245277701068
//	                                                      ⇒ 接受 iff base ≥ 72.9688…
//
// 四条记录（base / 客观结果 / 两条候选的模型判定）：
//
//	记录  base  客观       legacy(0.8)        vector(0.6852)
//	R1     65   被攻陷     52 ≥ 50 接受 ⇒ **漏判(FN)**   44.54 < 50 拒绝 ⇒ 正确
//	R2     40   被攻陷     32 < 50 拒绝 ⇒ 正确           27.41 < 50 拒绝 ⇒ 正确
//	R3     85   未攻陷     68 ≥ 50 接受 ⇒ 正确           58.24 ≥ 50 接受 ⇒ 正确
//	R4     70   未攻陷     56 ≥ 50 接受 ⇒ 正确           47.97 < 50 拒绝 ⇒ **误阻断(FP)**
//
// 由此（N = 4，两个率都是「占样本比」）：
//
//	                 一致率   漏判率   误阻断率   Spearman  Kendall  AUC
//	legacy  (R2,R3,R4 对)  0.75    0.25     0.00     −0.7379   −0.6     1.0
//	vector  (R1,R2,R3 对)  0.75    0.00     0.25     −0.7379   −0.6     1.0
//
// **一致率相同、排序层相同、数值层相同，只有决策层的两个率互补地互换** ⇒ Best 由
// 主判据（漏判率 0 < 0.25）判定为 vector，且这正是设计目标：如果实现把 FP 当主判据、
// 或把 AUC/Spearman 掺进选优，断言就会红。
//
// 排序层/数值层为何两条候选逐位相同：两条候选的分数互为**常数倍**
// （vector/legacy = 0.6852245277701068/0.8 = 0.8565306597126335），秩完全一致；
// 而 AUC 只看危险度（100−score）的组间序，也同样一致。
//
// 记录里的 `final_score` / `acceptable` 是在线 legacy 的观测值（离线 legacy 在 c = 1 时
// 与在线逐位一致，见 TestT9FixtureMatchesOnlineObservations）。

const t9FixtureJSONL = `{"scenario_id":"T9-R1","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":65},"final_score":52,"acceptable":true,"threshold":50,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:00Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","run":1}}
{"scenario_id":"T9-R2","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":40},"final_score":32,"acceptable":false,"threshold":50,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:01Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":600,"ttps_achieved":2,"nodes_affected":1,"block_effective":false},"meta":{"env":"wsl-clab-14","run":1}}
{"scenario_id":"T9-R3","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":85},"final_score":68,"acceptable":true,"threshold":50,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:02Z"}]},"ground_truth":{"compromised":false,"time_to_compromise_s":0,"ttps_achieved":0,"nodes_affected":0,"block_effective":true},"meta":{"env":"wsl-clab-14","run":1}}
{"scenario_id":"T9-R4","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":70},"final_score":56,"acceptable":true,"threshold":50,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8,"ts":"2026-09-08T10:00:03Z"}]},"ground_truth":{"compromised":false,"time_to_compromise_s":0,"ttps_achieved":0,"nodes_affected":0,"block_effective":true},"meta":{"env":"wsl-clab-14","run":1}}
`

// t9LegacyMultiplier = ∏ f_i = 0.8（legacy 的惩罚只在聚合后作用于总分）。
const t9LegacyMultiplier = 0.8

// t9VectorPenalty = P_floor + (1−P_floor)·exp(−λ·L)，其中 L = (1−0.8)·0.5 = 0.1、λ = 5、P_floor = 0.2。
// 写成分式而不是魔数：断言失败时能直接看出是哪一项算错了。
var t9VectorPenalty = 0.2 + 0.8*math.Exp(-5*((1-t9LegacyMultiplier)*0.5))

// t9Spearman = −7/(3√10) ≈ −0.7378647873726218。秩推导（分数秩 [2,1,4,3]、严重度秩 [4,3,1.5,1.5]）：
//
//	Σab = 21.5、Σa = Σb = 10、n = 4 ⇒ num = 4·21.5 − 100 = −14；
//	Σa² = 30、Σb² = 29.5 ⇒ den = √((120−100)(118−100)) = √360 ⇒ r = −14/√360 = −7/(3√10)。
var t9Spearman = -7 / (3 * math.Sqrt(10))

// t9Kendall = (conc − disc)/pairs = (1−4)/5 = −0.6。同序对：只有 (R1,R2) 同增；
// (R3,R4) 严重度并列 ⇒ 不计；其余四对反向。t9AUC = 1.0（两个被攻陷记录的分数都更低）。
const (
	t9Kendall = -0.6
	t9AUC     = 1.0
)

// t9Weights 是主夹具的权重表：只有 attack_surface 有权重，故 Evaluate 的域覆盖校验只要求该域。
func t9Weights() map[string]float64 { return map[string]float64{"attack_surface": 1} }

// t9LegacyCandidate 是现状候选（M0）：惩罚 = ∏ f_i 作用于聚合总分。
// p_floor 对 legacy 无语义，但 Validate 要求它在 (0,1) 内，故与 vector 取同一个值。
func t9LegacyCandidate() edgefactor.Params {
	return edgefactor.Params{
		Model:   edgefactor.ModelLegacy,
		PFloor:  0.2,
		Factors: map[string]float64{"EF-SELINUX": t9LegacyMultiplier},
	}
}

// t9VectorCandidate 是逐域向量候选（V）：λ = 5、v = 0.5、p_floor = 0.2 ⇒ 饱和惩罚更重，
// 于是它在 R1 上比 legacy 更早拒绝（少一次漏判），代价是在 R4 上误阻断。
func t9VectorCandidate() edgefactor.Params {
	return edgefactor.Params{
		Model:   edgefactor.ModelVector,
		PFloor:  0.2,
		Lambda:  map[string]float64{"attack_surface": 5.0},
		Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
		Factors: map[string]float64{"EF-SELINUX": t9LegacyMultiplier},
	}
}

// t9Records 读取主夹具（4 条记录）。
func t9Records(t *testing.T) []Record {
	t.Helper()
	recs, err := LoadRecords(writeJSONL(t, "t9-decision.jsonl", t9FixtureJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 4 {
		t.Fatalf("夹具应为 4 条记录，实际 %d 条", len(recs))
	}
	return recs
}

// assertMetrics 逐字段比对三层指标（浮点用 1e-12 容差 —— 这里要比的是公式，不是末位比特；
// 逐位可复现性另由 TestCompareIsDeterministic 钉住）。
func assertMetrics(t *testing.T, label string, got, want Metrics) {
	t.Helper()
	if got.N != want.N {
		t.Errorf("%s: N = %d, want %d", label, got.N, want.N)
	}
	for _, f := range []struct {
		name     string
		got, exp float64
	}{
		{"DecisionAgreement", got.DecisionAgreement, want.DecisionAgreement},
		{"FalseNegativeRate", got.FalseNegativeRate, want.FalseNegativeRate},
		{"FalsePositiveRate", got.FalsePositiveRate, want.FalsePositiveRate},
		{"Spearman", got.Spearman, want.Spearman},
		{"Kendall", got.Kendall, want.Kendall},
		{"AUC", got.AUC, want.AUC},
	} {
		if math.Abs(f.got-f.exp) > 1e-12 {
			t.Errorf("%s: %s = %v, want %v", label, f.name, f.got, f.exp)
		}
	}
}

// TestT9FixtureMatchesOnlineObservations 钉住夹具的自洽性：记录里的 `final_score` / `acceptable`
// 是在线 legacy 的观测值，而离线 legacy 在 c_trigger = 1 时与在线逐位一致（Task 7 口径），
// 故重算必须**复现**每一条的观测总分与观测判定。
//
// 这一条同时证明夹具不是凭空捏的数字：base 与 final_score 的关系（base × 0.8）正是
// 夹具注释里 k 的那张表的来源。
func TestT9FixtureMatchesOnlineObservations(t *testing.T) {
	for _, rec := range t9Records(t) {
		score, err := OfflineScoreWithWeights(t9LegacyCandidate(), rec, t9Weights())
		if err != nil {
			t.Fatalf("%s: %v", rec.ScenarioID, err)
		}
		if math.Abs(score-rec.Observed.FinalScore) > 1e-12 {
			t.Errorf("%s: 离线重算 = %v，在线观测 final_score = %v", rec.ScenarioID, score, rec.Observed.FinalScore)
		}
		if got, want := score >= rec.Observed.Threshold, rec.Observed.Acceptable; got != want {
			t.Errorf("%s: 离线判定 acceptable = %v，在线观测 = %v", rec.ScenarioID, got, want)
		}
	}
}

// TestComparePicksBestByDecisionLayer 是本任务的主测试：夹具在决策层真正区分两个候选，
// Best 由主判据（漏判率）判定。
//
// 断言分三层，缺一不可：
//  1. 每个候选的三层指标都等于手算值（夹具真的有区分力，而不是"两边都算错还相等"）；
//  2. 两个候选的**一致率相同**（0.75）⇒ Best 不是被一致率选出来的，只能由主判据选；
//  3. Best == "vector"：legacy 漏判 R1（把实际被攻陷的场景判成 acceptable），vector 没有。
func TestComparePicksBestByDecisionLayer(t *testing.T) {
	recs := t9Records(t)
	rep, err := Compare(recs, map[string]edgefactor.Params{
		"legacy": t9LegacyCandidate(),
		"vector": t9VectorCandidate(),
	}, t9Weights())
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if rep.Records != 4 || len(rep.Models) != 2 {
		t.Fatalf("报告形状不对：Records = %d, Models = %d", rep.Records, len(rep.Models))
	}
	if rep.GeneratedAt.IsZero() {
		t.Error("GeneratedAt 未填写")
	}
	assertMetrics(t, "legacy", rep.Models["legacy"], Metrics{
		DecisionAgreement: 0.75, FalseNegativeRate: 0.25, FalsePositiveRate: 0,
		Spearman: t9Spearman, Kendall: t9Kendall, AUC: t9AUC, N: 4,
	})
	assertMetrics(t, "vector", rep.Models["vector"], Metrics{
		DecisionAgreement: 0.75, FalseNegativeRate: 0, FalsePositiveRate: 0.25,
		Spearman: t9Spearman, Kendall: t9Kendall, AUC: t9AUC, N: 4,
	})
	if rep.Models["legacy"].DecisionAgreement != rep.Models["vector"].DecisionAgreement {
		t.Fatalf("夹具失效：两条候选的一致率不同（%v vs %v）—— Best 就可能不是由主判据决定的",
			rep.Models["legacy"].DecisionAgreement, rep.Models["vector"].DecisionAgreement)
	}
	if rep.Models["legacy"].FalseNegativeRate <= rep.Models["vector"].FalseNegativeRate {
		t.Fatalf("夹具失效：legacy 的漏判率（%v）必须**高于** vector（%v）",
			rep.Models["legacy"].FalseNegativeRate, rep.Models["vector"].FalseNegativeRate)
	}
	if rep.Best != "vector" {
		t.Errorf("Best = %q, want vector（legacy 漏判率 0.25 > vector 0；两者的误阻断率是反的，"+
			"但主判据先看漏判率）", rep.Best)
	}
	// 反例排除：如果实现把误阻断率或 AUC 掺进主判据、或按字典序兜底，Best 都会是 legacy。
	if rep.Best == "legacy" {
		t.Error("Best 落到了 legacy —— 主判据没有生效（字典序兜底或误阻断率被当成了主判据）")
	}
}

// TestCompareIsDeterministic 钉住「同输入同输出」：模型是 map，若实现按 map 迭代序评估/选优，
// 报告里的 Best 与错误归属都会随机漂移；报告要进论文与记录，不可复现等于没有结论。
func TestCompareIsDeterministic(t *testing.T) {
	recs := t9Records(t)
	candidates := map[string]edgefactor.Params{
		"legacy": t9LegacyCandidate(),
		"vector": t9VectorCandidate(),
	}
	first, err := Compare(recs, candidates, t9Weights())
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := Compare(recs, candidates, t9Weights())
		if err != nil {
			t.Fatalf("第 %d 次 Compare: %v", i+1, err)
		}
		if !reflect.DeepEqual(got.Models, first.Models) {
			t.Fatalf("第 %d 次三层指标与首次不同：%+v vs %+v", i+1, got.Models, first.Models)
		}
		if got.Best != first.Best || got.Records != first.Records {
			t.Fatalf("第 %d 次 Best/Records 与首次不同：%q/%d vs %q/%d",
				i+1, got.Best, got.Records, first.Best, first.Records)
		}
	}
	if first.Best != "vector" {
		t.Fatalf("Best = %q, want vector", first.Best)
	}
}

// TestCompareTieFallsBackToLexicographicOrder 端到端覆盖选优判据的**第四层（字典序兜底）**：
//
// 夹具里没有耦合边，于是 graph 与 chain 在数学上完全同构（单因子 ⇒ 耦合循环里没有任何
// 因子对），两者的三层指标逐位相同 —— 唯一能决定 Best 的就只剩模型名的字典序，
// 而 "chain" < "graph"，故 Best 必须是 chain。
//
// 这里刻意用两个**真实候选**（而不是两个手搓 Metrics）来走完整条 Compare 路径，
// 证明兜底不是只在 pickBest 的单测里成立。
func TestCompareTieFallsBackToLexicographicOrder(t *testing.T) {
	recs := t9Records(t)
	graph := t9VectorCandidate()
	graph.Model = edgefactor.ModelGraph
	chain := graph
	chain.Model = edgefactor.ModelChain
	chain.ChainWindowSeconds = 60

	rep, err := Compare(recs, map[string]edgefactor.Params{"graph": graph, "chain": chain}, t9Weights())
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !reflect.DeepEqual(rep.Models["graph"], rep.Models["chain"]) {
		t.Fatalf("夹具失效：graph 与 chain（无耦合边）的三层指标应逐位相同，实际 %+v vs %+v",
			rep.Models["graph"], rep.Models["chain"])
	}
	if rep.Best != "chain" {
		t.Errorf("Best = %q, want chain（三层全平 ⇒ 取名字字典序靠前者）", rep.Best)
	}
}

// TestCompareFailsFastOnMissingDomainCoverage 钉住主控裁定 2：Compare 必须走带域覆盖校验的
// `Evaluate`，不得直接调用低阶原语 `OfflineScore`/`OfflineScoreWithWeights`。
//
// 判别方式是让两条路径给出**不同结果**：记录只有 attack_surface / operation_trust，权重表却
// 额外要了 resilience。低阶入口会照算（缺失域以 0 计入却仍占一份权重 ⇒ 静默压低总分并翻转
// acceptable），只有 Evaluate（Task 8 评审 I2 的落点）会 fail-fast。因此本测试一红就说明
// Compare 绕开了校验层。
func TestCompareFailsFastOnMissingDomainCoverage(t *testing.T) {
	recs, err := LoadRecords(writeSample(t)) // 该记录只有 attack_surface / operation_trust
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1, "resilience": 1}

	// 前置：证据路径确实会拒绝（否则本测试抓不到"绕开校验"这件事）。
	if _, err := OfflineScoreWithWeights(t9LegacyCandidate(), recs[0], weights); err != nil {
		t.Fatalf("低阶入口不应报错（它是无校验原语）：%v", err)
	}
	if _, err := Evaluate(recs, t9LegacyCandidate(), weights); err == nil {
		t.Fatal("前置失效：Evaluate 必须拒绝缺域记录")
	}

	_, err = Compare(recs, map[string]edgefactor.Params{"legacy": t9LegacyCandidate()}, weights)
	if err == nil {
		t.Fatal("Compare 必须走 Evaluate：缺域记录应 fail-fast，而不是静默算出一份报告")
	}
	for _, want := range []string{"legacy", "resilience"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息必须点名候选与缺域 %q：%v", want, err)
		}
	}
	// 对照：覆盖完整的权重表照常出报告（证明拒绝是域覆盖引起的，不是"一有权重表就报错"）。
	if _, err := Compare(recs, map[string]edgefactor.Params{"legacy": t9LegacyCandidate()},
		map[string]float64{"attack_surface": 1, "operation_trust": 1}); err != nil {
		t.Errorf("覆盖完整的权重表不应报错：%v", err)
	}
}

// TestCompareRejectsEmptyCandidateSet：没有任何候选可比时，报告会是一张空表 + 一个不存在的
// 「选定模型」，属于"看起来比过了"的静默空操作 ⇒ 直接拒绝。
func TestCompareRejectsEmptyCandidateSet(t *testing.T) {
	recs := t9Records(t)
	rep, err := Compare(recs, nil, t9Weights())
	if err == nil {
		t.Fatal("空候选集必须报错")
	}
	if len(rep.Models) != 0 || rep.Best != "" {
		t.Errorf("出错时不得返回半成品报告：%+v", rep)
	}
}

// TestCompareRejectsEmptyRecords（Fix round 1 / Important-2 ①）：零记录必须 fail-fast。
//
// 零记录时每个候选的三层指标都是零值 ⇒ 三层全平 ⇒ `Best` 只是字典序兜底的产物；若 Compare
// 照常返回报告，`RenderMarkdown` 就会打印「场景数: 0」外加一个确定语气的「选定模型」——
// 筛选条件写错（路径写错、字段改名）时，操作者与下游产物文件看到的是一份**伪结论**。
// 这与"拒空候选集"是同一条纪律：比不了就别给结论。
func TestCompareRejectsEmptyRecords(t *testing.T) {
	candidates := map[string]edgefactor.Params{
		"legacy": t9LegacyCandidate(),
		"vector": t9VectorCandidate(),
	}
	for _, records := range [][]Record{nil, {}} {
		rep, err := Compare(records, candidates, t9Weights())
		if err == nil {
			t.Fatalf("零记录必须报错（records = %#v）", records)
		}
		if !strings.Contains(err.Error(), "记录") {
			t.Errorf("错误信息应说明「没有有效记录」：%v", err)
		}
		if len(rep.Models) != 0 || rep.Best != "" {
			t.Errorf("出错时不得返回半成品报告：%+v", rep)
		}
	}
}

// TestEmptyDatasetTieIsDecidedAtTheMetricLayer（原 TestCompareEmptyDatasetTiesAtZero 收窄而来）。
//
// 「零记录 ⇒ 三层全平 ⇒ 字典序兜底」这条**层次**上的事实仍然成立（`Evaluate` 对空输入返回零值
// Metrics，`pickBest` 在三层全平时取字典序靠前者），本用例继续钉住它；但端到端契约已按
// Fix round 1 / Important-2 收紧：`Compare` 对零记录 fail-fast、`RenderMarkdown` 对
// `Records == 0` 不打印选模结论 —— 故这里改在 Evaluate/pickBest 层面验证，而不再从 Compare 走
// （若继续从 Compare 断言，就等于要求端到端契约反过来变松）。
func TestEmptyDatasetTieIsDecidedAtTheMetricLayer(t *testing.T) {
	legacyM, err := Evaluate(nil, t9LegacyCandidate(), t9Weights())
	if err != nil {
		t.Fatalf("Evaluate(nil): %v", err)
	}
	vectorM, err := Evaluate(nil, t9VectorCandidate(), t9Weights())
	if err != nil {
		t.Fatalf("Evaluate(nil): %v", err)
	}
	if legacyM != (Metrics{}) || vectorM != (Metrics{}) {
		t.Fatalf("零记录应给出零值指标：legacy=%+v vector=%+v", legacyM, vectorM)
	}
	if got := pickBest(map[string]Metrics{"legacy": legacyM, "vector": vectorM}); got != "legacy" {
		t.Errorf("pickBest = %q, want legacy（三层全平 ⇒ 名字字典序靠前者）", got)
	}
}

// TestPickBestCriteriaOrder 逐层钉住选优判据的分界（主控裁定 4）：
//
//	① 漏判率低者 → ② 误阻断率低者 → ③ AUC 高者 → ④ 模型名字典序
//
// 前三层各自都构造了"下一层反向"的对照：若实现把层级顺序写反（例如先比 AUC），
// 或把某一层写成非严格比较（平局时误判为更优），对应子用例立刻红。
func TestPickBestCriteriaOrder(t *testing.T) {
	cases := []struct {
		name   string
		models map[string]Metrics
		want   string
	}{
		{
			name: "第一层：漏判率低者胜（即使误阻断率与 AUC 都更差）",
			models: map[string]Metrics{
				"alpha": {FalseNegativeRate: 0.00, FalsePositiveRate: 0.50, AUC: 0.10},
				"beta":  {FalseNegativeRate: 0.25, FalsePositiveRate: 0.00, AUC: 0.90},
			},
			want: "alpha",
		},
		{
			name: "第二层：漏判率相同时比误阻断率（即使 AUC 更差）",
			models: map[string]Metrics{
				"alpha": {FalseNegativeRate: 0.25, FalsePositiveRate: 0.00, AUC: 0.10},
				"beta":  {FalseNegativeRate: 0.25, FalsePositiveRate: 0.50, AUC: 0.90},
			},
			want: "alpha",
		},
		{
			name: "第三层：前两层相同时比 AUC 高者",
			models: map[string]Metrics{
				"alpha": {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.90},
				"beta":  {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.50},
			},
			want: "alpha",
		},
		{
			name: "第四层：三层全平 ⇒ 模型名字典序（chain < graph < legacy < vector）",
			models: map[string]Metrics{
				"vector": {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.50},
				"legacy": {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.50},
				"graph":  {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.50},
				"chain":  {FalseNegativeRate: 0.25, FalsePositiveRate: 0.25, AUC: 0.50},
			},
			want: "chain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// map 迭代序随机 ⇒ 重复 20 次，钉住兜底路径不依赖迭代序。
			for i := 0; i < 20; i++ {
				if got := pickBest(tc.models); got != tc.want {
					t.Fatalf("第 %d 次 pickBest = %q, want %q", i+1, got, tc.want)
				}
			}
		})
	}
}

// ============================================================================
// RenderMarkdown
// ============================================================================

// failingWriter 是永远失败的 io.Writer，用来钉住"写失败必须向上返回"这条错误路径
// （渲染函数返回 error 的全部意义就在于这条路径）。
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// t9Report 是把手算指标直接装成的报告（GeneratedAt 固定 ⇒ 输出可逐字比对）。
func t9Report() Report {
	return Report{
		GeneratedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		Records:     4,
		Best:        "vector",
		Models: map[string]Metrics{
			"legacy": {DecisionAgreement: 0.75, FalseNegativeRate: 0.25, FalsePositiveRate: 0,
				Spearman: t9Spearman, Kendall: t9Kendall, AUC: t9AUC, N: 4},
			"vector": {DecisionAgreement: 0.75, FalseNegativeRate: 0, FalsePositiveRate: 0.25,
				Spearman: t9Spearman, Kendall: t9Kendall, AUC: t9AUC, N: 4},
		},
	}
}

// TestRenderMarkdownFormat 钉住报告的表头、列序、精度与结论行。
// 列序（一致性/漏判率/误阻断率/Spearman/Kendall/AUC/N）与 spec §2.1 的三层指标顺序一致，
// 刻意不改：报告要按这个格式进论文附录，列序一变，旧记录就对不上了。
func TestRenderMarkdownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, t9Report()); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# 边缘因子模型对比报告",
		"生成时间: 2026-09-08T12:00:00Z｜场景数: 4",
		"| 模型 | 决策一致率 | 漏判率 | 误阻断率 | Spearman | Kendall | AUC | N |",
		"|---|---|---|---|---|---|---|---|",
		"| legacy | 0.750 | 0.250 | 0.000 | -0.738 | -0.600 | 1.000 | 4 |",
		"| vector | 0.750 | 0.000 | 0.250 | -0.738 | -0.600 | 1.000 | 4 |",
		"**选定模型**: `vector`",
		"判据：漏判率 ↓ → 误阻断率 ↓ → AUC ↑ → 模型名字典序",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("报告缺少 %q：\n%s", want, out)
		}
	}
	// 行序 = 模型名字典序（报告必须可复现，不能依赖 map 迭代序）。
	if strings.Index(out, "| legacy |") > strings.Index(out, "| vector |") {
		t.Errorf("模型行未按字典序输出：\n%s", out)
	}
}

// TestRenderMarkdownIsDeterministic：同一份 Report 重复渲染必须逐字节相同。
func TestRenderMarkdownIsDeterministic(t *testing.T) {
	rep := t9Report()
	var first bytes.Buffer
	if err := RenderMarkdown(&first, rep); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for i := 0; i < 50; i++ {
		var buf bytes.Buffer
		if err := RenderMarkdown(&buf, rep); err != nil {
			t.Fatalf("第 %d 次 RenderMarkdown: %v", i+1, err)
		}
		if buf.String() != first.String() {
			t.Fatalf("第 %d 次渲染与首次不同：\n%s\n---\n%s", i+1, buf.String(), first.String())
		}
	}
}

// TestRenderMarkdownEscapesPipeInModelName：模型名里的 `|` 会截断表格单元格（换行会截断整行），
// 让报告**静默**错位而不是报错 —— 渲染处必须转义。
func TestRenderMarkdownEscapesPipeInModelName(t *testing.T) {
	rep := Report{
		GeneratedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		Records:     1,
		Best:        "a|b",
		Models:      map[string]Metrics{"a|b": {N: 1}},
	}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `| a\|b |`) {
		t.Errorf("模型名里的竖线未转义：\n%s", out)
	}
	if strings.Contains(out, "`a|b`") {
		t.Errorf("结论行的模型名未转义：\n%s", out)
	}
}

// TestRenderMarkdownRejectsEmptyReport：没有任何候选的报告会被误读成"比过了、结论是空"，
// 直接拒绝渲染。
func TestRenderMarkdownRejectsEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, Report{GeneratedAt: time.Now(), Records: 0}); err == nil {
		t.Fatal("空报告必须报错")
	}
	if buf.Len() != 0 {
		t.Errorf("出错时不得写出半份报告：%q", buf.String())
	}
}

// TestRenderMarkdownZeroRecordsPrintsNoSelection（Fix round 1 / Important-2 ②）：
// 零记录的报告必须**显式**写明"无有效记录、未选模"，且**不得**打印任何选模结论。
//
// 这里与 TestCompareRejectsEmptyRecords 是两道独立的闸门：Compare 已经会拒零记录，但
// `RenderMarkdown` 是导出函数，可能被别的调用方（或未来的 CLI 分支）直接喂一份手搓 Report；
// 只要 `Records == 0`，它就不能输出「选定模型」——那正是本文件自述要消灭的"看起来有结论、
// 实际没有"的产物（Best 在零记录下只是字典序兜底的产物）。
func TestRenderMarkdownZeroRecordsPrintsNoSelection(t *testing.T) {
	rep := t9Report()
	rep.Records = 0
	rep.Best = "legacy" // 即便调用方硬塞了一个 Best，渲染也必须拒绝把它当成结论打印

	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "无有效记录") || !strings.Contains(out, "未选模") {
		t.Errorf("零记录报告必须写明「无有效记录、未选模」：\n%s", out)
	}
	// 结论行的标记必须缺席（用标记而不是"选定模型"这四个字：说明文字里出现这个词
	// 恰恰是正确的 —— 它正在解释"为什么没有选模"）。
	if strings.Contains(out, "**选定模型**:") {
		t.Errorf("零记录报告不得打印选模结论行：\n%s", out)
	}
	if strings.Contains(out, "`legacy`") {
		t.Errorf("零记录报告不得把传入的 Best 当成结论打印：\n%s", out)
	}
	if !strings.Contains(out, "场景数: 0") {
		t.Errorf("场景数应如实为 0：\n%s", out)
	}
}

// TestRenderersPropagateWriteError：渲染函数返回 error 的意义全在"写失败要能传出去"。
func TestRenderersPropagateWriteError(t *testing.T) {
	if err := RenderMarkdown(failingWriter{}, t9Report()); err == nil {
		t.Error("RenderMarkdown 必须向上返回写错误")
	}
	if err := RenderConfigSection(failingWriter{}, "vector", t9VectorCandidate()); err == nil {
		t.Error("RenderConfigSection 必须向上返回写错误")
	}
}

// ============================================================================
// RenderConfigSection
// ============================================================================

// parseRenderedSection 把渲染出的 `key = value` 行装成 `config.ParseEdgeFactorModel` 需要的
// sections 结构。用**真解析器**做往返，而不是在测试里自己写一套等价解析 —— 参数段的全部
// 价值就在于"粘回生产配置能被接受且语义不变"。
func parseRenderedSection(t *testing.T, out string) map[string]map[string]string {
	t.Helper()
	sections := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if sections[section] == nil {
				sections[section] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			t.Fatalf("渲染出的内容既不在段内、也不是 key = value：%q", line)
		}
		sections[section][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return sections
}

// t9RenderedParams 是被渲染的参数集：向量**只声明了配了 λ 的两个域**
// （离线重算的裁剪口径 DefaultDomains ∩ λ 正是这个形状），渲染必须补齐另外三个域。
func t9RenderedParams() edgefactor.Params {
	return edgefactor.Params{
		Model:  edgefactor.ModelGraph,
		PFloor: 0.4,
		Lambda: map[string]float64{"attack_surface": 1.5, "kernel_security": 0.25},
		Vectors: map[string]map[string]float64{
			"EF-SELINUX":  {"attack_surface": 0.5, "kernel_security": 0.25},
			"EF-APPARMOR": {"attack_surface": 0.25, "kernel_security": 0.25},
		},
		Coupling: map[string]map[string]float64{"EF-SELINUX": {"EF-APPARMOR": 0.35}},
	}
}

// TestRenderConfigSectionCoversAllFiveDomains 钉住主控裁定 3：`vector.<id>` 必须输出**全部 5 个域**
// 的逗号分隔值（按 DefaultDomains 顺序），不得只写配了 λ 的那几个。
//
// 两层理由，测试里各有一半：
//   - **正向**：这段会被人工粘回 `[edge_factors.model]`，而在线装配期用**完整**默认域列表跑
//     `Validate` —— 少任何一个域都会被拒（`vector %q does not cover domain %q`）。故渲染结果
//     必须能被真解析器读回、并让重建出的参数通过 Validate(DefaultDomains())。
//   - **负向（对照）**：未补齐的原始参数**必然**被同一个 Validate 拒绝，证明"补齐"不是装饰。
func TestRenderConfigSectionCoversAllFiveDomains(t *testing.T) {
	p := t9RenderedParams()

	// 负向对照：未补齐的向量（只声明 λ 覆盖到的域）过不了 Validate。
	if err := p.Validate(edgefactor.DefaultDomains()); err == nil {
		t.Fatal("负向对照失效：只声明部分域的向量本应被 Validate 拒绝")
	}

	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, "graph", p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"[edge_factors.model]",
		"model = graph",
		"p_floor = 0.4",
		// λ 按 DefaultDomains 顺序：attack_surface 在前、kernel_security 在后。
		"lambda.attack_surface = 1.5",
		"lambda.kernel_security = 0.25",
		// 5 个逗号分隔值，顺序 attack_surface,business_continuity,operation_trust,resilience,kernel_security；
		// 未声明的域补 0（该域若配了 λ 会被上面那条校验拦下，故补 0 不会改变任何在线/离线口径）。
		"vector.EF-APPARMOR = 0.25,0,0,0,0.25",
		"vector.EF-SELINUX = 0.5,0,0,0,0.25",
		"coupling.EF-SELINUX.EF-APPARMOR = 0.35",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("参数段缺少 %q：\n%s", want, out)
		}
	}
	if strings.Contains(out, "chain.window_seconds") {
		t.Errorf("非 chain 参数不该输出链条窗口：\n%s", out)
	}

	// 正向：真解析器读回 + 重建参数通过 Validate(DefaultDomains())。
	cfg, present, err := config.ParseEdgeFactorModel(parseRenderedSection(t, out))
	if err != nil {
		t.Fatalf("渲染出的段必须能被 config.ParseEdgeFactorModel 接受：%v\n%s", err, out)
	}
	if !present || cfg.Model != "graph" || cfg.PFloor != p.PFloor {
		t.Fatalf("解析结果不对：present=%v cfg=%+v", present, cfg)
	}
	if !reflect.DeepEqual(cfg.Lambda, p.Lambda) {
		t.Errorf("λ 未能逐值读回：%v vs %v", cfg.Lambda, p.Lambda)
	}
	for id, vec := range p.Vectors {
		rebuilt := cfg.Vectors[id]
		if len(rebuilt) != len(edgefactor.DefaultDomains()) {
			t.Fatalf("向量 %s 应为 5 个域，实际 %d 个：%v", id, len(rebuilt), rebuilt)
		}
		for _, d := range edgefactor.DefaultDomains() {
			if got, want := rebuilt[d], vec[d]; got != want {
				t.Errorf("向量 %s[%s] = %v, want %v（已声明的值必须原样保留，未声明的域补 0）", id, d, got, want)
			}
		}
	}
	rebuilt := edgefactor.Params{
		Model: edgefactor.ModelID(cfg.Model), PFloor: cfg.PFloor,
		Lambda: cfg.Lambda, Vectors: cfg.Vectors, Coupling: cfg.Coupling,
		ChainWindowSeconds: cfg.ChainWindowSeconds,
		Factors:            map[string]float64{"EF-SELINUX": 0.8, "EF-APPARMOR": 0.8},
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		t.Errorf("粘回去的参数必须通过 Validate(DefaultDomains())：%v", err)
	}
}

// TestRenderConfigSectionKeepsFullFloatPrecision：导出段存在的理由是"离线重算可复现"，
// 故数值必须**逐位可回读**。brief 原写法在向量分量上用 %.4g：1/3 会变成 0.3333、
// 0.1234567890123 会变成 0.1235 —— 粘回去的已不是同一份参数（Hash 变、分数变）。
func TestRenderConfigSectionKeepsFullFloatPrecision(t *testing.T) {
	p := edgefactor.Params{
		Model:  edgefactor.ModelVector,
		PFloor: 1.0 / 3.0,
		Lambda: map[string]float64{"attack_surface": 0.1234567890123},
		Vectors: map[string]map[string]float64{
			"EF-SELINUX": {"attack_surface": 2.0 / 7.0},
		},
		Factors: map[string]float64{"EF-SELINUX": 0.8},
	}
	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, "vector", p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	cfg, _, err := config.ParseEdgeFactorModel(parseRenderedSection(t, buf.String()))
	if err != nil {
		t.Fatalf("ParseEdgeFactorModel: %v\n%s", err, buf.String())
	}
	if cfg.PFloor != p.PFloor {
		t.Errorf("p_floor = %v, want 逐位等于 %v", cfg.PFloor, p.PFloor)
	}
	if got := cfg.Lambda["attack_surface"]; got != p.Lambda["attack_surface"] {
		t.Errorf("lambda.attack_surface = %v, want 逐位等于 %v", got, p.Lambda["attack_surface"])
	}
	if got := cfg.Vectors["EF-SELINUX"]["attack_surface"]; got != p.Vectors["EF-SELINUX"]["attack_surface"] {
		t.Errorf("vector.EF-SELINUX[attack_surface] = %v, want 逐位等于 %v",
			got, p.Vectors["EF-SELINUX"]["attack_surface"])
	}
}

// TestRenderConfigSectionIsDeterministic：λ / 向量 / 边都来自 map，输出必须与迭代序无关
// （参数段会被 diff、被写进记录，抖动即不可归因）。
func TestRenderConfigSectionIsDeterministic(t *testing.T) {
	p := t9RenderedParams()
	p.ChainWindowSeconds = 60
	p.Model = edgefactor.ModelChain
	var first bytes.Buffer
	if err := RenderConfigSection(&first, "chain", p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	for i := 0; i < 50; i++ {
		var buf bytes.Buffer
		if err := RenderConfigSection(&buf, "chain", p); err != nil {
			t.Fatalf("第 %d 次 RenderConfigSection: %v", i+1, err)
		}
		if buf.String() != first.String() {
			t.Fatalf("第 %d 次渲染与首次不同：\n%s\n---\n%s", i+1, buf.String(), first.String())
		}
	}
	if !strings.Contains(first.String(), "chain.window_seconds = 60") {
		t.Errorf("chain 参数必须输出窗口：\n%s", first.String())
	}
}

// TestRenderConfigSectionChainNeedsWindow（Fix round 1 / Important-1）：
//
// `chain.window_seconds` 只在 `ChainWindowSeconds > 0` 时输出，而解析层对"缺窗口的 chain"
// 是硬拒绝（`model=chain requires chain.window_seconds`）、`edgefactor.Validate` 同样要求
// `chain_window_seconds > 0`。于是"chain + 窗口 ≤ 0"会渲染出一份**必被解析器拒绝**的配置 ——
// 而函数契约正是"可直接粘贴"。故这里要求渲染前就 fail-fast，且不写出任何内容。
func TestRenderConfigSectionChainNeedsWindow(t *testing.T) {
	for _, window := range []int{0, -1} {
		p := t9RenderedParams()
		p.Model = edgefactor.ModelChain
		p.ChainWindowSeconds = window

		// 前置：这套参数确实过不了 Validate（渲染出它没有意义）。
		if err := p.Validate(edgefactor.DefaultDomains()); err == nil {
			t.Fatalf("前置失效：chain 窗口 = %d 本应被 Validate 拒绝", window)
		}
		// 层次断言：拦下它的必须是**渲染前的显式校验**（validateRenderable），
		// 而不是靠末尾的统一断言兜底。两者的行为在"报错"上重叠（见下），但契约不同：
		// 显式校验是给操作员的精确诊断（点名窗口与原因），统一断言是防漏网之鱼。
		// 少了这条断言，"删掉显式校验"的变异会存活 —— 统一断言会替它报错，行为看起来一模一样。
		if err := validateRenderable("chain", p); err == nil {
			t.Errorf("validateRenderable 必须直接拒绝 chain 窗口 = %d 的参数集", window)
		}
		var buf bytes.Buffer
		err := RenderConfigSection(&buf, "chain", p)
		if err == nil {
			t.Fatalf("chain 窗口 = %d 必须报错（渲染出的段粘不回去）", window)
		}
		for _, want := range []string{"chain", "window"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("错误信息应点名 %q：%v", want, err)
			}
		}
		if buf.Len() != 0 {
			t.Errorf("出错时不得写出半段配置：%q", buf.String())
		}
	}
}

// TestRenderConfigSectionChainRoundTrips：合法 chain（带窗口）的正向对照 ——
// 渲染 → 真解析器读回 → 重建参数 → `Validate(DefaultDomains())` 全通过，且窗口确实出现在段里。
func TestRenderConfigSectionChainRoundTrips(t *testing.T) {
	p := t9RenderedParams()
	p.Model = edgefactor.ModelChain
	p.ChainWindowSeconds = 60

	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, "chain", p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "chain.window_seconds = 60") {
		t.Errorf("chain 段必须带窗口：\n%s", out)
	}
	cfg, present, err := config.ParseEdgeFactorModel(parseRenderedSection(t, out))
	if err != nil {
		t.Fatalf("chain 段必须能被真解析器接受：%v\n%s", err, out)
	}
	if !present || cfg.Model != "chain" || cfg.ChainWindowSeconds != 60 {
		t.Fatalf("解析结果不对：present=%v cfg=%+v", present, cfg)
	}
	rebuilt := edgefactor.Params{
		Model: edgefactor.ModelID(cfg.Model), PFloor: cfg.PFloor,
		Lambda: cfg.Lambda, Vectors: cfg.Vectors, Coupling: cfg.Coupling,
		ChainWindowSeconds: cfg.ChainWindowSeconds,
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		t.Errorf("粘回去的 chain 参数必须通过 Validate(DefaultDomains())：%v", err)
	}
}

// TestRenderConfigSectionRejectsUnloadableParams 钉住 Fix round 1 / Important-1 的统一断言：
// 渲染结果必须**自我验证** —— 把最终要写出去的字符串重新解析成配置、重建参数并跑
// `Validate(DefaultDomains())`，任一环节失败都不得写出任何内容。
//
// 三个子用例都是"渲染前的显式校验看不见、但配置层或 Validate 会拒"的输入：
//
//	非有限 p_floor   —— 解析层 `must be a finite number`；
//	未知 λ 域        —— `Validate` 的 `lambda for unknown domain`（离线重算会静默丢掉非默认域的
//	                    λ 键，但粘回去的配置会被在线装配拒 ⇒ 导出段必须在这里拦下）；
//	Σ_d v > 1        —— `Validate` 的向量和上限。
//
// 统一断言的价值正在于此：不必为每个数值型字段各写一条规则，也不会漏掉下一个。
func TestRenderConfigSectionRejectsUnloadableParams(t *testing.T) {
	cases := []struct {
		name string
		p    edgefactor.Params
	}{
		{
			name: "非有限 p_floor",
			p: edgefactor.Params{
				Model: edgefactor.ModelVector, PFloor: math.NaN(),
				Lambda:  map[string]float64{"attack_surface": 1.0},
				Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5}},
			},
		},
		{
			name: "向量和超过 1",
			p: edgefactor.Params{
				Model: edgefactor.ModelVector, PFloor: 0.5,
				Lambda: map[string]float64{"attack_surface": 1.0, "kernel_security": 1.0},
				Vectors: map[string]map[string]float64{
					"EF-SELINUX": {"attack_surface": 0.8, "kernel_security": 0.8},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 前置：这条输入能穿过渲染前的显式校验（即"看起来能贴"），只可能被统一断言拦下。
			if err := validateRenderable("vector", tc.p); err != nil {
				t.Fatalf("前置失效：本应穿过显式校验、由统一断言兜住：%v", err)
			}
			var buf bytes.Buffer
			if err := RenderConfigSection(&buf, "vector", tc.p); err == nil {
				t.Fatalf("这段渲染结果会被解析层/Validate 拒绝，必须报错：\n%s", buf.String())
			}
			if buf.Len() != 0 {
				t.Errorf("出错时不得写出半段配置：%q", buf.String())
			}
		})
	}
}

// TestRenderConfigSectionRejectsNonDefaultDomainKeys 钉住"忠实可导出"这一条（Fix round 1
// 期间由统一断言的反例推出来的，与 Important-1 同类，见报告 §Fix round 1 自决 2）：
//
// λ 的域与向量的域都必须是**默认域**。非默认域的键在任何路径上都不会生效，但两条路径的表现
// 不同：离线重算的裁剪口径是 `DefaultDomains ∩ λ`，会**静默丢掉**它们；在线装配期则直接拒绝
// （`lambda for unknown domain`）。渲染时若把它们悄悄丢掉，产出的段就是"能贴、但与参数集不是
// 同一套"的配置 —— 而这段配置的全部意义就是"贴回去等于刚才算的那套参数"。
func TestRenderConfigSectionRejectsNonDefaultDomainKeys(t *testing.T) {
	cases := []struct {
		name string
		p    edgefactor.Params
	}{
		{"非默认域的 λ 键", edgefactor.Params{
			Model: edgefactor.ModelVector, PFloor: 0.5,
			Lambda:  map[string]float64{"zzz_custom": 1.0},
			Vectors: map[string]map[string]float64{"EF-SELINUX": {"zzz_custom": 0.5}},
		}},
		{"非默认域的向量分量", edgefactor.Params{
			Model: edgefactor.ModelVector, PFloor: 0.5,
			Lambda:  map[string]float64{"attack_surface": 1.0},
			Vectors: map[string]map[string]float64{"EF-SELINUX": {"attack_surface": 0.5, "zzz_custom": 0.5}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRenderable("vector", tc.p); err == nil {
				t.Error("validateRenderable 必须拒绝非默认域的键")
			}
			var buf bytes.Buffer
			err := RenderConfigSection(&buf, "vector", tc.p)
			if err == nil {
				t.Fatalf("非默认域的键必须报错（否则渲染出的段与参数集不是同一套）：\n%s", buf.String())
			}
			if !strings.Contains(err.Error(), "zzz_custom") {
				t.Errorf("错误信息应点名出问题的键：%v", err)
			}
			if buf.Len() != 0 {
				t.Errorf("出错时不得写出半段配置：%q", buf.String())
			}
		})
	}
}

// TestRenderConfigSectionRejectsModelNameMismatch 钉住两条渲染前的 fail-fast：
//   - 模型名与参数集的 Model 不一致 ⇒ 粘回去的配置会"用一个模型的名字描述另一套参数"（静默错配）；
//   - 未知模型名 ⇒ 配置解析层只接受 legacy|vector|graph|chain，写出来也是废段。
//
// 两种情况都必须**不写出任何内容**：半段配置是最容易被误粘的形态。
func TestRenderConfigSectionRejectsModelNameMismatch(t *testing.T) {
	cases := []struct {
		name  string
		model string
		p     edgefactor.Params
		want  []string
	}{
		{"名字与参数集不一致", "vector", t9LegacyCandidate(), []string{"vector", "legacy"}},
		{"未知模型名", "oracle", t9VectorCandidate(), []string{"oracle"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := RenderConfigSection(&buf, tc.model, tc.p)
			if err == nil {
				t.Fatalf("必须报错（model = %q, p.Model = %q）", tc.model, tc.p.Model)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("错误信息应点名 %q：%v", want, err)
				}
			}
			if buf.Len() != 0 {
				t.Errorf("出错时不得写出半段配置：%q", buf.String())
			}
		})
	}
}

// TestRenderConfigSectionRejectsVectorMissingLambdaDomain：向量漏掉一个**配了 λ 的域**时，
// 离线重算本身就会被 Synthesize 拒绝（"vector does not cover domain"）；渲染若在这一步补 0，
// 就会产出一份"看起来能算、算出来不一样"的配置 —— 正是导出段最不能犯的错。
func TestRenderConfigSectionRejectsVectorMissingLambdaDomain(t *testing.T) {
	p := edgefactor.Params{
		Model:  edgefactor.ModelVector,
		PFloor: 0.5,
		Lambda: map[string]float64{"attack_surface": 1.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{
			"EF-SELINUX": {"attack_surface": 0.5},
		},
		Factors: map[string]float64{"EF-SELINUX": 0.8},
	}
	// 前置：这套参数在离线重算路径上确实不可用（Synthesize 的域覆盖校验）。
	if _, err := OfflineScoreWithWeights(p, t9Records(t)[0], t9Weights()); err == nil {
		t.Fatal("前置失效：漏域的向量本应在离线重算时被拒绝")
	}
	var buf bytes.Buffer
	err := RenderConfigSection(&buf, "vector", p)
	if err == nil {
		t.Fatal("向量漏掉配了 λ 的域必须报错，不得补 0 蒙混")
	}
	for _, want := range []string{"EF-SELINUX", "operation_trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应点名 %q：%v", want, err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("出错时不得写出半段配置：%q", buf.String())
	}
}

// TestRenderConfigSectionLegacyIsMinimal：legacy 不读 λ / 向量，只输出模型与下限；
// 且这份最小段同样必须能被真解析器接受（它是"未启用 ⇒ 显式 legacy"的粘贴形态）。
func TestRenderConfigSectionLegacyIsMinimal(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, "legacy", t9LegacyCandidate()); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	want := "[edge_factors.model]\nmodel = legacy\np_floor = 0.2\n"
	if buf.String() != want {
		t.Errorf("legacy 参数段 = %q, want %q", buf.String(), want)
	}
	cfg, present, err := config.ParseEdgeFactorModel(parseRenderedSection(t, buf.String()))
	if err != nil || !present || cfg.Model != "legacy" {
		t.Fatalf("最小的 legacy 段也必须能被解析：present=%v err=%v cfg=%+v", present, err, cfg)
	}
}
