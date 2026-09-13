//go:build edgeexp

// 本文件是 Task 4D Step 4 的用例：**决策层指标的标签依据守卫**（用户裁定的 L2）。
//
// 为什么必须有它：`compromised` 现在有两种口径 —— `targeted_ttp`（该场景的目标 TTP 是否成功）
// 与 `recon_playbook`（固定侦察剧本的结果，**任何姿态下都成功**，只作背景测量）。两者在数据上
// 完全同形（都是一个 bool），把它们混进同一个漏判率里，指标就没有定义；而"旧数据集没有 basis"
// 这件事会让默认路径静默地把历史数据也算进来。
//
// 三条判据：
//  1. 缺 `basis` ⇒ **报错**（不静默算，也不静默丢）；
//  2. 两类混在一起 ⇒ **报错**（缺省），`AllowMixedBasis` 才放开；
//  3. 侦察口径的记录**始终**被丢出决策层指标，且被丢的条数**写进指标本体与报告头**（分母 N 变了，
//     不写清就没法比）。
package main

import (
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// basisRecords 读主夹具（4 条）并把依据设成调用方给的序列。
//
// 用**真夹具**而不是手搓记录：手搓的记录容易漏掉域覆盖/权重等前置条件，于是用例会先被那些
// 守卫拦下，测不到 basis 这条判据（"用错误的原因变红"是最难发现的一类假证据）。
func basisRecords(t *testing.T, bases ...string) []Record {
	t.Helper()
	recs := t9Records(t)
	if len(bases) != len(recs) {
		t.Fatalf("夹具 %d 条记录，给定了 %d 个 basis", len(recs), len(bases))
	}
	for i := range recs {
		recs[i].GroundTruth.Basis = bases[i]
	}
	return recs
}

// TestBasisGuardRejectsMissingBasis：**缺依据 ⇒ 报错**（默认口径）。
//
// 这条堵的是"旧数据集静默进决策层指标"：里程碑 B 之前的记录都没有 `basis`，而它们的
// `compromised` 是**旧口径**（任意 link 成功）算出来的 —— 静默算进新报告的漏判率，
// 等于把两种量混在一起且不留痕。
func TestBasisGuardRejectsMissingBasis(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, edgeexp.BasisTargetedTTP, edgeexp.BasisTargetedTTP, ""}
	recs := basisRecords(t, bases...)
	_, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{})
	if err == nil {
		t.Fatal("缺 basis 必须报错（缺省口径）")
	}
	if !strings.Contains(err.Error(), "basis") || !strings.Contains(err.Error(), "1/4") {
		t.Errorf("拒绝理由必须点名 basis 与计数（1/4 条），实际: %v", err)
	}
	// **两条出路的对照**：显式假设 ⇒ 放行（并记下"假设了几条"）；逃生开关 ⇒ 放行但把缺依据的
	// 记录当作侦察口径丢出决策层指标（条数如实记进 BasisSkipped）。
	m, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(),
		EvaluateOptions{AssumeBasis: edgeexp.BasisTargetedTTP})
	if err != nil {
		t.Fatalf("--assume-basis 应放行：%v", err)
	}
	if m.N != 4 || m.BasisAssumed != 1 {
		t.Errorf("假设应让 4 条都参与、并记下 assumed=1，实际 N=%d assumed=%d", m.N, m.BasisAssumed)
	}
	m2, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{AllowMixedBasis: true})
	if err != nil {
		t.Fatalf("--allow-mixed-basis 应放行：%v", err)
	}
	if m2.N != 3 {
		t.Errorf("逃生开关下缺依据的记录按侦察口径丢出指标 ⇒ N=3，实际 N=%d", m2.N)
	}
	if m2.BasisSkipped["(未声明)"] != 1 {
		t.Errorf("'缺依据'的条数必须如实记进 BasisSkipped，实际 %+v", m2.BasisSkipped)
	}
}

// TestBasisGuardRejectsMixedBasisWhenForced：**两类都进指标**（= 逃生开关打开）时才是真矛盾 ⇒ 报错。
func TestBasisGuardRejectsMixedBasisWhenForced(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook,
		edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook}
	recs := basisRecords(t, bases...)

	// 缺省口径：**不是**错误 —— 侦察口径的记录被自动丢出决策层指标（2 条目标参与）。
	m, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{})
	if err != nil {
		t.Fatalf("缺省口径下侦察口径的记录应被自动丢出，而不是报错：%v", err)
	}
	if m.N != 2 || m.BasisSkipped[edgeexp.BasisReconPlaybook] != 2 || m.RecordsTotal != 4 {
		t.Errorf("过滤后的指标不对：N=%d skipped=%+v total=%d", m.N, m.BasisSkipped, m.RecordsTotal)
	}
	if m.Basis[edgeexp.BasisTargetedTTP] != 2 || len(m.Basis) != 1 {
		t.Errorf("参与计数必须只有 targeted_ttp=2，实际 %+v", m.Basis)
	}

	// 逃生开关：两类都要进指标 ⇒ 那才是"混算" ⇒ 报错。
	if _, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(),
		EvaluateOptions{AllowMixedBasis: true}); err == nil {
		t.Fatal("两类都进决策层指标（逃生开关打开）时必须报错")
	} else if !strings.Contains(err.Error(), edgeexp.BasisTargetedTTP) ||
		!strings.Contains(err.Error(), edgeexp.BasisReconPlaybook) {
		t.Errorf("拒绝理由必须点名两类：%v", err)
	}
}

// TestBasisGuardSkipsReconPlaybookAndReportsIt：侦察口径的记录**始终**不进决策层指标，
// 而"跳过了多少条"必须能从指标本体与报告头读出来（分母 N 变了，不写清就没法比）。
func TestBasisGuardSkipsReconPlaybookAndReportsIt(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, edgeexp.BasisTargetedTTP,
		edgeexp.BasisReconPlaybook, edgeexp.BasisReconPlaybook}
	recs := basisRecords(t, bases...)
	m, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{})
	if err != nil {
		t.Fatalf("EvaluateWith: %v", err)
	}
	if m.N != 2 {
		t.Errorf("侦察口径的记录必须被丢出决策层指标（N=2），实际 N=%d", m.N)
	}
	if m.RecordsTotal != 4 {
		t.Errorf("RecordsTotal = 过滤前总条数（4），实际 %d", m.RecordsTotal)
	}
	if m.BasisSkipped[edgeexp.BasisReconPlaybook] != 2 {
		t.Errorf("BasisSkipped 必须记下被丢的条数（2），实际 %+v", m.BasisSkipped)
	}
	if m.Basis[edgeexp.BasisTargetedTTP] != 2 || len(m.Basis) != 1 {
		t.Errorf("参与计数必须只有 targeted_ttp=2，实际 %+v", m.Basis)
	}
	// 报告头必须把它写出来（否则两份报告字面一样、分母却不同）。
	rep := Report{Records: 4, Models: map[string]Metrics{"legacy": m}, Best: "legacy"}
	var b strings.Builder
	if err := RenderMarkdown(&b, rep); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	out := b.String()
	for _, want := range []string{"标签依据口径", "参与决策层 2 条", "跳过 2 条", "过滤前共 4 条"} {
		if !strings.Contains(out, want) {
			t.Errorf("报告头必须含 %q：\n%s", want, truncForTest(out, 1200))
		}
	}
}

// TestBasisGuardRejectsUnknownBasis：未知依据值 ⇒ 报错（不得被当成某一类静默算进去）。
func TestBasisGuardRejectsUnknownBasis(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, "targeted-ttp",
		edgeexp.BasisTargetedTTP, edgeexp.BasisTargetedTTP}
	recs := basisRecords(t, bases...)
	_, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{AllowMixedBasis: true})
	if err == nil {
		t.Fatal("未知 basis 必须报错")
	}
	if !strings.Contains(err.Error(), "targeted-ttp") {
		t.Errorf("拒绝理由必须点名那个未知值：%v", err)
	}
}

// TestBasisFilterKeepsDecisionMetricsWellDefined：过滤之后指标必须**与"只喂那一类"逐位相同**。
//
// 为什么单列（这是本改动最该避免的形态）：过滤会把 N 变小。若实现里把"过滤前"与"过滤后"的 N
// 混起来（例如在过滤前记 N），指标会出现"N=2 而分母按 4 算"这类不自洽 —— 而报告照常打印。
// 判据取**逐位比对**（同一份参数、同一份权重）：过滤后的结果 == 只喂 targeted_ttp 那两条的结果。
func TestBasisFilterKeepsDecisionMetricsWellDefined(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, edgeexp.BasisTargetedTTP,
		edgeexp.BasisReconPlaybook, edgeexp.BasisReconPlaybook}
	recs := basisRecords(t, bases...)
	m, err := EvaluateWith(recs, t9LegacyCandidate(), t9Weights(), EvaluateOptions{})
	if err != nil {
		t.Fatalf("EvaluateWith: %v", err)
	}
	only := recs[:2]
	m2, err := EvaluateWith(only, t9LegacyCandidate(), t9Weights(), EvaluateOptions{})
	if err != nil {
		t.Fatalf("EvaluateWith(only): %v", err)
	}
	if m.N != m2.N {
		t.Errorf("N: 过滤后 %d vs 只喂 %d", m.N, m2.N)
	}
	for _, f := range []struct {
		name     string
		got, exp float64
	}{
		{"DecisionAgreement", m.DecisionAgreement, m2.DecisionAgreement},
		{"FalseNegativeRate", m.FalseNegativeRate, m2.FalseNegativeRate},
		{"FalsePositiveRate", m.FalsePositiveRate, m2.FalsePositiveRate},
		{"Spearman", m.Spearman, m2.Spearman},
		{"Kendall", m.Kendall, m2.Kendall},
		{"AUC", m.AUC, m2.AUC},
	} {
		if f.got != f.exp {
			t.Errorf("过滤后的 %s 必须与『只喂 targeted_ttp』逐位相同：%v vs %v", f.name, f.got, f.exp)
		}
	}
}

// TestBasisGuardComparePathIsGuarded：守卫在 `CompareWith`（对比入口）这条路径上也生效 ——
// 报告不会以"混算了两类"的名义悄悄给出结论。
//
// 判据用**都进指标**的那个配置（逃生开关 + 两类混在），因为缺省口径下侦察口径的记录会被自动
// 丢出指标（那是正确的行为，不是错误）。
func TestBasisGuardComparePathIsGuarded(t *testing.T) {
	bases := []string{edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook,
		edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook}
	recs := basisRecords(t, bases...)
	params := map[string]edgefactor.Params{"legacy": t9LegacyCandidate()}
	opts := EvaluateOptions{AllowMixedBasis: true}
	if _, err := CompareWith(recs, params, t9Weights(), opts); err == nil {
		t.Fatal("Compare 路径必须同样被依据守卫拦住（两类都进指标 = 混算）")
	} else if !strings.Contains(err.Error(), "basis") {
		t.Errorf("错误必须指向 basis：%v", err)
	}
	// 对照：缺省口径下同一份数据**能**给出报告（侦察口径被丢出指标、剩下 2 条目标）。
	rep, err := CompareWith(recs, params, t9Weights(), EvaluateOptions{})
	if err != nil {
		t.Fatalf("缺省口径下应当能算（丢侦察口径）：%v", err)
	}
	if m := rep.Models["legacy"]; m.N != 2 || m.BasisSkipped[edgeexp.BasisReconPlaybook] != 2 {
		t.Errorf("报告里的指标必须反映过滤：N=%d skipped=%+v", m.N, m.BasisSkipped)
	}
}

// truncForTest 只用于把失败信息里的长输出截断（不影响判据）。
func truncForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
