//go:build edgeexp

// 本文件是 Task 4D Step 4 的用例：**决策层标签的依据守卫**（用户裁定的 L2）。
//
// 为什么必须有它：`compromised` 现在有两种口径 —— `targeted_ttp`（该场景的目标 TTP 是否成功）
// 与 `recon_playbook`（固定侦察剧本的结果，**任何姿态下都成功**，只作背景测量）。两者在数据上
// 完全同形（都是一个 bool），把它们混进同一个漏判率（或同一个拟合似然）里，指标就没有定义；
// 而"旧数据集没有 basis"这件事会让默认路径静默地把历史数据也算进来。
//
// 三条判据（**两条路径同一套**：候选对比 `EvaluateWith/CompareWith` 与参数拟合 `Fit`）：
//  1. 缺 `basis` ⇒ **报错**（不静默算，也不静默丢）；
//  2. 两类混在一起 ⇒ 侦察口径的记录被**自动丢出**决策层/拟合，条数写进 `BasisSkipped` 与报告头；
//     只有 `AllowMixedBasis`（让两类**都进**）时才是真矛盾 ⇒ **报错**；
//  3. 侦察口径的记录**始终**被丢出决策层指标，且被丢的条数**写进指标本体与报告头**（分母 N 变了，
//     不写清就没法比）。
//
// Fix round 2 / Important-1 之前，拟合路径**完全没有**接守卫（`fit.go` 里没有一处引用 `Basis`），
// 于是四种依据形态在 `-fit` 下一律 rc=0，连这两个开关都被静默忽略。文件末尾的
// `TestFitGoesThroughTheSameBasisGuard`（四形态 × 三开关矩阵）就是那件事的钉子。
package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

// ============================================================================
// Fix round 2：拟合路径也必须过同一套守卫（Important-1）
// ============================================================================

// fitBasisRecords 造一批**确定性**的拟合记录（真值可知：每一对里一条被攻陷、一条没有），
// 并按调用方给的序列设依据。
//
// 为什么不用 `syntheticRecordsN`（上一个版本用的）：那批记录的标签是**随机**的，于是"过滤后
// 只剩 2 条"这种格子会偶然落在单类别上，用例就以 `validateLabelVariation` 的名义变红 ——
// 那不是被测判据的红（"用错误的原因变红"是最难发现的一类假证据）。本夹具把类别与基线的对应
// 关系写死，故每一格的期望都能精确写出。
//
// 因子链含 A/B 两条主效应（`aA`/`aB` 在 0.05…0.95 之间取值，与 `syntheticRecordsN` 同量级），
// 故 `fitBaseParams()` + `fitEdgeOpts()` 可直接用；样本量取 8 的倍数 ⇒ `Folds=3` 合法。
func fitBasisRecords(t *testing.T, bases ...string) []Record {
	t.Helper()
	n := len(bases)
	if n < 6 || n%2 != 0 {
		t.Fatalf("本夹具要求偶数且 ≥ 6 条（两类各半、Folds=3 合法），收到 %d 条", n)
	}
	aLevels := []float64{0.05, 0.35, 0.65, 0.95}
	recs := make([]Record, 0, n)
	base := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	compromised := 0
	for i := 0; i < n; i++ {
		aA, aB := aLevels[i%4], aLevels[(i/2)%4]
		rec := Record{
			ScenarioID: fmt.Sprintf("FITBASIS-%02d", i),
			Observed: Observed{
				DomainScores: map[string]float64{"attack_surface": 60},
				Threshold:    50,
				SPCScore:     0.8,
				ThreatCoeff:  0.7,
			},
		}
		for _, f := range []struct {
			id string
			a  float64
		}{{"A", aA}, {"B", aB}} {
			rec.Observed.EdgeFactorChain = append(rec.Observed.EdgeFactorChain, ChainObs{
				Factor: f.id, TriggerCheck: "OT-005", CTrigger: 1,
				EffectiveFactor: 1 - f.a,
				TS:              base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			})
		}
		rec.GroundTruth.Compromised = i%2 == 1 // 一半被攻陷、一半没有
		rec.GroundTruth.Basis = bases[i]
		if rec.GroundTruth.Compromised {
			compromised++
			rec.GroundTruth.TTPsAchieved = 3
			rec.GroundTruth.NodesAffected = 2
		}
		recs = append(recs, rec)
	}
	// 判据前置（用例本身的前提）：两类标签都在，否则 `validateLabelVariation` 会先把我们拦下，
	// 用例就测不到 basis 这条判据。
	if compromised == 0 || compromised == n {
		t.Fatalf("夹具的标签是单类别（%d/%d 被攻陷）—— 判据矩阵的前提不成立", compromised, n)
	}
	return recs
}

// fitOptsWith 在默认拟合选项上叠加依据口径开关（与 CLI 传给 `FitOptions` 的两个字段同款）。
func fitOptsWith(seed int64, opts EvaluateOptions) FitOptions {
	fo := fitEdgeOpts(seed)
	fo.AllowMixedBasis = opts.AllowMixedBasis
	fo.AssumeBasis = opts.AssumeBasis
	return fo
}

// TestFitGoesThroughTheSameBasisGuard 是 Important-1 的**判据矩阵**：四形态 × 三开关。
//
// 每一格都对着"上一版会怎么做"写期望（上一版在 `-fit` 下 12 格全部 rc=0、两个开关被静默忽略）：
//
//	形态              默认                     --allow-mixed-basis        --assume-basis targeted_ttp
//	1 全 targeted_ttp  拟合（N=8）              拟合（N=8）                 拟合（N=8，assumed=0）
//	2 全 recon_playbook **不可算：报错**（N=0）  拟合（N=8，吃背景测量）      **不可算：报错**（assume 只管"缺依据"）
//	3 混合(4+4)        拟合（N=4，跳过 4）      **报错**（混算无定义）       拟合（N=4，跳过 4）
//	4 全缺席(旧记录)   **报错**（缺依据）         **不可算：报错**（缺依据被丢） 拟合（N=8，assumed=8）
//
// 判据取"错误/成功 + N + 依据计数 + 跳过计数"，不看系数 —— 系数由别的用例管（本格的被测对象是**口径**）。
func TestFitGoesThroughTheSameBasisGuard(t *testing.T) {
	const (
		T = edgeexp.BasisTargetedTTP
		R = edgeexp.BasisReconPlaybook
		E = ""
	)
	emptyFit := "过滤后没有任何记录进入拟合"
	forms := []struct {
		name  string
		bases []string
	}{
		{"全 targeted_ttp", []string{T, T, T, T, T, T, T, T}},
		{"全 recon_playbook", []string{R, R, R, R, R, R, R, R}},
		{"混合(4+4)", []string{T, T, T, T, R, R, R, R}},
		{"全缺席(旧记录)", []string{E, E, E, E, E, E, E, E}},
	}
	type want struct {
		err      bool   // 期望报错
		errHas   string // 报错时必须出现的字样（判"错得对"）
		n        int    // 期望参与条数
		skippedR int    // 跳过里 recon 的条数
		assumed  int    // 按假设归类的条数
		basisKey string // 参与部分的依据键（生效依据）
	}
	switches := []struct {
		name string
		opts EvaluateOptions
		want map[string]want // form name → want
	}{
		{"默认", EvaluateOptions{}, map[string]want{
			"全 targeted_ttp":   {n: 8, basisKey: T},
			"全 recon_playbook": {err: true, errHas: emptyFit},
			"混合(4+4)":          {n: 4, skippedR: 4, basisKey: T},
			"全缺席(旧记录)":         {err: true, errHas: "没有 ground_truth.basis"},
		}},
		{"--allow-mixed-basis", EvaluateOptions{AllowMixedBasis: true}, map[string]want{
			"全 targeted_ttp":   {n: 8, basisKey: T},
			"全 recon_playbook": {n: 8, basisKey: R},
			"混合(4+4)":          {err: true, errHas: R},
			// 逃生开关让"缺依据"按旧口径理解 ⇒ 它们被当作侦察口径丢出决策层 ⇒ 一条都不剩。
			"全缺席(旧记录)": {err: true, errHas: emptyFit},
		}},
		{"--assume-basis targeted_ttp", EvaluateOptions{AssumeBasis: T}, map[string]want{
			"全 targeted_ttp":   {n: 8, basisKey: T},
			"全 recon_playbook": {err: true, errHas: emptyFit}, // assume 只作用于"缺依据"，不改已有依据
			"混合(4+4)":          {n: 4, skippedR: 4, basisKey: T},
			"全缺席(旧记录)":         {n: 8, assumed: 8, basisKey: T},
		}},
	}
	for _, sw := range switches {
		for _, form := range forms {
			t.Run(sw.name+"/"+form.name, func(t *testing.T) {
				recs := fitBasisRecords(t, form.bases...)
				// 全缺席那一格在缺省口径下会先被"缺依据"拒（那正是期望），故两格共用同一次调用。
				_, rep, err := Fit(recs, fitBaseParams(), fitOptsWith(7, sw.opts))
				w := sw.want[form.name]
				if w.err {
					if err == nil {
						t.Fatalf("这一格必须报错（上一版在这里 rc=0 照常出拟合报告）")
					}
					if w.errHas != "" && !strings.Contains(err.Error(), w.errHas) {
						t.Errorf("错误必须点名原因 %q，实际：%v", w.errHas, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("这一格不该报错：%v", err)
				}
				if rep.N != w.n {
					t.Errorf("参与拟合的条数 = %d, want %d（过滤前 %d）", rep.N, w.n, rep.RecordsTotal)
				}
				if rep.RecordsTotal != len(recs) {
					t.Errorf("RecordsTotal 必须是过滤前总数 %d，实际 %d", len(recs), rep.RecordsTotal)
				}
				if got := rep.BasisSkipped[edgeexp.BasisReconPlaybook]; got != w.skippedR {
					t.Errorf("跳过里 recon 的条数 = %d, want %d（全部：%+v）", got, w.skippedR, rep.BasisSkipped)
				}
				if rep.BasisAssumed != w.assumed {
					t.Errorf("按假设归类的条数 = %d, want %d", rep.BasisAssumed, w.assumed)
				}
				// **生效依据**：报告头那一格必须是"哪一类"，不能掉进空串键（Fix round 2 / Minor-2）。
				if rep.Basis[w.basisKey] != w.n || len(rep.Basis) != 1 {
					t.Errorf("参与部分的依据分布必须只有 %s=%d，实际 %+v", w.basisKey, w.n, rep.Basis)
				}
			})
		}
	}
}

// TestFitReportStatesTheBasisLine：拟合报告头必须写出依据口径（与对比报告同一件事）。
//
// 为什么它是独立判据：过滤会改 `N`，而两份风格相同的拟合报告在字面上无法区分 —— 报告的用途正是
// 入档与回填 `[edge_factors.model]`，读者必须能看出"这份系数是用哪一类标签估出来的、丢了多少条"。
func TestFitReportStatesTheBasisLine(t *testing.T) {
	const (
		T = edgeexp.BasisTargetedTTP
		R = edgeexp.BasisReconPlaybook
	)
	recs := fitBasisRecords(t, T, T, T, T, R, R, R, R)
	fitted, rep, err := Fit(recs, fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	var b strings.Builder
	if err := RenderFitReport(&b, fitted, rep); err != nil {
		t.Fatalf("RenderFitReport: %v", err)
	}
	out := b.String()
	for _, want := range []string{"标签依据口径", "参与拟合 4 条", "跳过 4 条",
		edgeexp.BasisReconPlaybook, "过滤前共 8 条"} {
		if !strings.Contains(out, want) {
			t.Errorf("拟合报告头必须含 %q：\n%s", want, truncForTest(out, 1500))
		}
	}
}

// TestFitCLIHonoursBasisSwitches：CLI 层证明这两个开关在 `-fit` 下**真的生效**（上一版被静默忽略）。
//
// 判据取三件事：①同一条命令加 `-assume-basis` 前后退出码从 1 变 0；②加了之后 stdout 里出现依据行；
// ③缺依据时 stderr 必须给出那三条出路中的一条（不是"拟合失败"这类含糊话）。
func TestFitCLIHonoursBasisSwitches(t *testing.T) {
	bases := make([]string, 8) // 全缺席 = 旧数据集形态
	recs := fitBasisRecords(t, bases...)
	records := writeRecordsJSONL(t, "fit-nobasis.jsonl", recs)
	cfg := writeConfig(t, "fit-base.ini",
		"[edge_factors.model]\nmodel = graph\np_floor = 0.5\nlambda.attack_surface = 1\nvector.A = 1,0,0,0,0\nvector.B = 1,0,0,0,0\n")
	base := []string{"-records", records, "-fit", "-config", cfg, "-factors", "A=0.5,B=0.5",
		"-edges", "A|B", "-seed", "7", "-folds", "3", "-l2", "0.01"}

	code, _, stderr := runCLIForTest(t, base...)
	if code == 0 {
		t.Fatalf("缺依据的记录在 -fit 下必须被拒（上一版这里 rc=0 静默出拟合报告）；stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "basis") && !strings.Contains(stderr, "依据") {
		t.Errorf("拒绝理由必须指向标签依据，实际 stderr=%s", stderr)
	}

	code, stdout, stderr := runCLIForTest(t, append(append([]string{}, base...),
		"-assume-basis", edgeexp.BasisTargetedTTP)...)
	if code != 0 {
		t.Fatalf("--assume-basis 在 -fit 下必须生效（不得被静默忽略）：rc=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "标签依据口径") {
		t.Errorf("拟合产物必须写明依据口径：\n%s", truncForTest(stdout, 1500))
	}
	if !strings.Contains(stdout, "bas`--assume-basis` 归类") && !strings.Contains(stdout, "--assume-basis") {
		t.Errorf("拟合产物必须写明有多少条是按假设归类的：\n%s", truncForTest(stdout, 1500))
	}
	if !strings.Contains(stderr, "--assume-basis") {
		t.Errorf("stderr 必须喊出假设生效（与对比路径同款可见性）：%s", stderr)
	}
}

// TestNothingIsConcludedWhenTheFilterEmptiesTheDecisionLayer：**过滤后 N=0 ⇒ 不给结论**（Minor-3）。
//
// Task 5 的第一次全量决策层报告极可能落在这一格上：22 个非 AppArmor 场景没有目标 TTP，它们的记录
// 必然是 `recon_playbook`；一旦整批里没有 `targeted_ttp`，决策层就只剩 N=0。上一版在**单候选**时
// 仍会打印「选定模型」与一整段参数（两候选时既有"全等 ⇒ 不选模"规则能兜住）。
func TestNothingIsConcludedWhenTheFilterEmptiesTheDecisionLayer(t *testing.T) {
	const R = edgeexp.BasisReconPlaybook
	recs := basisRecords(t, R, R, R, R)
	params := map[string]edgefactor.Params{"legacy": t9LegacyCandidate()}

	// ① 单候选 + 全侦察口径 ⇒ CompareWith 必须报错（不给结论）。
	if _, err := CompareWith(recs, params, t9Weights(), EvaluateOptions{}); err == nil {
		t.Fatal("过滤后 N=0 时不得给出『选定模型』—— 必须报错")
	} else if !strings.Contains(err.Error(), R) || !strings.Contains(err.Error(), "不给出结论") {
		t.Errorf("错误必须写清『不给出结论』与跳过的是哪一类，实际：%v", err)
	}

	// ② 导出层同样是独立闸门（手搓 Report 的调用方也拦得住）：N=0 时不打印选模结论。
	m := Metrics{BasisSkipped: map[string]int{R: 4}, RecordsTotal: 4}
	rep := Report{Records: 4, Models: map[string]Metrics{"legacy": m}, Best: "legacy"}
	var b strings.Builder
	if err := RenderMarkdown(&b, rep); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "未选模") {
		t.Errorf("N=0 的报告必须明确写『未选模』：\n%s", truncForTest(out, 1200))
	}
	if strings.Contains(out, "**选定模型**") {
		t.Errorf("N=0 的报告不得出现「选定模型」：\n%s", truncForTest(out, 1200))
	}
}
