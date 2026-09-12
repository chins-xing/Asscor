//go:build edgeexp

package main

import (
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
	ssam "github.com/chins-xing/ssam"
)

// ============================================================================
// 离线 ↔ 在线一致性门禁（主控裁定 C1，Fix wave 重写）
// ============================================================================
//
// **旧版门禁为什么必须删掉**：它把生产实现与一个测试侧独立重写的"在线接线镜像"
// （`onlineMirror`）逐位对比 —— 而两者都只是同一个 `edgefactor.Synthesize` + 自研聚合的
// 两份抄写。这样的门禁**永远无法与真实引擎对拍**：评审实测的致命口径差
// （离线 `weightedSum × 乘子` vs 引擎 `round2(0.5·base + 30·E + 20·T)`）在旧门禁下是绿的，
// 因为两侧犯的是同一个错。门禁的对照物必须是**部署引擎真正调用的那个函数**。
//
// 新版门禁的内容 —— 每条都直接调用或直接对照 `ssam.SSAMV20Formula`：
//
//	1. **同一公式**：离线的总分 == `ssam.SSAMV20Formula` 对同一组入参的 `Total`。
//	   legacy 分支的入参在**测试里独立装配**（自己遍历默认域、自己构造因子结果），
//	   并显式保证钩子处于默认状态 —— 这条对照物是内仓的真实公式，不是本工具的抄写。
//	2. **同一注入方式**：V/G/C 的域级修正走 `ssam.RegisterDomainAdjust`（在线同一入口），
//	   恒等乘子走 `ssam.RegisterEdgeFactorStrategy`；期望值用「预修正域分 + 恒等因子 + 真实
//	   公式」独立算出，并附反向对照（不做域级修正时分数必然不同）。
//	3. **同一裁剪口径**：请求域 = `DefaultDomains ∩ λ`（`edgefactor.RequestedDomains`，
//	   与在线装配期同一实现）。不裁剪的完整默认域调用必须被拒 —— 否则本门禁测不到裁剪。
//	4. **同一评审反例**：评审实测的那条记录（域分 62.5、threshold 60、因子 0.8）在旧口径下
//	   判 not acceptable、在引擎口径下判 acceptable，本门禁把它钉成可执行证据。
//
// 可信度换算的口径（spec §10.2 记录在案，本轮**不修正**）：legacy 直接使用记录里的
// `effective_factor`（策略层已衰减一次的观测值 = 引擎 `EdgeFactorResult.Factor`），
// V/G/C 在合成层前再衰减一次（`EffectiveFactor(f, c)`，与在线 `activationsFromResults` 同口径）。
// 这两条与在线逐位一致，正是 C1 要的"同一个量"。

// engineFormulaDirect 用**测试侧独立装配**的入参调用真实引擎公式（legacy 分支）。
//
// 它刻意不复用生产侧的 `engineDomainScores` / `engineEdgeFactors`：门禁要抓的正是
// "生产侧的装配与引擎口径不一致"，复用生产代码会把这条检查变成同义反复。
// 钩子显式恢复成默认（legacy 零注册 = 内仓默认的逐次相乘路径）。
func engineFormulaDirect(rec Record, weights map[string]float64) ssam.FinalScore {
	ssam.RegisterEdgeFactorStrategy(nil)
	ssam.RegisterDomainAdjust(nil)

	scores := make([]ssam.DomainScore, 0, len(weights))
	for _, d := range edgefactor.DefaultDomains() {
		if w, ok := weights[d]; ok && w > 0 {
			scores = append(scores, ssam.DomainScore{Domain: d, Score: rec.Observed.DomainScores[d]})
		}
	}
	weightConfigs := make([]ssam.WeightConfig, 0, len(weights))
	for d, w := range weights {
		weightConfigs = append(weightConfigs, ssam.WeightConfig{Domain: d, Weight: w})
	}
	factors := make([]ssam.EdgeFactorResult, 0, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		factors = append(factors, ssam.EdgeFactorResult{
			ID: edgefactor.NormalizeFactorID(c.Factor),
			// 记录里的 effective_factor 就是引擎侧 EdgeFactorResult.Factor（策略层衰减一次后的观测值）。
			Factor:            c.EffectiveFactor,
			Active:            true,
			TriggerConfidence: c.CTrigger,
		})
	}
	return ssam.SSAMV20Formula(scores, weightConfigs,
		ssam.RiskContext{Exposure: rec.Observed.SPCScore, Threat: rec.Observed.ThreatCoeff},
		factors)
}

// bespokeAggregate 是**被 C1 废弃的旧口径**：`weightedSum(观测域分) × ∏effective_f`。
// 它只出现在反例里，用来证明新门禁有区分力（旧实现回归时第 1 条测试会立刻变红）。
func bespokeAggregate(rec Record, weights map[string]float64) float64 {
	sum, total := 0.0, 0.0
	for _, d := range edgefactor.DefaultDomains() {
		w := weights[d]
		if w <= 0 {
			continue
		}
		sum += rec.Observed.DomainScores[d] * w
		total += w
	}
	if total == 0 {
		return 0
	}
	mult := 1.0
	for _, c := range rec.Observed.EdgeFactorChain {
		mult *= c.EffectiveFactor
	}
	return sum / total * mult
}

// twoFactorChainJSONL 是门禁用的两条记录：同一条链里同时激活 A 与 B（graph 耦合项真的被算到），
// c_trigger = 1.0，域分只给 attack_surface（与裁剪后的请求域一致）。
const twoFactorChainJSONL = `{"scenario_id":"CONS-R1","factors":["A","B"],"observed":{"domain_scores":{"attack_surface":80},"threshold":50,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"A","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.6,"ts":"2026-09-08T10:00:00Z"},{"factor":"B","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.5,"ts":"2026-09-08T10:00:01Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":100,"ttps_achieved":2,"nodes_affected":1,"block_effective":false}}
{"scenario_id":"CONS-R2","factors":["A"],"observed":{"domain_scores":{"attack_surface":30},"threshold":50,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"A","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.9,"ts":"2026-09-08T10:00:02Z"}]},"ground_truth":{"compromised":false,"time_to_compromise_s":0,"ttps_achieved":0,"nodes_affected":0,"block_effective":true}}
`

// consGraphParams 是门禁用的 graph 候选：λ 只声明 attack_surface、向量只覆盖该域（故**必须**
// 裁剪才过得了 Validate），并带一条真实耦合 A→B。
func consGraphParams() edgefactor.Params {
	return edgefactor.Params{
		Model:   edgefactor.ModelGraph,
		PFloor:  0.4,
		Lambda:  map[string]float64{"attack_surface": 2.0},
		Vectors: map[string]map[string]float64{"A": {"attack_surface": 1.0}, "B": {"attack_surface": 1.0}},
		Coupling: map[string]map[string]float64{
			"A": {"B": 0.5},
		},
		Factors: map[string]float64{"A": 0.6, "B": 0.5},
	}
}

func consWeights() map[string]float64 { return map[string]float64{"attack_surface": 1} }

func consRecords(t *testing.T) []Record {
	t.Helper()
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	return recs
}

// legacyParityParams 是门禁 legacy 分支的候选参数（与在线 legacy 同一条路径：零注册）。
func legacyParityParams() edgefactor.Params {
	return edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5,
		Factors: map[string]float64{"A": 0.6, "B": 0.5}}
}

// TestConsistencyGateOfflineEqualsEngineFormula 是门禁的主测试（legacy 分支）：
// 离线重算的总分必须**逐位等于**真实引擎公式对同一组入参的输出。
//
// 对照物是内仓的 `ssam.SSAMV20Formula`（部署引擎实际调用的那个函数），入参在测试侧独立装配。
// 旧实现（自研加权和 × 乘子）在这条测试下必然红 —— 两条判定线不是同一个量。
func TestConsistencyGateOfflineEqualsEngineFormula(t *testing.T) {
	p := legacyParityParams()
	for _, rec := range consRecords(t) {
		offline, err := OfflineScoreWithWeights(p, rec, consWeights())
		if err != nil {
			t.Fatalf("%s: OfflineScoreWithWeights: %v", rec.ScenarioID, err)
		}
		want := engineFormulaDirect(rec, consWeights()).Total
		if offline != want {
			t.Fatalf("%s: 离线总分 %v ≠ 引擎公式 SSAMV20Formula 的 Total %v（两条判定线不是同一个量）",
				rec.ScenarioID, offline, want)
		}
		// 反向对照：废弃的旧口径（加权和 × 乘子）**不等于**引擎总分 ⇒ 本门禁真的有区分力，
		// 不是"两边都算错还相等"。
		if bespoke := bespokeAggregate(rec, consWeights()); bespoke == offline {
			t.Fatalf("%s: 旧口径与新口径给出同一个数（%v）—— 本门禁测不出 C1 要求的差异",
				rec.ScenarioID, bespoke)
		}
	}
}

// TestConsistencyGateReproducesTheReviewerCounterexample：评审实测的那条记录 ——
//
//	域分 62.5、threshold 60、因子 0.8
//	旧离线口径：62.5 × 0.8 = 50 < 60 ⇒ not acceptable
//	引擎口径  ：round2(0.5×50 + 30×1 + 20×1) = 75 ≥ 60 ⇒ acceptable
//
// 两条判定线给出**相反结论**。C1 之后离线必须跟随引擎（这才是部署行为），
// 且这条断言同时钉住"量纲"这件事：引擎总分既不是域分，也不是域分×乘子。
func TestConsistencyGateReproducesTheReviewerCounterexample(t *testing.T) {
	const recJSON = `{"scenario_id":"REVIEW-CASE","factors":["EF-SELINUX"],"observed":{"domain_scores":{"attack_surface":62.5},"threshold":60,"spc_score":1.0,"threat_coeff":1.0,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.8}]},"ground_truth":{"compromised":false}}`
	recs, err := LoadRecords(writeJSONL(t, "review-case.jsonl", recJSON+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	rec := recs[0]
	p := edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5,
		Factors: map[string]float64{"EF-SELINUX": 0.8}}
	weights := map[string]float64{"attack_surface": 1}

	if got := bespokeAggregate(rec, weights); got != 50 {
		t.Fatalf("反例前提失效：旧口径应为 62.5×0.8 = 50，实得 %v", got)
	}
	offline, err := OfflineScoreWithWeights(p, rec, weights)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	if offline != 75 {
		t.Errorf("离线总分 = %v, want 75（引擎公式：round2(0.5×50 + 30×1 + 20×1)）", offline)
	}
	if offline < rec.Observed.Threshold {
		t.Errorf("离线判定 = not acceptable（%v < %v）—— 引擎会判 acceptable，两条判定线又反了",
			offline, rec.Observed.Threshold)
	}
	if offline == bespokeAggregate(rec, weights) {
		t.Error("离线总分等于废弃的旧口径 —— C1 没有落地")
	}
}

// TestConsistencyGateVGCUsesTheSameDomainAdjustAsTheEngine：V/G/C 分支的对照 ——
//
// 引擎的域级修正是"域聚合之前乘 P_d"，乘子恒为 1（惩罚完全由 P_d 表达）。测试侧独立算出
// 期望值：先用合成层唯一实现 `edgefactor.Synthesize` 取 P_d，把观测域分**预修正**，
// 再调用真实公式并让默认策略乘 1（Factor = 1 落在默认策略的判据之外 ⇒ 乘子恒 1）。
func TestConsistencyGateVGCUsesTheSameDomainAdjustAsTheEngine(t *testing.T) {
	p := consGraphParams()
	recs := consRecords(t)
	weights := consWeights()

	requested := edgefactor.RequestedDomains(p)
	if len(requested) == 0 {
		t.Fatal("夹具失效：graph 候选应至少覆盖一个默认域的 λ")
	}
	plan := edgefactor.PruneToDomains(p, requested)

	for _, rec := range recs {
		offline, err := OfflineScoreWithWeights(p, rec, weights)
		if err != nil {
			t.Fatalf("%s: OfflineScoreWithWeights: %v", rec.ScenarioID, err)
		}

		// 期望值：预修正的域分 + 恒等乘子 + 真实公式。
		acts := make([]edgefactor.FactorActivation, 0, len(rec.Observed.EdgeFactorChain))
		identity := make([]ssam.EdgeFactorResult, 0, len(rec.Observed.EdgeFactorChain))
		for _, c := range rec.Observed.EdgeFactorChain {
			id := edgefactor.NormalizeFactorID(c.Factor)
			if _, known := p.Factors[id]; !known {
				continue
			}
			acts = append(acts, edgefactor.FactorActivation{
				FactorID:        id,
				CTrigger:        c.CTrigger,
				EffectiveFactor: edgefactor.EffectiveFactor(c.EffectiveFactor, c.CTrigger),
				TS:              mustTS(t, c.TS),
			})
			identity = append(identity, ssam.EdgeFactorResult{
				ID: id, Factor: 1, Active: true, TriggerConfidence: c.CTrigger,
			})
		}
		res, err := edgefactor.Synthesize(plan, requested, edgefactor.Input{Factors: acts})
		if err != nil {
			t.Fatalf("%s: Synthesize: %v", rec.ScenarioID, err)
		}
		adjusted := map[string]float64{}
		for d, s := range rec.Observed.DomainScores {
			adjusted[d] = s
		}
		for d, pd := range res.P {
			adjusted[d] = rec.Observed.DomainScores[d] * pd
		}

		ssam.RegisterEdgeFactorStrategy(nil)
		ssam.RegisterDomainAdjust(nil)
		scores := make([]ssam.DomainScore, 0, len(weights))
		for _, d := range edgefactor.DefaultDomains() {
			if w, ok := weights[d]; ok && w > 0 {
				scores = append(scores, ssam.DomainScore{Domain: d, Score: adjusted[d]})
			}
		}
		riskCtx := ssam.RiskContext{Exposure: rec.Observed.SPCScore, Threat: rec.Observed.ThreatCoeff}
		want := ssam.SSAMV20Formula(scores, []ssam.WeightConfig{{Domain: "attack_surface", Weight: 1}},
			riskCtx, identity).Total
		if offline != want {
			t.Fatalf("%s: 离线 %v ≠ 「预修正域分 + 恒等乘子 + 真实公式」%v", rec.ScenarioID, offline, want)
		}

		// 反向对照：不做域级修正时分数必然不同 —— 否则本测试测不到域级修正这条通路。
		unadjusted := ssam.SSAMV20Formula(
			[]ssam.DomainScore{{Domain: "attack_surface", Score: rec.Observed.DomainScores["attack_surface"]}},
			[]ssam.WeightConfig{{Domain: "attack_surface", Weight: 1}},
			riskCtx, identity).Total
		if unadjusted == offline {
			t.Fatalf("%s: 未修正与已修正的分数相同（%v）—— 域级修正没有生效", rec.ScenarioID, offline)
		}
	}
}

// TestConsistencyGateUsesTheFormulaOutputVerbatim：离线返回的就是公式的输出对象本身 ——
// `.Total` 与三层明细全部来自 `SSAMV20Formula`，不存在"离线自己再聚合一次"的中间步骤。
// 三层权重（50/30/20）是内仓公式的常量，一个自研聚合不可能凭空产出它们。
func TestConsistencyGateUsesTheFormulaOutputVerbatim(t *testing.T) {
	rec := consRecords(t)[0]
	res, err := offlineFormulaResult(legacyParityParams(), rec, consWeights())
	if err != nil {
		t.Fatalf("offlineFormulaResult: %v", err)
	}
	total, err := OfflineScoreWithWeights(legacyParityParams(), rec, consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	if res.Total != total {
		t.Fatalf("离线入口的分数 %v ≠ 公式输出的 Total %v", total, res.Total)
	}
	if res.Layers.Intrinsic.Weight != 50 || res.Layers.Exposure.Weight != 30 || res.Layers.Threat.Weight != 20 {
		t.Errorf("三层权重 = %v/%v/%v, want 50/30/20（引擎公式的固定层次）",
			res.Layers.Intrinsic.Weight, res.Layers.Exposure.Weight, res.Layers.Threat.Weight)
	}
	want := engineFormulaDirect(rec, consWeights())
	if res.Total != want.Total {
		t.Errorf("离线 = %v, 直接调用引擎公式 = %v", res.Total, want.Total)
	}
	if res.Layers.Intrinsic.Coeff != want.Layers.Intrinsic.Coeff {
		t.Errorf("Intrinsic 层系数 = %v, want %v", res.Layers.Intrinsic.Coeff, want.Layers.Intrinsic.Coeff)
	}
}

// TestConsistencyGateCoversCouplingNotJustMainEffects：门禁必须真的走到耦合项上 ——
// 若把 consGraphParams 的耦合清零，分数必须变（否则上面的测试只在测主效应）。
func TestConsistencyGateCoversCouplingNotJustMainEffects(t *testing.T) {
	rec := consRecords(t)[0]
	withCoupling, err := OfflineScoreWithWeights(consGraphParams(), rec, consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	noCoupling := consGraphParams()
	noCoupling.Coupling = nil
	plain, err := OfflineScoreWithWeights(noCoupling, rec, consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights(无耦合): %v", err)
	}
	if withCoupling == plain {
		t.Fatalf("耦合清零后分数不变（%v）⇒ 门禁没有覆盖耦合路径", withCoupling)
	}
	if withCoupling >= plain {
		t.Errorf("耦合应加重惩罚：有耦合 %v 应 < 无耦合 %v", withCoupling, plain)
	}
}

// TestConsistencyGatePrunesDomainsLikeTheOnlineAssembly：裁剪口径必须是
// `DefaultDomains ∩ λ`（与在线装配期同一实现 `edgefactor.RequestedDomains`）。证据是
// **两条路径的对照**：按完整默认域直接调用 Synthesize 会被拒（缺 λ / 向量不覆盖），
// 而离线路径（与在线同一裁剪）能算。
func TestConsistencyGatePrunesDomainsLikeTheOnlineAssembly(t *testing.T) {
	rec := consRecords(t)[0]
	p := consGraphParams()
	// 不裁剪：请求域含没有 λ 的域 ⇒ Synthesize 必须拒绝。这条断言保证本测试真的在测裁剪，
	// 而不是"两条路径都恰好能算"。
	if _, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), edgefactor.Input{
		Factors: modelActivations(p, rec),
	}); err == nil {
		t.Fatal("未经裁剪的完整默认域调用本应被拒 —— 否则本测试测不到裁剪口径")
	}
	if _, err := OfflineScoreWithWeights(p, rec, consWeights()); err != nil {
		t.Fatalf("离线路径应自行裁剪到 DefaultDomains ∩ λ 并成功：%v", err)
	}
	// 裁剪口径本身与在线同一实现：请求域 = DefaultDomains ∩ λ，且保持默认域顺序。
	if got, want := edgefactor.RequestedDomains(p), []string{"attack_surface"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RequestedDomains = %v, want %v", got, want)
	}
}

// TestConsistencyGateGoesThroughDomainCoverageCheck：门禁的域覆盖校验必须落在 `Evaluate`
// 层（带权重却无观测域分的记录直接拒绝），而不是让低阶原语静默按 0 聚合。
func TestConsistencyGateGoesThroughDomainCoverageCheck(t *testing.T) {
	recs := consRecords(t)
	// 记录只有 attack_surface，权重表却给 operation_trust 也记了分量 ⇒ 必须先拒绝。
	weights := map[string]float64{"attack_surface": 1, "operation_trust": 1}
	if _, err := Evaluate(recs, consGraphParams(), weights); err == nil {
		t.Fatal("Evaluate 必须拒绝『有权重却无观测域分』的记录")
	}
	// 低阶原语不做这条校验（它照算）—— 门禁因此只走 Evaluate / 显式校验，正是本节存在的原因。
	if _, err := OfflineScoreWithWeights(consGraphParams(), recs[0], weights); err != nil {
		t.Fatalf("低阶原语按约定不做域覆盖校验：%v", err)
	}
	// 覆盖齐全时 Evaluate 必须成功。
	if _, err := Evaluate(recs, consGraphParams(), consWeights()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

// TestConsistencyGateHoldsAcrossWeightTables：换权重表只应改聚合口径，
// 离线结果仍必须与真实引擎公式逐位相等（权重表是公式的入参之一，不是离线自己发明的）。
func TestConsistencyGateHoldsAcrossWeightTables(t *testing.T) {
	rec := consRecords(t)[0]
	p := legacyParityParams()
	for _, w := range []map[string]float64{
		{"attack_surface": 1},
		{"attack_surface": 3},
		{"attack_surface": 1, "operation_trust": 2},
	} {
		offline, err := OfflineScoreWithWeights(p, rec, w)
		if err != nil {
			t.Fatalf("offline(%v): %v", w, err)
		}
		want := engineFormulaDirect(rec, w).Total
		if offline != want {
			t.Errorf("权重 %v 下离线 %v ≠ 引擎公式 %v", w, offline, want)
		}
	}
}

// TestConsistencyGateIsBitwiseReproducible：同一输入重复重算必须逐位相同 ——
// 钩子是进程级全局态，安装/拆除若有泄漏或顺序漂移，门禁与报告都会"偶然绿、偶然红"。
func TestConsistencyGateIsBitwiseReproducible(t *testing.T) {
	for _, p := range []edgefactor.Params{legacyParityParams(), consGraphParams()} {
		for _, rec := range consRecords(t) {
			first, err := OfflineScoreWithWeights(p, rec, consWeights())
			if err != nil {
				t.Fatalf("%s/%s: %v", p.Model, rec.ScenarioID, err)
			}
			for i := 0; i < 100; i++ {
				again, err := OfflineScoreWithWeights(p, rec, consWeights())
				if err != nil {
					t.Fatalf("repeat %d: %v", i, err)
				}
				if !reflect.DeepEqual(first, again) {
					t.Fatalf("%s/%s: 第 %d 次重算 = %v ≠ %v（聚合序或钩子状态不确定）",
						p.Model, rec.ScenarioID, i, again, first)
				}
			}
		}
	}
}

// TestConsistencyGateLeavesHooksUnregistered：用完之后钩子必须回到**默认**
// （`Register*(nil)`）。残留注册会在下一次评分里静默改变分数：钩子是进程级的，
// 而 default（逐次相乘）与"注入的等价策略（base×乘子）"在取整半格边界上不同。
func TestConsistencyGateLeavesHooksUnregistered(t *testing.T) {
	rec := consRecords(t)[0]
	if _, err := OfflineScoreWithWeights(consGraphParams(), rec, consWeights()); err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	// 拆除后，直接用默认路径算同一个 legacy 输入必须与"从未装过钩子"一致。
	got := engineFormulaDirect(rec, consWeights()).Total
	want, err := OfflineScoreWithWeights(legacyParityParams(), rec, consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights(legacy): %v", err)
	}
	if got != want {
		t.Fatalf("V/G/C 重算后 legacy 直接调用公式 = %v ≠ 离线 legacy %v —— 钩子有残留",
			got, want)
	}
}

// TestConsistencyGateChainWindowComesFromTheRecord：chain 的时间戳只能来自 JSONL
// （在线结果类型没有时间字段），窗口内外必须给出不同分数，且窗口内受更重的惩罚。
func TestConsistencyGateChainWindowComesFromTheRecord(t *testing.T) {
	p := consGraphParams()
	p.Model = edgefactor.ModelChain
	p.ChainWindowSeconds = 30

	within := consRecords(t)
	// 窗口外的那条必须**重新读一份 JSONL**（不能浅拷贝 Record 后改字段：Record 里的
	// EdgeFactorChain 是切片，浅拷贝会让两条记录共享同一份链条目）。
	outside, err := LoadRecords(writeJSONL(t, "cons-outside.jsonl",
		strings.Replace(twoFactorChainJSONL, `"ts":"2026-09-08T10:00:01Z"`, `"ts":"2026-09-08T10:05:00Z"`, 1)))
	if err != nil {
		t.Fatalf("LoadRecords(outside): %v", err)
	}

	inScore, err := OfflineScoreWithWeights(p, within[0], consWeights())
	if err != nil {
		t.Fatalf("chain(within): %v", err)
	}
	outScore, err := OfflineScoreWithWeights(p, outside[0], consWeights())
	if err != nil {
		t.Fatalf("chain(outside): %v", err)
	}
	if inScore == outScore {
		t.Fatalf("时间戳没有影响结果（%v）：chain 的时序语义未生效", inScore)
	}
	if inScore >= outScore {
		t.Errorf("窗口内应受更重的惩罚：窗口内 %v 应 < 窗口外 %v", inScore, outScore)
	}
	if math.Abs(inScore-outScore) < 1e-9 {
		t.Errorf("窗口内外的差异小到不可观测：%v vs %v", inScore, outScore)
	}
}

// mustTS 解析夹具里的 RFC3339 时间戳（夹具错误即测试失败）。
func mustTS(t *testing.T, v string) time.Time {
	t.Helper()
	ts, err := parseTS(v)
	if err != nil {
		t.Fatalf("夹具时间戳非法 %q: %v", v, err)
	}
	return ts
}

// ============================================================================
// Task 3B：记录自带权重（spec §5.1 前提 2）与域累加顺序（与引擎同序）
// ============================================================================

// spec51Weights 是 spec §5.1 / 计划里那串 `-weights`（35/25/25/15/10，和 **110**）：
// 它**不是**引擎生效的那张表（引擎会 `Normalize(100)`），正是"只凭 `-weights` 复算必然有
// 系统偏差"的实证。
func spec51Weights() map[string]float64 {
	return map[string]float64{
		"attack_surface": 35, "business_continuity": 25, "operation_trust": 25,
		"resilience": 15, "kernel_security": 10,
	}
}

// spec51RecordJSONL 是 Task 3B 的 round-trip 夹具 —— 用的就是 spec §5.1 的那组数
// （域分 82/75/68/71/55、两个因子的观测值 0.82/0.838、E=0.93、T=1.4），外加**记录自带的
// 生效权重表**（那串和 110 的表，键集 = 参与聚合的域）。
//
// `final_score` 取 **81.08** —— spec §5.1 自己记录的那个数（"同一份记录在出厂 `[weights]`
// （35/25/25/15/10）下是 81.08"）；同一份域分在**五域等权**下是 80.02（= spec 示例里写的
// `final_score`）。两个数不同 ⇒ 本夹具能区分"谁提供了权重表"。
const spec51RecordJSONL = `{"scenario_id":"S2-selinux-apparmor-01","factors":["EF-SELINUX","EF-APPARMOR"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":82,"business_continuity":75,"operation_trust":68,"resilience":71,"kernel_security":55},"effective_weights":{"attack_surface":35,"business_continuity":25,"operation_trust":25,"resilience":15,"kernel_security":10},"final_score":81.08,"acceptable":true,"threshold":60,"spc_score":0.93,"threat_coeff":1.4,"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82,"ts":"2026-09-08T10:00:03Z"},{"factor":"EF-APPARMOR","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.838,"ts":"2026-09-08T10:00:03Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","run":1}}`

// spec51Params 是夹具的 legacy 候选（两个因子都建模，f 值即配置值；离线乘的是记录里
// `effective_factor` 的观测值，参数里的 f 只作成员资格判定）。
func spec51Params() edgefactor.Params {
	return edgefactor.Params{Model: edgefactor.ModelLegacy, PFloor: 0.5,
		Factors: map[string]float64{"EF-SELINUX": 0.80, "EF-APPARMOR": 0.82}}
}

// TestConsistencyGateRoundTripsARecordThatCarriesItsOwnWeights（Task 3B Step 1 的验收）：
// **合法记录**上的 round-trip（门禁②：`|复算 − 记录| == 0`）必须由记录自带的权重表决定。
//
// 这正是 Task 3 复审实测出的规格-实现缺口：门禁② 此前从 `-weights` 取权重，而一条**合法**的
// 记录（引擎按归一后的生效表算分）在这串"和 110"的表下复算不出 `final_score` ⇒ 门禁在合法
// 记录上报红，看起来像数据缺陷。
func TestConsistencyGateRoundTripsARecordThatCarriesItsOwnWeights(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "spec51-weights.jsonl", spec51RecordJSONL+"\n"))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	rec := recs[0]
	if len(rec.Observed.EffectiveWeights) == 0 {
		t.Fatal("夹具失效：记录必须自带生效权重表")
	}

	// 门禁② 的形态：调用方给的是**另一张**表（五域等权），复算仍必须等于记录里的 final_score。
	equal := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		equal[d] = 1
	}
	got, err := OfflineScoreWithWeights(spec51Params(), rec, equal)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	if got != rec.Observed.FinalScore {
		t.Errorf("round-trip 失败：复算 = %v，记录里写的是 %v —— 记录自带的生效权重没有生效",
			got, rec.Observed.FinalScore)
	}
	// spec §5.1 记录的同一组数：这份域分 × 和 110 的权重表 ⇒ 81.08。
	if rec.Observed.FinalScore != 81.08 {
		t.Fatalf("夹具的 final_score 不是 spec §5.1 记录的那个数（%v）", rec.Observed.FinalScore)
	}
	// 反向对照：等权表算出的**另一个**数（80.02 = spec §5.1 示例里的 final_score）。
	withoutWeights := rec
	withoutWeights.Observed.EffectiveWeights = nil
	fallback, err := OfflineScoreWithWeights(spec51Params(), withoutWeights, equal)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights(无生效权重): %v", err)
	}
	if fallback != 80.02 {
		t.Errorf("等权回退值 = %v, want 80.02（spec §5.1 示例里的五域等权值）", fallback)
	}
	if fallback == rec.Observed.FinalScore {
		t.Error("等权表与记录表给出同一个数 —— 本用例没有区分力")
	}
}

// TestConsistencyGateDomainOrderMatchesTheEngine（Task 3B Step 2）：离线装域分切片的顺序必须
// 与**引擎同序**，而不是"数学等价即可"。
//
// 为什么必须同序：内仓公式按切片顺序累加 `sum += ds.Score * w`；在线侧这个切片来自
// `ssam.ComputeDomainScoresBayes`，它对 activeDomains 做 `sort.Slice(Domain <)` ⇒ **字典序**。
// 离线此前按 `DefaultDomains` 的顺序装（`kernel_security` 排在最后）⇒ 两侧是两条不同的浮点
// 累加路径：乘积项不可精确表示时末位会差 1 ulp，而**落在取整半格上的 base** 会因此让总分差 0.01。
//
// 边界有多窄（实测，不是推测）：spec §5.1 那组数（本文件 spec51RecordJSONL）的 base 是
// `round2(73.2727…×0.82×0.838) = 50.35`，总分 raw = `8107.5 + 9.09e-13` —— 离取整边界**只有
// 1 ulp**（`math.Round(8107.5)=8108` ⇒ 81.08，而 `8107.4999…` ⇒ 81.07）。故本用例钉的是
// **结构性**的事实：顺序取自引擎自己，而不是靠"这组数恰好不受顺序影响"。
// （实测补充：该夹具的乘积项都是整数、累加精确，两种顺序给出同一个总分；邻域扫描共 **15125** 组，
// 轴 = 五个域各在 spec 值 ±1.0 内取一位小数（`attack_surface` / `business_continuity` 步长 0.2 各 11 档，
// `operation_trust` / `resilience` / `kernel_security` 步长 0.5 各 5 档 ⇒ 11×11×5×5×5），
// 其中**没有一组**能被两种顺序改变总分 —— 所以本任务不构造"半分位反例"，只留下这条边界记录。）
func TestConsistencyGateDomainOrderMatchesTheEngine(t *testing.T) {
	weights := spec51Weights()

	// 对照物：引擎自己的域分切片顺序 —— 同一份权重表 + 每个域一条检查。
	cfg := make([]ssam.WeightConfig, 0, len(weights))
	checks := make([]ssam.CheckInput, 0, len(weights))
	for d, w := range weights {
		cfg = append(cfg, ssam.WeightConfig{Domain: d, Weight: w})
		checks = append(checks, ssam.CheckInput{CheckID: "C-" + d, Domain: d, Delta: -1, Confidence: 1})
	}
	engineOrder := make([]string, 0, len(weights))
	for _, ds := range ssam.ComputeDomainScoresBayes(cfg, checks, ssam.DefaultConfidencePolicy()) {
		engineOrder = append(engineOrder, ds.Domain)
	}
	if len(engineOrder) != len(weights) {
		t.Fatalf("夹具失效：引擎只为 %d 个域产出域分（want %d）", len(engineOrder), len(weights))
	}
	// 本用例的区分力来自"DefaultDomains 的顺序**确实**与引擎不同"：否则它抓不到这次漂移。
	if reflect.DeepEqual(engineOrder, edgefactor.DefaultDomains()) {
		t.Fatal("夹具失效：DefaultDomains 的顺序恰好等于引擎的字典序 ⇒ 本用例对 Step 2 无区分力")
	}
	if got := orderedDomains(weights); !reflect.DeepEqual(got, engineOrder) {
		t.Errorf("离线装切片的顺序 %v ≠ 引擎 ComputeDomainScoresBayes 的输出顺序 %v —— "+
			"两侧是两条不同的浮点累加路径，落在取整半格上的 base 会因此差 0.01", got, engineOrder)
	}

	// 离线**实际装出的**域分切片也必须按该序（顺序契约的消费者是 engineDomainScores）。
	scores := map[string]float64{}
	for d := range weights {
		scores[d] = 1
	}
	got := engineDomainScores(scores, weights)
	if len(got) != len(engineOrder) {
		t.Fatalf("域分切片长度 = %d, want %d", len(got), len(engineOrder))
	}
	for i := range got {
		if got[i].Domain != engineOrder[i] {
			t.Fatalf("域分切片[%d] = %q, want %q（顺序必须与引擎一致）", i, got[i].Domain, engineOrder[i])
		}
	}
}
