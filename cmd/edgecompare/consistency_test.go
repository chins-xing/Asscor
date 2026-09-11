//go:build edgeexp

package main

import (
	"fmt"
	"testing"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// 离线 ↔ 在线一致性门禁（Task 10 mandate 口径 3）
// ============================================================================
//
// 门禁内容 —— 三条「同一」，缺一条门禁就是假的：
//
//	1. **同一实现**：离线重算不做任何自研公式，把观测装进 `edgefactor.Input` 后调用
//	   `edgefactor.Synthesize` —— 与在线评分同一个函数（onlinePathScore 是测试侧**独立
//	   重写**的接线镜像：它照在线装配期的三步自己走一遍，用来抓"离线把某一步走错了"）；
//	2. **同一域裁剪口径**：请求域 = `DefaultDomains ∩ λ`，参数按该域集合一致裁剪后再合成。
//	   不裁剪就会假红（缺 λ 的域直接报错）或假绿（未经裁剪地放宽校验），见
//	   TestConsistencyGatePrunesDomainsLikeTheOnlineAssembly；
//	3. **同一可信度换算口径**：记录里的 `effective_factor` 是 ssam-lib 策略层已经衰减过一次
//	   的值，离线必须复用装配层的换算 `EffectiveFactor(f, c)` 再衰减一次（合计 1−(1−f)·c²，
//	   spec §10.2 的既有口径），不得直接把记录里的值用掉。
//
// **前提（必须如实标注，这不是本任务要修的缺陷）**：
//
//	本门禁**只在可信度策略关闭（c = 1）时成立**。`EffectiveFactor(f, 1) = f`，两次衰减与在线
//	legacy 的单次衰减恒等；一旦 c ≠ 1，在线 legacy 路径（assessor 的 attenuate / 内仓默认的
//	逐次相乘）只衰减一次，而离线统一按装配层口径衰减两次，两者天然相差一次衰减（离线的 legacy
//	惩罚更重）。spec §10.2 已把这条记为「可信度被衰减两次」的已知口径问题，是否修正属独立决策；
//	Task 8–10 一律**复用**同一口径并在报告标注。TestConsistencyGateOnlyHoldsAtFullConfidence
//	把这件事钉成可执行的证据，而不是一句注释。
//
// 域覆盖：门禁走 `Evaluate`（带域覆盖校验的决策层入口）或显式校验，绝不用低阶原语
// `OfflineScore*` 静默按 0 聚合缺域记录 —— 后者会把"记录缺一个域"变成"总分被无理由压低"
// 且报告上看不出异常（Task 8 评审 I2）。

// onlineMirror 是**测试侧独立重写**的在线接线镜像（不调用生产代码的 offlinePlan/
// activationsOf，否则就成了拿生产代码验证生产代码）。它照在线装配期做三步：
//
//	① 取请求域 = DefaultDomains ∩ λ；
//	② 把参数裁剪到该域集合；
//	③ 把记录的因子链按装配层换算（EffectiveFactor(f, c)）装进 Input，调用 Synthesize，
//	   再把逐域修正后的域分按权重聚合。
//
// 与生产实现的差别只应是"代码写法"，不是"口径"；任何一处口径漂移都会被逐位比较抓住。
func onlineMirror(p edgefactor.Params, rec Record, weights map[string]float64) (float64, error) {
	requested := make([]string, 0, len(weights))
	for _, d := range edgefactor.DefaultDomains() {
		if _, ok := p.Lambda[d]; ok {
			requested = append(requested, d)
		}
	}
	if len(requested) == 0 {
		return 0, fmt.Errorf("onlineMirror: λ 未覆盖任何默认域")
	}
	keep := make(map[string]bool, len(requested))
	for _, d := range requested {
		keep[d] = true
	}
	pruned := edgefactor.Params{
		Model:              p.Model,
		PFloor:             p.PFloor,
		Lambda:             map[string]float64{},
		Vectors:            map[string]map[string]float64{},
		Coupling:           p.Coupling,
		ChainWindowSeconds: p.ChainWindowSeconds,
		Factors:            p.Factors,
	}
	for d := range keep {
		if l, ok := p.Lambda[d]; ok {
			pruned.Lambda[d] = l
		}
	}
	for id, vec := range p.Vectors {
		trimmed := map[string]float64{}
		for d := range keep {
			if v, ok := vec[d]; ok {
				trimmed[d] = v
			}
		}
		pruned.Vectors[id] = trimmed
	}

	var acts []edgefactor.FactorActivation
	for _, c := range rec.Observed.EdgeFactorChain {
		ts, _ := parseTS(c.TS)
		acts = append(acts, edgefactor.FactorActivation{
			FactorID:        normalizeFactorID(c.Factor),
			TriggerCheck:    c.TriggerCheck,
			CTrigger:        c.CTrigger,
			EffectiveFactor: edgefactor.EffectiveFactor(c.EffectiveFactor, c.CTrigger),
			TS:              ts,
		})
	}
	res, err := edgefactor.Synthesize(pruned, requested, edgefactor.Input{
		DomainScores: rec.Observed.DomainScores,
		Factors:      acts,
	})
	if err != nil {
		return 0, err
	}
	if p.Model == edgefactor.ModelLegacy {
		return weightedSum(rec.Observed.DomainScores, weights) * res.GlobalMultiplier, nil
	}
	merged := map[string]float64{}
	for d, s := range rec.Observed.DomainScores {
		merged[d] = s
	}
	for d, s := range res.DomainScores {
		merged[d] = s
	}
	return weightedSum(merged, weights), nil
}

// twoFactorChainJSONL 是门禁用的两条记录：同一条链里同时激活 A 与 B（graph 耦合项真的被算到），
// c_trigger = 1.0（门禁成立的前提），域分只给 attack_surface（与裁剪后的请求域一致）。
const twoFactorChainJSONL = `{"scenario_id":"CONS-R1","factors":["A","B"],"observed":{"domain_scores":{"attack_surface":80},"threshold":50,"edge_factor_chain":[{"factor":"A","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.6,"ts":"2026-09-08T10:00:00Z"},{"factor":"B","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.5,"ts":"2026-09-08T10:00:01Z"}]},"ground_truth":{"compromised":true,"time_to_compromise_s":100,"ttps_achieved":2,"nodes_affected":1,"block_effective":false}}
{"scenario_id":"CONS-R2","factors":["A"],"observed":{"domain_scores":{"attack_surface":30},"threshold":50,"edge_factor_chain":[{"factor":"A","trigger_check":"OT-005","c_trigger":1.0,"effective_factor":0.9,"ts":"2026-09-08T10:00:02Z"}]},"ground_truth":{"compromised":false,"time_to_compromise_s":0,"ttps_achieved":0,"nodes_affected":0,"block_effective":true}}
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

// TestConsistencyGateOfflineMatchesOnlineWiring 是门禁的主测试：同一份记录、同一套参数、
// 同一个权重表下，离线重算与在线接线镜像必须**逐位相同**（不是容差相等）。
func TestConsistencyGateOfflineMatchesOnlineWiring(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := consGraphParams()
	for _, rec := range recs {
		offline, err := OfflineScoreWithWeights(p, rec, consWeights())
		if err != nil {
			t.Fatalf("%s: OfflineScoreWithWeights: %v", rec.ScenarioID, err)
		}
		online, err := onlineMirror(p, rec, consWeights())
		if err != nil {
			t.Fatalf("%s: onlineMirror: %v", rec.ScenarioID, err)
		}
		if offline != online {
			t.Fatalf("%s: 离线 %v ≠ 在线 %v —— 两侧必须共用同一份 Synthesize 与同一裁剪口径",
				rec.ScenarioID, offline, online)
		}
		// 逐位可复现：同一 EvalContext 下重复重算不得抖出 1 ulp（Task 8 Fix round 1 的定序契约）。
		for i := 0; i < 100; i++ {
			again, err := OfflineScoreWithWeights(p, rec, consWeights())
			if err != nil {
				t.Fatalf("repeat %d: %v", i, err)
			}
			if again != offline {
				t.Fatalf("%s: 第 %d 次重算 = %v ≠ %v（聚合序不确定）", rec.ScenarioID, i, again, offline)
			}
		}
	}
}

// TestConsistencyGateCoversCouplingNotJustMainEffects：门禁必须真的走到耦合项上 ——
// 若把 ConsGraphParams 的耦合清零，分数必须变（否则上一条测试只在测主效应）。
func TestConsistencyGateCoversCouplingNotJustMainEffects(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	withCoupling, err := OfflineScoreWithWeights(consGraphParams(), recs[0], consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	noCoupling := consGraphParams()
	noCoupling.Coupling = nil
	plain, err := OfflineScoreWithWeights(noCoupling, recs[0], consWeights())
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights(无耦合): %v", err)
	}
	if withCoupling == plain {
		t.Fatalf("耦合清零后分数不变（%v）⇒ 门禁没有覆盖耦合路径", withCoupling)
	}
	if !(withCoupling < plain) {
		t.Errorf("耦合应加重惩罚：有耦合 %v 应 < 无耦合 %v", withCoupling, plain)
	}
}

// TestConsistencyGatePrunesDomainsLikeTheOnlineAssembly：裁剪口径必须是
// `DefaultDomains ∩ λ`。证据是**两条路径的对照**：按完整默认域直接调用 Synthesize 会被拒
// （缺 λ / 向量不覆盖），而离线路径（与在线同一裁剪）能算。
func TestConsistencyGatePrunesDomainsLikeTheOnlineAssembly(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := consGraphParams()
	// 不裁剪：请求域含没有 λ 的域 ⇒ Synthesize 必须拒绝。这条断言保证本测试真的在测裁剪，
	// 而不是"两条路径都恰好能算"。
	if _, err := edgefactor.Synthesize(p, edgefactor.DefaultDomains(), edgefactor.Input{
		DomainScores: recs[0].Observed.DomainScores,
		Factors:      modelActivations(p, recs[0]),
	}); err == nil {
		t.Fatal("未经裁剪的完整默认域调用本应被拒 —— 否则本测试测不到裁剪口径")
	}
	if _, err := OfflineScoreWithWeights(p, recs[0], consWeights()); err != nil {
		t.Fatalf("离线路径应自行裁剪到 DefaultDomains ∩ λ 并成功：%v", err)
	}
}

// TestConsistencyGateOnlyHoldsAtFullConfidence 是本门禁的**前提证据**（mandate 口径 3 明文要求）：
//
//   - c = 1.0：离线重算与在线观测/镜像逐位一致（门禁成立）；
//   - c ≠ 1（0.9）：离线（双衰减 1−(1−f)c²）与在线 legacy 单次衰减（记录里的
//     effective_factor 本就是衰减一次后的观测值）**必然不等** —— 门禁在该前提下不成立，
//     这是 spec §10.2 记录在案的已知口径问题，本任务复用而不修正。
func TestConsistencyGateOnlyHoldsAtFullConfidence(t *testing.T) {
	// ① c = 1.0：T9 夹具（c_trigger = 1.0）的离线 legacy 重算必须复现**在线观测总分**。
	for _, rec := range t9Records(t) {
		score, err := OfflineScoreWithWeights(t9LegacyCandidate(), rec, t9Weights())
		if err != nil {
			t.Fatalf("%s: %v", rec.ScenarioID, err)
		}
		if score != rec.Observed.FinalScore {
			t.Fatalf("%s: c=1 时离线 %v 必须逐位等于在线观测 %v", rec.ScenarioID, score, rec.Observed.FinalScore)
		}
	}

	// ② c = 0.9：同一条记录的离线重算与**在线观测总分**必须不同，且离线更重。
	// 观测 final_score 是 90 × 0.82（在线 legacy 单次衰减），离线是 90 × 0.838（双衰减）。
	// 两侧都按记录的两个域等权聚合，故差异只可能来自换算口径本身。
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	rec := recs[0]
	if rec.Observed.EdgeFactorChain[0].CTrigger == 1 {
		t.Fatal("夹具已变：这条记录本应是 c_trigger = 0.9")
	}
	weights := twoDomainWeights()
	offline, err := OfflineScoreWithWeights(legacyParams(), rec, weights)
	if err != nil {
		t.Fatalf("OfflineScoreWithWeights: %v", err)
	}
	observed := rec.Observed.FinalScore
	if offline == observed {
		t.Fatalf("c ≠ 1 时离线 %v 不该逐位等于在线观测 %v —— 若相等说明换算口径已经改了", offline, observed)
	}
	wantOffline := 90.0 * assemblyDecay(0.82, 0.9)
	if offline != wantOffline {
		t.Fatalf("离线 = %v, want %v（双衰减口径）", offline, wantOffline)
	}
	if observed >= offline {
		t.Fatalf("c ≠ 1 时在线（单次衰减）应比离线（双衰减）宽松：观测 %v 应 < 离线 %v", observed, offline)
	}
	// 低阶原语与等权入口在同一记录上口径一致（差的是权重表，不是换算）。
	if equalWeight, err := OfflineScore(legacyParams(), rec); err != nil {
		t.Fatalf("OfflineScore: %v", err)
	} else if equalWeight != (90.0+90.0)/5.0*assemblyDecay(0.82, 0.9) {
		t.Fatalf("等权入口 = %v，与显式权重入口的换算口径不一致", equalWeight)
	}
}

// TestConsistencyGateGoesThroughDomainCoverageCheck：门禁的域覆盖校验必须落在 `Evaluate`
// 层（带权重却无观测域分的记录直接拒绝），而不是让低阶原语静默按 0 聚合。
func TestConsistencyGateGoesThroughDomainCoverageCheck(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
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

// TestConsistencyGateHoldsAcrossWeightTables：同一 EvalContext 下换权重表只应改聚合口径，
// 两侧（离线入口与独立镜像）仍必须逐位相等。
func TestConsistencyGateHoldsAcrossWeightTables(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "cons.jsonl", twoFactorChainJSONL))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	p := consGraphParams()
	for _, w := range []map[string]float64{
		{"attack_surface": 1},
		{"attack_surface": 3},
	} {
		a, err := OfflineScoreWithWeights(p, recs[0], w)
		if err != nil {
			t.Fatalf("offline: %v", err)
		}
		b, err := onlineMirror(p, recs[0], w)
		if err != nil {
			t.Fatalf("mirror: %v", err)
		}
		if a != b {
			t.Errorf("权重 %v 下离线 %v ≠ 镜像 %v", w, a, b)
		}
	}
}

// TestConsistencyGateMirrorIsIndependent 是一条**反向守卫**：镜像若被改成转发调用生产入口，
// 本门禁就退化成同义反复（自己和自己比）。这里用一个两侧都会拒绝、但**报错来源不同**的输入
// 来证明两条路径确实各走各的代码：一旦镜像变成转发，两条错误就会逐字相同。
func TestConsistencyGateMirrorIsIndependent(t *testing.T) {
	bad := consGraphParams()
	bad.Lambda = map[string]float64{"made_up_domain": 1}
	_, mirrorErr := onlineMirror(bad, Record{}, consWeights())
	_, prodErr := OfflineScoreWithWeights(bad, Record{}, consWeights())
	if mirrorErr == nil || prodErr == nil {
		t.Fatalf("两侧都必须拒绝 λ 未覆盖任何默认域的参数：mirror=%v prod=%v", mirrorErr, prodErr)
	}
	if mirrorErr.Error() == prodErr.Error() {
		t.Errorf("镜像与生产入口报了同一条错误 %q —— 它们很可能已经不是独立实现", mirrorErr)
	}
}
