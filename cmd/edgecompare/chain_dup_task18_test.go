//go:build edgeexp

package main

import (
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// Task 18：链上「同一因子出现多次」在**候选模型**下的口径钉子
// ============================================================================
//
// **背景（真机实测，见 task-18 报告 §1）**：出厂/实验配置的 `[edge_factors.custom]` 刻意
// 复制了内置六因子的同名条目（解析层把它们**小写化**），于是 `ssam-lib` 按**原始大小写**
// 建键 ⇒ 同一个因子产出**两条** `EdgeFactorResult`；`observeEdgeFactorChain` 把 ID 归一后
// 两条长得一模一样地落进链里。**真实数据里 24/33 条记录的两条逐字段完全相同，9/33 条的
// `EF-002FA` 一条 0.70（内置，`level4_override`）、一条 0.85（custom）。**
//
// **这一层为什么必须折叠**：`internal/edgefactor.Params` 的参数空间**是因子级的** ——
// `Factors`（`factorWeights` 按归一 ID 建 map）、`Vectors[id]`、`Coupling[i][j]` 全部按
// 因子 ID 建键；离线 CLI 的 `-factors` 也是因子级（`EF-002FA` 只有一个值）。把「条目级」
// 的观测喂进「因子级」的模型，等于让同一个 `a_i` 进入求和两次。
//
// **判据取「不变性」而不是硬编码分数**：把一条记录的链**折叠成每个因子一条**之后，任何候选
// 的离线分数都必须**逐位不变**。这条判据：
//
//	· 不需要维护魔数（改配置不会让它红）；
//	· 直接钉住「链上的冗余重复条目不得改变候选分数」这个语义；
//	· 在**真记录**上跑（仓内 `lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl`，
//	  Task 9 的 11 条 CT 记录，11/11 条同形态）。
//
// 折叠规则（与 `internal/edgefactor.CollapseToFactors` 的文档化规则一致，此处**独立实现**，
// 免得不变量自证）：每因子一条，保留**最强观测惩罚**（归一后 `EffectiveFactor` 最小），
// 并列取先出现的那条。
func TestChainDuplicateEntriesDoNotChangeCandidateScore(t *testing.T) {
	recs, err := LoadRecords("../../lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("记录文件为空")
	}
	factors := map[string]float64{
		"EF-002FA": 0.70, "EF-SYNCOOKIE": 0.75, "EF-SELINUX": 0.80, "EF-APPARMOR": 0.82,
		"EF-NO-SIEM": 0.90, "EF-NO-IDS": 0.88, "EF-3FA": 0.82,
	}
	weights := map[string]float64{
		"attack_surface": 35, "business_continuity": 25, "operation_trust": 25,
		"resilience": 15, "kernel_security": 10,
	}

	checked := 0
	// **只对 V/G/C**：legacy（M0）走的是**逐条目相乘**的历史路径，链上的重复对它是**载荷**
	// 而不是冗余（见 TestLegacyCandidateConsumesEveryChainEntry 的反向钉子）。这正是修复
	// 必须落在「条目→因子的换算层」而不是「链」或「legacy 结果列表」上的原因。
	for _, name := range []string{"vector", "graph", "chain"} {
		p, err := loadCandidateParams(candidateRef{name: name, path: "../../configs/edgeexp/" + candidateConfigFile(name)})
		if err != nil {
			t.Fatalf("候选 %s: %v", name, err)
		}
		p.Factors = map[string]float64{}
		for id, f := range factors {
			p.Factors[id] = f
		}
		for _, rec := range recs {
			if !hasDuplicateFactor(rec) {
				continue
			}
			dupScore, err := OfflineScoreWithWeights(p, rec, weights)
			if err != nil {
				t.Fatalf("候选 %s / %s 原记录: %v", name, rec.ScenarioID, err)
			}
			onceScore, err := OfflineScoreWithWeights(p, collapseRecordChain(rec), weights)
			if err != nil {
				t.Fatalf("候选 %s / %s 折叠记录: %v", name, rec.ScenarioID, err)
			}
			if dupScore != onceScore {
				t.Errorf("候选 %s / %s：链上的同一因子重复条目**改变了候选分数**（%.4f → 折叠后 %.4f）—— "+
					"合成层把「条目级观测」当成了「因子级输入」：主效应按条目多次累加、耦合项按条目对多次累加。"+
					"折叠必须发生在**条目→因子的换算层**（`internal/edgefactor.CollapseToFactors`），"+
					"不得在求和处打补丁，也不得改动链本身",
					name, rec.ScenarioID, dupScore, onceScore)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("没有任何记录被这个用例覆盖到 —— 夹具与真实形态脱节，判据形同虚设")
	}
	t.Logf("覆盖 %d 组（候选 × 含重复条目的记录），折叠前后分数逐位相同", checked)
}

// TestLegacyCandidateConsumesEveryChainEntry 是上一条的**反向钉子**：M0（legacy）候选的离线
// 分数**必须**依赖链上的每一条条目 —— 因为在线引擎的默认路径就是**逐条目相乘**
// （`ConfigToEdgeFactors` 刻意不去重，见 `adapter.go` 的注释与设计文档 §5.4.3），而 M0 的
// 语义是「与历史评分逐位一致」（性质 P4）。
//
// 为什么必须有这条反向钉子：修复「同一因子被合成层计两次」时，最诱人也最错的两种改法是
//
//	① 把链去重（改记录）——实验自己产出的数据集会被读取层/门禁判死，门禁⓪ 也失去观测对象；
//	② 把 `engineEdgeFactors` 去重（改 legacy 的因子结果列表）——M0 与在线引擎不再逐位一致。
//
// 这条用例把「链上的重复对 legacy 是载荷」钉成事实：谁做了 ① 或 ②，它立刻变红。
func TestLegacyCandidateConsumesEveryChainEntry(t *testing.T) {
	recs, err := LoadRecords("../../lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadCandidateParams(candidateRef{name: "legacy", path: "../../configs/edgeexp/m0-baseline.ini"})
	if err != nil {
		t.Fatal(err)
	}
	p.Factors = map[string]float64{
		"EF-002FA": 0.70, "EF-SYNCOOKIE": 0.75, "EF-SELINUX": 0.80, "EF-APPARMOR": 0.82,
		"EF-NO-SIEM": 0.90, "EF-NO-IDS": 0.88, "EF-3FA": 0.82,
	}
	weights := map[string]float64{
		"attack_surface": 35, "business_continuity": 25, "operation_trust": 25,
		"resilience": 15, "kernel_security": 10,
	}
	covered := 0
	for _, rec := range recs {
		if !hasDuplicateFactor(rec) {
			continue
		}
		covered++
		dup, err := OfflineScoreWithWeights(p, rec, weights)
		if err != nil {
			t.Fatal(err)
		}
		once, err := OfflineScoreWithWeights(p, collapseRecordChain(rec), weights)
		if err != nil {
			t.Fatal(err)
		}
		if dup == once {
			t.Errorf("%s：把链折叠成每因子一条之后 **legacy 候选的分数没有变化**（%v）—— "+
				"说明链上的重复条目没有被 legacy 路径消费。那是**误修**：M0 的语义是"+
				"「与历史/在线评分逐位一致」，而在线引擎对同名条目**逐条相乘**（P4）。"+
				"修复必须只落在 V/G/C 的『条目→因子』换算层，不得改链、也不得改 engineEdgeFactors",
				rec.ScenarioID, dup)
		}
	}
	if covered == 0 {
		t.Fatal("没有覆盖到任何含重复条目的记录")
	}
	t.Logf("覆盖 %d 条含重复条目的记录：legacy 候选**确实**消费了每一条链条目（P4 载荷）", covered)
}

// TestActivationsCollapseFrameDuplicateFactorIDs 钉住**换算层的不变量**：合成层的输入项
// 每个规范因子 ID **至多一项**。
//
// 为什么这条必须单独钉（而不是只钉分数）：分数是不变量的**后果**，而"输入项里有重复 ID"
// 是**原因**。只有原因被钉住，将来新增消费点（例如新的拟合列、新的导出格式）才不会又把
// 条目级列表直接喂进因子级模型。两条离线换算路径（评分的 `activationsFromResults` 与
// 拟合/指标的 `activationsOf`）都必须满足它 —— 此前后者在 `fit.go:design()` 里被 map 覆盖
// **静默折叠**（last-wins），与评分侧的"不折叠"互相矛盾。
func TestActivationsCollapseFrameDuplicateFactorIDs(t *testing.T) {
	recs, err := LoadRecords("../../lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadCandidateParams(candidateRef{name: "graph", path: "../../configs/edgeexp/graph.ini"})
	if err != nil {
		t.Fatal(err)
	}
	p.Factors = map[string]float64{
		"EF-002FA": 0.70, "EF-SYNCOOKIE": 0.75, "EF-SELINUX": 0.80, "EF-APPARMOR": 0.82,
		"EF-NO-SIEM": 0.90, "EF-NO-IDS": 0.88, "EF-3FA": 0.82,
	}

	covered := 0
	for _, rec := range recs {
		if !hasDuplicateFactor(rec) {
			continue
		}
		covered++

		// 路径 ①：评分侧（记录 → 引擎结果 → 合成层输入）
		scoreActs := activationsFromResults(p, engineEdgeFactors(p, rec), chainTimestamps(rec))
		assertUniqueFactorIDs(t, "评分侧 activationsFromResults", rec.ScenarioID, scoreActs)

		// 路径 ②：拟合/指标侧（记录 → 合成层输入）
		metricActs := activationsOf(rec)
		assertUniqueFactorIDs(t, "拟合侧 activationsOf", rec.ScenarioID, metricActs)

		// 两条路径对**同一个因子**必须给出同一个观测值（否则拟合与评分不同口径）。
		scoreEff := map[string]float64{}
		for _, a := range scoreActs {
			scoreEff[a.FactorID] = a.EffectiveFactor
		}
		for _, a := range metricActs {
			if _, known := p.Factors[a.FactorID]; !known {
				continue
			}
			if got, ok := scoreEff[a.FactorID]; ok && got != a.EffectiveFactor {
				t.Errorf("%s：因子 %s 在评分侧的口径是 %v、拟合侧是 %v —— 同一份记录两条换算路径不同口径",
					rec.ScenarioID, a.FactorID, got, a.EffectiveFactor)
			}
		}
	}
	if covered == 0 {
		t.Fatal("没有覆盖到任何含重复条目的记录")
	}
	t.Logf("覆盖 %d 条含重复条目的记录：两条换算路径的输入项均无重复因子 ID", covered)
}

func assertUniqueFactorIDs(t *testing.T, path, scenario string, acts []edgefactor.FactorActivation) {
	t.Helper()
	seen := map[string]int{}
	for _, a := range acts {
		seen[a.FactorID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("%s（%s）：因子 %s 出现了 %d 次 —— 合成层的参数空间（Factors/Vectors/Coupling）"+
				"是**因子级**的，输入项必须每因子至多一项", path, scenario, id, n)
		}
	}
}

// hasDuplicateFactor 报告一条记录的链上是否有归一后重复的因子 ID。
func hasDuplicateFactor(rec Record) bool {
	seen := map[string]bool{}
	for _, c := range rec.Observed.EdgeFactorChain {
		id := edgefactor.NormalizeFactorID(c.Factor)
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// collapseRecordChain 按**文档化折叠规则**把一条记录的链折叠成每因子一条（独立实现）：
// 保留归一后 `EffectiveFactor` 最小的那条（最强观测惩罚），并列取先出现的那条。
//
// 注意 `c_trigger`：合成层对 `effective_factor` 会**再衰减一次**（spec §10.2 的已知口径），
// 故"最强惩罚"按 `EffectiveFactor(effective_factor, c_trigger)` 比较 —— 与实现同口径。
func collapseRecordChain(rec Record) Record {
	out := rec
	best := map[string]edgeexp.ChainObs{}
	var order []string
	for _, c := range rec.Observed.EdgeFactorChain {
		id := edgefactor.NormalizeFactorID(c.Factor)
		cur, ok := best[id]
		if !ok {
			best[id] = c
			order = append(order, id)
			continue
		}
		if penalisedEff(c) < penalisedEff(cur) {
			best[id] = c
		}
	}
	chain := make([]edgeexp.ChainObs, 0, len(order))
	for _, id := range order {
		chain = append(chain, best[id])
	}
	out.Observed.EdgeFactorChain = chain
	return out
}

func penalisedEff(c edgeexp.ChainObs) float64 {
	return edgefactor.EffectiveFactor(c.EffectiveFactor, c.CTrigger)
}

// candidateConfigFile 把候选名映射到它的实验模板文件名。
func candidateConfigFile(name string) string {
	if name == "legacy" {
		return "m0-baseline.ini"
	}
	return name + ".ini"
}
