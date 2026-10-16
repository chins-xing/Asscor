package edgefactor

import "sort"

// CollapseToFactors 把**条目级**的因子激活列表折叠成**因子级**：每个规范因子 ID 至多保留一项。
//
// # 为什么必须有这一步（真机实测的根因，Task 18）
//
// 出厂/实验配置（`configs/*.ini`、`configs/edgeexp/*.ini` 的 `[edge_factors.custom]`）
// **刻意**把内置六因子的同名条目又写了一遍 —— 门禁⓪ 要观测的正是"引擎会不会对同一因子乘两次"，
// 所以那些条目**不得删**（设计文档 §5.4.3 第 2 条）；`ConfigToEdgeFactors` 也**刻意不去重**
// （去重会改变出厂乘子，违反 P4「显式 legacy 与历史评分逐位一致」）。
// 配置键在解析层被**小写化**，而 `ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy` 用
// **原始 ID（含大小写）** 建键 ⇒ 同一个逻辑因子产出**两条** `EdgeFactorResult`；
// 观测层 `observeEdgeFactorChain` 再把 ID 归一 ⇒ 链上出现"同一因子两条、字段可能完全相同"
// 的条目。**实测**：33 条真机记录里 24 条的两条目逐字段相同，9 条的 `EF-002FA` 一条 0.70
// （内置，`level4_override`）、一条 0.85（custom）。
//
// **链上的重复是如实观测，不得消除**（`internal/edgeexp` 的读取层契约与里程碑 B 计划书都
// 明文禁止任何消费方按因子 ID 去重 —— 记录里的链是**列表**，且 M0/legacy 的在线评分正是
// **逐条目相乘**，重复对它是载荷而非冗余）。但**合成层的参数空间是因子级的**：
// `Params.Factors`（`factorWeights` 按归一 ID 建 map、同名时内置胜出）、`Params.Vectors[id]`、
// `Params.Coupling[i][j]`、离线 CLI 的 `-factors` 全部只认因子 ID。
// 把条目级观测喂进因子级模型 ⇒
//
//   - 主效应项 `Σ_{i∈A} a_i[d]` 对同一因子累加 **n_i** 次（实测 n_i = 2 ⇒ 恰好 2 倍）；
//   - 耦合项 `Σ c_ij·a_i·a_j` 按**条目对**累加（`Synthesize` 的耦合循环只跳过
//     `from.id == to.id`）⇒ 同一对因子被计 **n_i·n_j** 次（实测 2×2 ⇒ **4 倍**）。
//
// 2 : 4 的比例畸变**无法被 λ 重新标定吸收**（λ 只出现在 `exp(−λ_d·L_d)`，只能吸收统一倍数），
// 而 `Σc_ij a_i a_j / Σa_i` 恰恰是 G/C 候选要估计的对象。故本函数在**条目 → 因子**的换算层
// 折叠，而不是在求和处打补丁、也不是改动链或配置。
//
// # 折叠规则（为什么是这一条）
//
// **每因子保留一项：`EffectiveFactor` 最小（= 最强观测惩罚）的那一项；并列时取先出现的那一项。**
//
//  1. 对"两条目逐字段相同"的记录（真机 24/33 条），折叠**不是选择而是唯一读法** ——
//     §3.1 的 `a_i = (1 − effective_f_i)·v_i` 里 `effective_f_i` 只有一个值，折叠必须给出
//     **该值本身**。这条排除了任何"跨条目再做一次算术"的规则（例如取乘积 `f²`）：那会在
//     **毫无争议**的那 24 条记录上改分，凭空发明设计文档里没有的第三种语义。
//  2. 冲突情形（内置 0.70 vs custom 0.85）取**最强惩罚**，它与**模型自己已有的因子级裁定
//     同值**：`factorWeights` 明写"与内置六因子同名的自定义项不覆盖内置权重 ⇒
//     `[edge_factors]` 是内置因子的单一事实来源"，即 `Params.Factors["EF-002FA"] = 0.70`。
//  3. **单调**：观测到更强的失败证据时，因子的建模惩罚只会更强、不会更弱（性质 P2 的方向）。
//  4. **最小**：每个因子只出现一次时（无重复的历史数据集与手写夹具），本函数**逐位返回原值**。
//
// # 口径与副作用
//
//   - `FactorID` 会被归一（`NormalizeFactorID`）：折叠按**规范 ID** 进行，故调用方即使传入
//     未归一的 ID（例如解析层小写化过的自定义因子）也会被正确合并；输出恒为规范 ID。
//   - 输出按 `FactorID` **升序**，保证同输入同输出（`Synthesize` 内部也按 ID 排序，但它的
//     排序不稳定，重复 ID 的先后在此之前是未定义的）。
//   - 被丢弃条目的 `CTrigger` / `TS` / `TriggerCheck` 随之丢弃：保留项的字段**原样**带走，
//     本函数**不做任何算术合成**（不平均、不相乘、不取最大值以外的组合）。
//   - `EffectiveFactor == 0`（`Synthesize` 的"未提供"哨兵）按最小处理 —— 它的语义是
//     "回落到配置权重"，即该因子**没有更弱的观测**，保留它是对的。
func CollapseToFactors(acts []FactorActivation) []FactorActivation {
	if len(acts) == 0 {
		return acts
	}
	idx := make(map[string]int, len(acts))
	out := make([]FactorActivation, 0, len(acts))
	for _, a := range acts {
		a.FactorID = NormalizeFactorID(a.FactorID)
		at, ok := idx[a.FactorID]
		if !ok {
			idx[a.FactorID] = len(out)
			out = append(out, a)
			continue
		}
		// 严格小于才替换 ⇒ 并列时保留**先出现**的那一项（确定性，不看输入顺序的偶然）。
		if a.EffectiveFactor < out[at].EffectiveFactor {
			out[at] = a
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FactorID < out[j].FactorID })
	return out
}
