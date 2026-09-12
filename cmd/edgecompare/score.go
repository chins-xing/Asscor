//go:build edgeexp

package main

import (
	"fmt"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
	ssam "github.com/chins-xing/ssam"
)

// 离线重算的**评分层**：与部署引擎共用同一个评分公式与同一套因子注入方式（主控裁定 C1）。
//
// 为什么必须共用（评审实测结论）：此前离线用自己的 `weightedSum(域分) × 乘子` 与
// `observed.threshold` 比较，而引擎（internal/engine/ssam → ssam.SSAMV20Formula）的总分是
// `round2(0.5·base + 30·E + 20·T)`，`Acceptable = Total >= Threshold`。两者**不是同一个量**：
// 同一条记录（域分 62.5、threshold 60、因子 0.8）离线判 not acceptable、引擎判 acceptable，
// 于是里程碑 B 的漏判率/误阻断率根本不是部署行为。spec §2.1 把决策层定为主判据、
// §2.2 把离线重算定为唯一比较范式，两者都要求这里的分数**逐位等于**引擎总分。
//
// 因此本文件只做三件事：
//
//  1. 把 JSONL 的观测量装成 `ssam.SSAMV20Formula` 的四个入参（域分 / 权重 / 风险上下文 /
//     因子结果）；
//  2. 按候选模型**以在线相同的方式**注入合成层钩子
//     （V/G/C：恒等乘子 + 域级 P_d；legacy：零注册 = 内仓默认的逐次相乘路径）；
//  3. 调用 `ssam.SSAMV20Formula` 并把它的 `Total` 作为离线分数。
//
// 与在线路径的一致点逐条如下（每一条都对应一处曾经可能漂移的口径）：
//
//	域分        ：观测的 `domain_scores`（= 引擎输出的 DomainScores），按权重表的确定顺序
//	              装入切片；未参与聚合（权重 ≤ 0）的域不进入切片。
//	权重        ：**记录自带** `observed.effective_weights` 优先（键集 = 参与聚合的域），
//	              记录没带该字段时回退到 `-weights`（= 本字段被消费之前的行为），
//	              再看 recordWeights 的说明；两者都装成 []ssam.WeightConfig（引擎用 cfg.Weights）。
//	风险上下文  ：`observed.spc_score` / `observed.threat_coeff` → RiskContext{Exposure, Threat}
//	              （引擎用 output.SPCScore / output.ThreatCoeff；四层公式的 Intrinsic 层不入参）。
//	因子结果    ：`observed.edge_factor_chain[].effective_factor` 就是引擎侧
//	              `ApplyEdgeFactorsToChecksPolicy` 输出的 `EdgeFactorResult.Factor`
//	              （策略层按触发可信度衰减**一次**后的观测值），故这里**原样**装进
//	              `EdgeFactorResult.Factor`，绝不再衰减一次。
//	域级修正    ：V/G/C 走 `RegisterDomainAdjust`（Score_d' = Base_d·P_d），与在线同一入口；
//	              legacy 不注册任何钩子，走内仓默认的**逐次相乘**路径（与在线逐位一致）。
//
// 钩子是**进程级全局状态**（内仓设计如此），故每次重算都成对安装/拆除；
// 拆除用 `Register*(nil)`（恢复内仓默认），绝不注册"等价默认策略"——那会换掉默认路径的
// 算术顺序（IEEE754 乘法不满足结合律），在取整半格边界上产生可观测差异。

// synthesizePlan 是离线重算用的合成计划：**一致裁剪**后的参数集 + 请求域。
//
// 裁剪口径与在线装配期（`ssam.newSynthesizePlan`）相同，且两侧都调用
// `internal/edgefactor.RequestedDomains` / `PruneToDomains` —— 唯一实现（主控 I2）:
// 内仓 `Validate`/`Synthesize` 以**传入的域列表**为准，配置里出现请求域之外的 λ 或向量键
// 会被直接拒绝，而配置允许只声明部分 λ；故请求域 = `DefaultDomains ∩ λ`，参数裁剪到该域
// 集合上再合成。裁剪只用于**计算**（装载/指纹仍用完整参数，与在线一致）。
type synthesizePlan struct {
	params  edgefactor.Params
	domains []string
}

// offlinePlan 计算离线合成计划（与在线 `ssam.newSynthesizePlan` 同一口径、同一实现）。
//
// legacy 例外：legacy 不读 λ（惩罚完全由全局乘子表达），在线也不为它构造合成计划
// （显式 model=legacy 与"未配置"共用内仓默认的逐次相乘路径），故这里用完整的默认域列表
// 返回计划 —— 它只用于文档化口径，legacy 路径不会调用 `Synthesize`。
//
// V/G/C：一个 λ 都没覆盖到默认域 ⇒ 任何域都不会被修正，报错而不是静默返回"未修正"的分数
// （与在线装配期的 fail-fast 同款纪律：能装配出来的东西必须真的能算）。
func offlinePlan(p edgefactor.Params) (synthesizePlan, error) {
	if p.Model == edgefactor.ModelLegacy {
		return synthesizePlan{params: p, domains: edgefactor.DefaultDomains()}, nil
	}
	// 拒绝**非默认域**的 λ / 向量键（Task 8 评审 M6 的收口）。
	//
	// 为什么必须在这里拦：`PruneToDomains` 的文档化前提是"请求域已由 `Validate`（在完整参数上）
	// 保证是默认域的子集"，在线 `ssam.newSynthesizePlan` 正是这么做的；而离线此前直接裁剪，
	// 于是"λ/向量键写到了非默认域"（例如把 `operation_trust` 拼错）这类**在线永远装不上**的
	// 配置会被静默裁掉，离线照样给出一份看起来有效的报告 —— Task 10 的"离线↔在线一致"门禁
	// 在这类数据上根本无法归因（两侧一个报错、一个出数）。
	//
	// 这里复用渲染侧的 `validateDefaultDomainKeys`（Task 9 为导出路径写的同一条规则），
	// 而**不是**整份 `p.Validate(DefaultDomains())`：后者还要求"已声明的向量覆盖全部默认域"，
	// 那是在线装配期的额外约束，会把只声明部分向量分量的夹具一并拒掉 —— 那是另一种口径，
	// 不属于本条修复的范围。
	if err := validateDefaultDomainKeys(p); err != nil {
		return synthesizePlan{}, err
	}
	requested := edgefactor.RequestedDomains(p)
	if len(requested) == 0 {
		return synthesizePlan{}, fmt.Errorf(
			"edgecompare: model %s declares no lambda.<domain> for any default domain — it could never adjust a domain score",
			p.Model)
	}
	return synthesizePlan{params: edgefactor.PruneToDomains(p, requested), domains: requested}, nil
}

// OfflineScoreWithWeights 用**引擎的评分公式**重算总分（主控裁定 C1）。
//
// 返回值就是 `ssam.SSAMV20Formula(...).Total`：与在线评分同一个函数、同一套入参口径，
// 因而是同一个量 —— 决策层可以拿它直接与 `observed.threshold` 比较（引擎的
// `Acceptable = FinalScore >= Threshold`）。
//
// `weights` 是**回退表**：记录自带 `observed.effective_weights` 时以记录为准（spec §5.1
// 前提 2，见 `recordWeights`），否则用它 —— 后者与本字段被消费之前的行为逐位一致。
//
// 本函数是**低阶原语**：不做域覆盖校验（见 metrics.go:validateDomainsCovered 的说明）。
func OfflineScoreWithWeights(p edgefactor.Params, rec Record, weights map[string]float64) (float64, error) {
	res, err := offlineFormulaResult(p, rec, weights)
	if err != nil {
		return 0, err
	}
	return res.Total, nil
}

// OfflineScore 是 weights 取"等权"时的便捷入口（等权 = 全部默认域各 1 份）。
//
// 语义与 `SSAMV20Formula` 的加权平均一致：权重表里出现的域若在记录中缺失，会以 0 计入
// 并仍占一份权重。决策层入口 `Evaluate` 会对"有权重却无观测域分"的记录 fail-fast
// （`validateDomainsCovered`），故主判据路径不受该语义影响。
//
// 注意（spec §5.1 前提 2）：这里的等权表同样是**回退表** —— 记录自带 `effective_weights`
// 时以记录为准，等权只对"没带权重表的记录"生效。
func OfflineScore(p edgefactor.Params, rec Record) (float64, error) {
	weights := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		weights[d] = 1
	}
	return OfflineScoreWithWeights(p, rec, weights)
}

// offlineFormulaResult 返回引擎公式对同一条记录的**完整输出**（Total + 三层明细）。
//
// 单独暴露它的理由是可检验性：一致性门禁要断言的正是「离线算出的分数与总分 == 该公式对
// 同一输入的结果」，而 `.Total` 与 `.Layers` 都来自内仓函数的返回值，不存在"离线自己再
// 聚合一次"的中间步骤。
//
// 权重在这里**统一解析**（记录自带优先，见 recordWeights）：所有入口
// （`OfflineScore` / `OfflineScoreWithWeights` / `Evaluate`）都经过它，故"用哪张权重表"只有
// 一处判据，不会出现"某个入口按记录、另一个入口按 `-weights`"的分叉。
func offlineFormulaResult(p edgefactor.Params, rec Record, weights map[string]float64) (ssam.FinalScore, error) {
	weights = recordWeights(rec, weights)
	plan, err := offlinePlan(p)
	if err != nil {
		return ssam.FinalScore{}, err
	}
	results := engineEdgeFactors(p, rec)
	cleanup, err := installEngineHooks(p, plan, results, chainTimestamps(rec))
	if err != nil {
		return ssam.FinalScore{}, err
	}
	defer cleanup()

	return ssam.SSAMV20Formula(
		engineDomainScores(rec.Observed.DomainScores, weights),
		engineWeightConfigs(weights),
		ssam.RiskContext{Exposure: rec.Observed.SPCScore, Threat: rec.Observed.ThreatCoeff},
		results,
	), nil
}

// recordCarriesWeights 报告记录是否**自带**生效权重表（全仓唯一判据：`len(...) > 0`）。
//
// 单列一个函数是为了让"谁赢"（`recordWeights`）与"报告里怎么统计/点名权重来源"
// （`countWeightSources` / `resolvedWeightSource`）用**同一条**判据 —— 三处各写一遍
// `len(...) > 0` 迟早漂移。
func recordCarriesWeights(rec Record) bool { return len(rec.Observed.EffectiveWeights) > 0 }

// resolvedWeightSource 是诊断信息里对"这张权重表从哪来"的描述（判据同 recordCarriesWeights）。
func resolvedWeightSource(rec Record) string {
	if recordCarriesWeights(rec) {
		return "记录自带 observed.effective_weights"
	}
	return "-weights（记录未带生效权重，走回退）"
}

// recordWeights 决定本次重算用哪张权重表：**记录自带优先**（spec §5.1 前提 2），
// `fallback` 只是记录没有该字段时的回退。
//
// 为什么记录必须赢（而不是让 `-weights` 覆盖它）：记录里的那张表是引擎**归一化之后**的生效
// 权重 —— `DynamicScoringEngine` 会给 0 权重域填默认值再 `Normalize(100)`，故"配置权重 ≠
// 生效权重"，而**归一化不可逆**：只凭 `-weights` 复算不出引擎实际用的比例。工程实况就是
// 计划里那串 `-weights`（35/25/25/15/10，和 **110**）与引擎归一后的比例不同。
// 以 `-weights` 为准的后果是 round-trip 门禁（`|复算 − 记录| == 0`）在**合法记录**上变红，
// 看起来像数据缺陷；而 `validateDomainsCovered` 还会因为 `-weights` 里多一个部署没聚合的域
// 而报"缺域"。
//
// 回退分支（记录没带该字段）与它被消费之前的行为**逐位一致**：历史数据集与手写夹具里没有
// `effective_weights`，它们仍然完全按 `-weights` 复算。
//
// **回退表的域集必须是默认域的子集**（Fix round 1 / Minor 5，口径如实记录、本轮**不**放宽）：
// CLI 的 `parseWeights` 拒绝任何非默认域的权重键（"非默认域的权重键不会被合成层理解，
// 评估口径与参数口径会变成两套"）。故"多了一个加权域"的部署，其 `-weights` 只能写成默认域的
// 子集 —— 那个多出来的域由**记录自带的生效权重表**表达（它没有这条限制，键集就是引擎实际
// 聚合的域集）。这是"记录赢"的又一条现实理由。
//
// 存在性判据是 `len(...) > 0`，**不是**"JSON 里有没有这个键"：nil map 会序列化成
// `"effective_weights":null`（键在场、值为空），那是"未记录"的可见信号，见
// `internal/edgeexp.Observed.EffectiveWeights`。
func recordWeights(rec Record, fallback map[string]float64) map[string]float64 {
	if recordCarriesWeights(rec) {
		return rec.Observed.EffectiveWeights
	}
	return fallback
}

// engineEdgeFactors 把记录里观测到的因子链还原成引擎侧的因子结果列表。
//
// `Factor` 直接取 `effective_factor`：它是 ssam-lib 策略路径（`ApplyEdgeFactorsToChecksPolicy`）
// 按触发可信度衰减**一次**之后的观测值，也就是引擎侧 `EdgeFactorResult.Factor` 本身。
// 引擎的 legacy 路径（内仓默认的逐次相乘）乘的就是这个值，故离线必须原样使用 ——
// 再衰减一次（`EffectiveFactor(f, c)`）会让惩罚变轻、分数变高，离线相对于引擎变成**乐观**，
// 而里程碑 B 的决策层主判据全部来自离线重算（Task 8 评审 I2 记录在案的口径差，
// 由本轮 C1 按"与引擎逐位一致"的裁定消除）。
//
// 候选未建模的因子（归一后不在 `p.Factors` 里，例如只作级联入口、从不 Active 的 EF-3FA，
// 或配置改坏后的孤儿 ID）一律丢弃 —— 与在线消费者 `ssam.activationsFromResults` 同口径。
// 放进去的后果是 Vectors 查表落空并**静默**按"作用于全部域、强度 1"计入惩罚，
// 让一个未建模的因子凭空产生比配置更强的惩罚。
func engineEdgeFactors(p edgefactor.Params, rec Record) []ssam.EdgeFactorResult {
	out := make([]ssam.EdgeFactorResult, 0, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		id := edgefactor.NormalizeFactorID(c.Factor)
		if _, known := p.Factors[id]; !known {
			continue
		}
		out = append(out, ssam.EdgeFactorResult{
			ID:                id,
			Factor:            c.EffectiveFactor,
			Active:            true,
			TriggerConfidence: c.CTrigger,
		})
	}
	return out
}

// chainTimestamps 是 chain 模型唯一的时间来源（JSONL 的 `edge_factor_chain[].ts`）。
//
// 在线评分拿不到它：引擎侧的结果类型 `ssam.EdgeFactorResult` 没有时间字段，故 chain 在
// 在线路径上不可执行（装配期即 fail-fast，见 `ssam.newSynthesizePlan`），
// 由本工具的离线评估承担 —— 与 spec「离线重算为主」一致。
//
// 同一条链里同一因子出现多次时取**最后一个非零时间戳**：这在 chain 语义下本就是退化输入
// （同一因子的两次激活没有先后区分），读取层保证坏时间戳不会走到这里。
func chainTimestamps(rec Record) map[string]time.Time {
	out := make(map[string]time.Time, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		ts, _ := parseTS(c.TS) // 坏值已在 LoadRecords 处按行拒绝
		if ts.IsZero() {
			continue
		}
		out[edgefactor.NormalizeFactorID(c.Factor)] = ts
	}
	return out
}

// resetEngineHooks 把内仓的两个钩子恢复成默认（nil == 未注册 ⇒ 逐位一致的历史乘性路径）。
//
// 绝不能用「注册一个语义等价的默认策略」来代替它：内仓 ast.go 的 edgeFactorStrategyIsDefault
// 标记决定 applyEdgeFactorStrategyToBase 走「逐次相乘」还是「base×单次乘积」，
// 显式注册等价策略会换掉默认算术顺序，在取整半格边界上产生可观测差异（实测 50.31 → 50.32）。
func resetEngineHooks() {
	ssam.RegisterEdgeFactorStrategy(nil)
	ssam.RegisterDomainAdjust(nil)
}

// installEngineHooks 按候选模型安装合成层钩子，返回**必须 defer 的**拆除函数。
//
// 安装口径与在线装配期 `Engine.ApplyEdgeFactorModel` 逐条一致：
//
//   - **legacy（M0）**：零注册（钩子保持内仓默认），与"未配置"走同一条评分路径。
//   - **V/G/C**：
//     1. `RegisterEdgeFactorStrategy` 返回 `res.GlobalMultiplier` —— V/G/C 恒为 1，
//     用来**抵消**内仓默认的逐次相乘（惩罚完全由域级系数 P_d 表达，不能再乘一次）；
//     2. `RegisterDomainAdjust` 把域级修正 `Score_d' = Base_d·P_d` 应用到**域聚合之前**
//     （与在线同一入口、同一写法；不在计划内的域原样放行）。
//
// 与在线的一处**刻意差异**（如实标注）：在线在钩子内部调用 `Synthesize` 并吞掉错误
// （返回恒等乘子 / 原样域分），而离线在这里**先算一次并让错误向上传** ——
// 离线工具的全部意义是"如实报错，不造兜底"，链缺时间戳、向量漏域这类输入必须在重算处
// fail-fast，而不是悄悄产出一个"没被修正过"的分数。合成是纯函数，先算一次与在钩子里算
// 结果逐位相同（钩子捕获的是同一份 `res`，与它收到的 `factors` 同源）。
func installEngineHooks(p edgefactor.Params, plan synthesizePlan, results []ssam.EdgeFactorResult,
	ts map[string]time.Time) (func(), error) {

	// 每次重算都从默认状态出发：钩子是进程级全局态，上一次重算若因 panic 之外的路径
	// 留下注册（例如测试里手动注册过），不清掉就会污染本次评分。
	resetEngineHooks()
	if p.Model == edgefactor.ModelLegacy {
		return resetEngineHooks, nil
	}

	acts := activationsFromResults(p, results, ts)
	res, err := edgefactor.Synthesize(plan.params, plan.domains, edgefactor.Input{Factors: acts})
	if err != nil {
		return nil, err
	}

	ssam.RegisterEdgeFactorStrategy(func([]ssam.EdgeFactorResult) float64 {
		return res.GlobalMultiplier
	})
	ssam.RegisterDomainAdjust(func(scores []ssam.DomainScore, _ []ssam.EdgeFactorResult) []ssam.DomainScore {
		for i := range scores {
			pd, ok := res.P[scores[i].Domain]
			if !ok {
				// 未配置 λ 的域不参与修正（合成计划已保证至少有一个域参与）。
				continue
			}
			scores[i].Score *= pd
		}
		return scores
	})
	return resetEngineHooks, nil
}

// activationsFromResults 把引擎侧的因子结果换算成合成层的输入项，与在线
// `ssam.activationsFromResults` 同口径，外加一个**离线专有**的时间戳来源。
//
// 逐条对齐在线（任何一处漂移都会让 V/G/C 的惩罚与在线不同）：
//   - 未激活项不得进入输入（未激活因子 Factor 为 0，会命中 `Synthesize` 里"沿用配置权重"
//     的哨兵，让一个根本没触发的因子按配置权重计入惩罚）；
//   - ID 归一后再查 `p.Factors`，查不到即丢弃；
//   - `EffectiveFactor(r.Factor, r.TriggerConfidence)` —— 对**已衰减一次**的观测值再衰减一次，
//     合计 `1−(1−f)·c²`（spec §10.2 记录的既有口径，本工具复用而不修正）；
//   - `TriggerCheck` 仅用于溯源，`Synthesize` 不消费，故不填。
func activationsFromResults(p edgefactor.Params, results []ssam.EdgeFactorResult,
	ts map[string]time.Time) []edgefactor.FactorActivation {

	out := make([]edgefactor.FactorActivation, 0, len(results))
	for _, r := range results {
		if !r.Active {
			continue
		}
		id := edgefactor.NormalizeFactorID(r.ID)
		if _, known := p.Factors[id]; !known {
			continue
		}
		out = append(out, edgefactor.FactorActivation{
			FactorID:        id,
			CTrigger:        r.TriggerConfidence,
			EffectiveFactor: edgefactor.EffectiveFactor(r.Factor, r.TriggerConfidence),
			TS:              ts[id],
		})
	}
	return out
}

// engineDomainScores 把观测域分装成 `SSAMV20Formula` 的域分切片。
//
// 顺序取 `orderedDomains(weights)`（**域名字典序** = 引擎 `ComputeDomainScoresBayes` 输出切片
// 的顺序）：公式按切片顺序累加 `sum += ds.Score * w`，顺序漂移会在末位抖出 1 ulp，让"逐位一致"
// 变成偶然（Task 3B Step 2 之前这里按 `DefaultDomains` 顺序装，与引擎不同序）。
//
// 只装入**权重 > 0** 的域（公式对 w ≤ 0 的域本来就会跳过），未参与聚合的域不占分母 ——
// 与内仓公式的 `if w, ok := wMap[ds.Domain]; ok && w > 0` 逐字同义。
func engineDomainScores(scores, weights map[string]float64) []ssam.DomainScore {
	out := make([]ssam.DomainScore, 0, len(weights))
	for _, d := range orderedDomains(weights) {
		if weights[d] <= 0 {
			continue
		}
		out = append(out, ssam.DomainScore{Domain: d, Score: scores[d]})
	}
	return out
}

// engineWeightConfigs 把权重表装成引擎的 []WeightConfig（引擎侧来自 cfg.Weights）。
// 定序只为可复现；内仓用 BuildWeightMap 建映射后按域分切片顺序消费，权重侧的次序无语义。
func engineWeightConfigs(weights map[string]float64) []ssam.WeightConfig {
	out := make([]ssam.WeightConfig, 0, len(weights))
	for _, d := range orderedDomains(weights) {
		out = append(out, ssam.WeightConfig{Domain: d, Weight: weights[d]})
	}
	return out
}
