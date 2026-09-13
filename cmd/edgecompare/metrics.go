//go:build edgeexp

package main

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 重算层 + 三层指标（spec §2.1 / §5.2 第 2–3 步）。
//
// 对比范式是「离线重算为主」：真实攻防实验只记录**原始观测与客观结果**，四候选
// （legacy / vector / graph / chain）在同一份真实数据上用 `internal/edgefactor` 的
// **同一份 Synthesize** 重算分数与决策。评分本身（含总分公式）在 `score.go`：
// 离线分数 == `ssam.SSAMV20Formula` 的总分（主控裁定 C1），本文件只负责把 JSONL 的观测
// 装进合成层、按在线口径裁剪域、再按 spec §2.1 的三层指标汇总。
//
// 三层指标（定义处见 Evaluate / severityOf / auc）：
//
//	决策层（主判据）：DecisionAgreement / FalseNegativeRate / FalsePositiveRate
//	排序层（辅助）  ：Spearman / Kendall（模型分数 vs 客观严重度）
//	数值层（辅助）  ：AUC（以 100−score 为危险度，compromised 为正类）
//
// **判定口径（C1 报告头要求，必须与在线一致）**：离线分数 = 引擎总分（同一公式
// `SSAMV20Formula`），阈值 = 引擎决策线（`Acceptable = Total >= threshold`）。

type Metrics struct {
	DecisionAgreement float64 `json:"decision_agreement"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	Spearman          float64 `json:"spearman"`
	Kendall           float64 `json:"kendall"`
	AUC               float64 `json:"auc"`
	N                 int     `json:"n"`

	// Basis 是本次评估**实际吃进决策层**的记录按依据的计数（Task 4D Step 4）。
	//
	// 为什么它必须进指标本体（而不只是报告头的一段话）：`N` 是分母，而 `N` 会因为
	// "过滤掉了侦察口径的记录"而变小 —— 不写清过滤前后各多少，同一份报告在不同过滤设置下
	// 字面完全一样，而它们的漏判率/误阻断率不可比。缺省口径下这个 map 只会有一个键
	// （`targeted_ttp`）；`--allow-mixed-basis` 时才可能有两个。
	Basis map[string]int `json:"basis"`
	// BasisSkipped 是被**过滤掉**（不参与决策层指标）的记录数，按依据计数。
	//
	// 缺省口径下**非空是常态**：侦察口径（`recon_playbook`）的记录是背景测量，一律被丢出决策层
	// 指标（`--allow-mixed-basis` 才让它们参与计算）；缺依据的记录在缺省口径下**报错**而不是被
	// 静默丢样本（只有打开逃生开关时才会以 `(未声明)` 记在这里）。
	BasisSkipped map[string]int `json:"basis_skipped,omitempty"`
	// RecordsTotal 是**过滤前**的记录总数（= `N + Σ BasisSkipped`）。
	RecordsTotal int `json:"records_total"`
	// BasisAssumed 是本次按 `--assume-basis` **补的依据**覆盖了多少条记录（0 = 全部记录自带依据）。
	//
	// 为什么必须报出来：那些记录在数据里**没有** basis，是"这次评估假设它们是什么口径"；
	// 不写这个数，报告里就分不清"这批数据本来就是目标 TTP 口径"与"我们假设它是"。
	BasisAssumed int `json:"basis_assumed,omitempty"`
}

// activationsOf 把 JSONL 的因子链换算成合成层的输入项（Task 10 的拟合也用它）。
//
// 这里就是 mandate 口径 2 的落点：**复用在线装配层 `ActivationFromResult` 的换算**——
// 对记录里已经过 ssam-lib 策略层衰减一次的 `effective_factor` 再衰减一次
// （`EffectiveFactor(value, c_trigger)`），合计 `1−(1−f)·c²`。spec §10.2 把这条口径记为
// 「可信度被衰减两次」的已知问题，并要求 Task 8–10 的离线重算**复用**它、在标定报告中标注，
// 而不是在此处修正（修正会改变评分，属独立决策）。
//
// **这条换算只属于 V/G/C 的合成层**：`score.go:activationsFromResults` 用它把"已衰减一次"
// 的观测值再衰减一次（与在线 `ssam.activationsFromResults` 同口径）。legacy 走的是另一条路
// —— 引擎的默认策略直接乘 `EdgeFactorResult.Factor`（= 记录里的 `effective_factor`，
// 单次衰减），故 legacy 的重算**不得**经过本函数（C1 裁定后由 `engineEdgeFactors` 承担）。
//
// 本函数同时供拟合器（fit.go 的设计矩阵）使用：拟合的列口径是
// `a_i = (1−eff_i)·Σ_d v_i[d]`，其中 eff_i 就是装配层换算后的值。
//
// 因子 ID 一并做**消费侧**归一（唯一实现：`internal/edgefactor.NormalizeFactorID`）：
// 合成层的 Vectors / Factors / Coupling 三处查表都以规范大写键进行，不归一会查表落空并
// 静默回落到"全强度"默认向量。
func activationsOf(rec Record) []edgefactor.FactorActivation {
	out := make([]edgefactor.FactorActivation, 0, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		ts, _ := parseTS(c.TS) // 坏值已在 LoadRecords 处按行拒绝
		out = append(out, edgefactor.FactorActivation{
			FactorID:        edgefactor.NormalizeFactorID(c.Factor),
			TriggerCheck:    c.TriggerCheck,
			CTrigger:        c.CTrigger,
			EffectiveFactor: edgefactor.EffectiveFactor(c.EffectiveFactor, c.CTrigger),
			TS:              ts,
		})
	}
	return out
}

// modelActivations 在 activationsOf 之上丢弃**候选模型未建模**的因子。
//
// 口径与在线消费者 `ssam.activationsFromResults` 一致（Task 7 评审的接线要求）：归一后的 ID
// 必须能在 Params.Factors 里查到，查不到说明该因子不在这个候选模型的因子集合里（例如只作
// 级联入口、从不 Active 的 EF-3FA，或配置改坏后的孤儿 ID）。放它进去会让 Params.Vectors
// 查表落空并**静默**按"作用于全部域、强度 1"计入惩罚——一个未建模的因子凭空产生比配置
// 更强的惩罚。
//
// 代价（须在报告中如实标注）：候选模型漏配一个真实激活的因子时，离线不会报错，而是"该因子
// 不产生惩罚"。这不是静默失效的隐蔽路径——它的后果直接体现在决策层指标上（漏判率偏高），
// 也正是四个候选要比出来的东西。
func modelActivations(p edgefactor.Params, rec Record) []edgefactor.FactorActivation {
	acts := activationsOf(rec)
	out := make([]edgefactor.FactorActivation, 0, len(acts))
	for _, a := range acts {
		if _, known := p.Factors[a.FactorID]; !known {
			continue
		}
		out = append(out, a)
	}
	return out
}

// orderedDomains 返回权重键的确定顺序：**域名字典序**（与引擎装切片时的顺序一致）。
//
// 确定性契约（本方向的核心门禁「离线重算 ↔ 在线评分逐位一致」依赖它）：**同一输入必须给出
// 逐位相同的结果**。Go 的 map 迭代序是随机的，直接 `range` 会让域分切片在末位抖动 1 ulp ——
// 门禁于是"偶然绿、偶然红"，这不是精度问题而是**不可复现**问题（同一份数据两次跑出不同判定
// 时，报告里的数字无法归因）。
//
// 顺序的消费者是 `score.go:engineDomainScores`：内仓 `SSAMV20Formula` 按域分切片顺序累加
// `sum += ds.Score * w`（加法交换律保证数学语义不变，定序只把浮点舍入路径钉死）。
//
// **为什么是字典序而不是 `DefaultDomains` 的顺序**（Task 3B Step 2）：在线侧喂给公式的域分
// 切片来自内仓 `ssam.ComputeDomainScoresBayes`，它对 activeDomains 做
// `sort.Slice(results[i].Domain < results[j].Domain)` ⇒ **字典序**。离线此前按
// `DefaultDomains`（`kernel_security` 在最后）装切片 ⇒ 两侧是两条不同的浮点累加路径。乘积项
// 不可精确表示时（小数域分/权重）末位会差 1 ulp，而**落在取整半格上的 base** 会因此让
// round2 差 0.01 —— spec §5.1 那组数（域分 82/75/68/71/55、权重 35/25/25/15/10、legacy 因子
// 0.82·0.838、E=0.93/T=1.4）的 base 正是 `round2(73.2727…×0.82×0.838) = 50.35`，总分
// raw = `8107.5 + 9.09e-13`（**离取整边界只有 1 ulp**，`Round(8107.5)=8108 ⇒ 81.08`，
// `8107.4999… ⇒ 81.07`）。门禁的红必须是**数据缺陷**的红，而不是"累加顺序碰巧不同"的红；
// 把顺序对齐到引擎，让"逐位一致"成为事实而不是巧合。
//
// 只返回**实际出现在 weights 里**的键，故不改变"哪些域参与聚合"的语义（权重 ≤ 0 的域仍由
// `engineDomainScores` 跳过）。
func orderedDomains(weights map[string]float64) []string {
	out := make([]string, 0, len(weights))
	for d := range weights {
		out = append(out, d)
	}
	// 先收集再排序：map 迭代序只影响收集顺序，不影响排序后的结果。
	sort.Strings(out)
	return out
}

// validateDomainsCovered 校验记录**覆盖了本次评估用到的每个域**（评审 I2 的另一半）。
//
// 为什么这条检查在 Evaluate 而不在读取层：读取层看不到"评估时用了哪些域"——域权重由
// `Evaluate` 解析（**记录自带优先**，`-weights` 只是回退，Task 3B Step 1），读取层只能保证
// `domain_scores` 非空（见 `internal/edgeexp.Record.Validate`，由 `load.go` 的
// `LoadRecords` 转发调用）。
// 缺域的危险是**静默压低**：引擎公式对缺失域取到 0，却仍把它那份额度计入分母（
// `engineDomainScores` 会为该域装入一个 0 分），于是总分被无理由拉低、`acceptable` 判定随之
// 翻转，而报告里看不出任何异常。
// 记录里的域分是评估的输入证据，缺一项就意味着这份记录不能配这张权重表 —— 直接拒绝。
func validateDomainsCovered(rec Record, weights map[string]float64) error {
	for _, d := range orderedDomains(weights) {
		if weights[d] <= 0 {
			continue
		}
		if _, ok := rec.Observed.DomainScores[d]; !ok {
			return fmt.Errorf(
				"edgecompare: scenario %s: domain %q has weight %v but no observed domain score — 缺失域会被当成 0 参与聚合（仍占一份权重），静默压低总分并扭曲决策层指标",
				rec.ScenarioID, d, weights[d])
		}
	}
	return nil
}

// validateWeightsUsable 拒绝**解析后**仍然没有任何正权重的表（Task 3B Fix round 1 / Minor 1）。
//
// 为什么要在 `Evaluate` 里再查一次：CLI 的 `-weights` 守卫（`main.go:parseWeights` 的"全零"分支）
// 挡的是**命令行输入**；Task 3B 之后权重还可以来自**记录本身** —— 一条
// `{"effective_weights":{"attack_surface":0}}` 的记录会绕过那道守卫、**赢过**合法的 `-weights`，
// 然后产出一份"齐全、可信"的报告：聚合分母恒 0 ⇒ 引擎公式对每条记录都返回 Total=0 ⇒
// 判定全是 not acceptable，决策层指标退化成"全阻断"，而报告上看不出任何异常。
//
// 判据与 CLI 同款：**存在 > 0 的权重**（空表 / 全零 / 全负一律拒绝）。诊断信息点名**权重来源**
// （记录自带 vs 回退）—— 同一句话在两种来源下的修法完全不同。
func validateWeightsUsable(rec Record, weights map[string]float64) error {
	for _, w := range weights {
		if w > 0 {
			return nil
		}
	}
	return fmt.Errorf("edgecompare: scenario %s: 生效权重表（%s）没有任何正权重 —— 聚合分母恒为 0，"+
		"引擎公式对每条记录都返回 Total=0、判定退化为『全阻断』，而报告照常打印（看起来比过了）",
		rec.ScenarioID, resolvedWeightSource(rec))
}

// countWeightSources 统计本次评估里权重表的来源分布（Task 3B Fix round 1 / Important 1）。
//
// 判据与"谁赢"同源（`recordCarriesWeights`），故报告里写的口径就是实际用的口径。
func countWeightSources(records []Record) WeightSourceCounts {
	var c WeightSourceCounts
	for _, rec := range records {
		if recordCarriesWeights(rec) {
			c.RecordCarried++
			continue
		}
		c.Fallback++
	}
	return c
}

// EvaluateOptions 承载"本次评估的显式覆盖项"。零值 = 一切按记录本体走（既有行为逐位不变）。
//
// 目前只有一个字段：阈值覆盖。它存在的唯一理由是**敏感性分析** —— spec §5.4 要求"若部署判定线
// 下两类样本为空，必须另附一行 threshold = 60.0 的敏感性结果"，而在此之前该要求无法执行：
// 阈值来自记录本体（`observed.threshold`），工具没有覆盖入口，操作者只能手改 JSONL 副本，
// 而手改过的数据集**与原始数据不再逐字节可复现**。有了这个字段，"敏感性行"可以用一条命令、
// 同一份数据复现，且覆盖值会写进报告头（`Report.ThresholdOverride`），读者一眼能看出
// "这一行不是部署的判定线"。
//
// **不得用于选模的默认路径**：选模必须用部署的真实判定线（覆盖率与可复现性都指着它）。
// CLI 侧对此有明确说明（`-threshold` 的 flag 文案），报告头也会带上"敏感性分析覆盖值"字样。
type EvaluateOptions struct {
	// ThresholdOverride > 0 时替代**每条记录**的 `observed.threshold`；0 = 不覆盖（缺省）。
	ThresholdOverride float64

	// AllowMixedBasis 允许把 `recon_playbook` 口径的记录也吃进决策层指标（Task 4D Step 4）。
	//
	// **缺省是 false**，缺省口径下：**缺依据 ⇒ 报错**；**两类混在一起 ⇒ 侦察口径的记录被自动
	// 丢出**决策层/拟合（条数写进 `BasisSkipped` 与报告头），**不报错** —— 那批记录本来就不该
	// 参与决策层，用剩下那一类算就是了（Fix round 2 / Minor-1：此前这里的注释与 flag 文案都写成
	// "两类混在一起也报错"，与实现不符）。**打开本开关才是让两类都进** ⇒ 那时混装报错（混算的
	// 漏判率没有定义）。理由见 `applyBasisGuard`：旧数据集没有 `ground_truth.basis`，静默把它们
	// 算进决策层指标，等于把"目标 TTP 是否成功"与"任意 link 是否成功"两种标签混进同一个漏判率里，
	// 而报告上看不出任何异常。
	//
	// 打开它同时意味着**接受"缺依据的记录按旧口径（recon_playbook）理解"** —— 那正是这批历史
	// 数据的事实（里程碑 B 之前 `compromised` 由"任意 link 成功"算出来），而缺依据的计数仍会
	// 如实写进 `BasisSkipped["(未声明)"]`，不会被静默吞掉；它们同样**不进**决策层指标
	// （缺依据 ≠ 目标 TTP 口径），故"全缺席 + 本开关"会因为过滤后为空而 fail-fast。
	AllowMixedBasis bool

	// AssumeBasis 是给**没有 `basis` 的记录**补一个显式假设（`targeted_ttp` / `recon_playbook`）。
	//
	// 为什么需要它（而不是只有"报错"与"全局放宽"两个选项）：历史数据集确实没有这个字段，
	// 而"这批数据的 compromised 是旧口径（任意 link 成功）算出来的"是一个**可以如实声明**的事实。
	// `--allow-mixed-basis` 解决不了它 —— 那个开关只放开"两类混算"，缺依据的记录仍然被拒。
	//
	// **空串 = 不假设**（缺依据 ⇒ 报错）。取值只能是两个合法值之一（由 `applyBasisGuard` 校验）——
	// 一个拼错的假设会把整批记录标成错误的依据，而它与合法值在数据上完全同形。
	AssumeBasis string
}

// basisGuardOutcome 是 `applyBasisGuard` 的结果。
//
// 为什么把原来的五元组收成命名结构（Task 4D Fix round 2）：调用方现在有**两条路径**
// （决策层指标与拟合），而"参与/跳过/假设"这三个计数必须**逐字同源** —— 五元组在第二个
// 调用点手抄一遍位置，任何一处顺序错位都会静默把"跳过"读成"参与"。字段名即语义。
type basisGuardOutcome struct {
	// kept 是**参与决策层**的记录（已按依据过滤，顺序与输入一致）。
	kept []Record
	// determined 是**逐条判定**的依据分布：含被丢的（侦察口径）与按假设归类的。
	// 它的用途是审计"这批数据本来是什么口径" —— 不参与报告头的"参与 N 条（…）"。
	determined map[string]int
	// keptCounts 是**参与决策层那部分**的依据分布（生效依据：`--assume-basis` 归类的记录算在
	// 假设的那一类，而不是落在空串键上）。报告头与 `Metrics.Basis` 用的是它。
	keptCounts map[string]int
	// skipped 是被丢出决策层指标的条数（按依据计数）。
	skipped map[string]int
	// assumed 是按 `--assume-basis` 补的依据覆盖了多少条。
	assumed int
}

// applyBasisGuard 是**决策层标签的依据守卫**（Task 4D Step 4，用户裁定的 L2）。
//
// **两条路径共用**（Task 4D Fix round 2 / Important-1）：候选对比（`EvaluateWith` → `CompareWith`）
// 与参数拟合（`Fit`）都从这里过。上一轮只在对比路径上接了守卫，而拟合的标签向量正是
// `ground_truth.compromised` ⇒ 混类/缺依据的记录照样进拟合，且 `--allow-mixed-basis` /
// `--assume-basis` 在拟合路径上**被静默忽略**（既不生效也不报错）。守卫是"这批数据的标签能不能
// 放在一起算"的前置问题，与"用这些标签算指标还是拟合系数"无关。
//
// 判据（缺省口径）：
//  1. 每条参与决策层的记录都必须**显式声明** `ground_truth.basis`（缺 ⇒ 报错并给出计数）；
//  2. 依据只能取 `targeted_ttp` / `recon_playbook`（走 `edgeexp.Validate` 的值域校验，这里不重抄）；
//  3. **两类混在一起**：缺省口径下侦察口径的记录被**自动丢出**决策层指标（条数记进
//     `skipped`）；打开 `AllowMixedBasis` 让两类**都进**时才是真矛盾 ⇒ 报错（混算的漏判率没有定义）。
//
// `opts.AllowMixedBasis` 是**显式逃生开关**（敏感性/历史对比用）：它让侦察口径的记录参与计算，
// 并把"缺依据"的记录按**旧口径**（`recon_playbook`）理解 —— 那是这批历史数据的事实（里程碑 B 之前
// `compromised` 由"任意 link 成功"算出），而不是一句方便的假设。缺依据/被丢的条数会如实写进
// 指标本体（`BasisSkipped` / `RecordsTotal` / `BasisAssumed`），报告头必须打印出来。
func applyBasisGuard(records []Record, opts EvaluateOptions) (basisGuardOutcome, error) {
	if a := strings.TrimSpace(opts.AssumeBasis); a != "" &&
		a != edgeexp.BasisTargetedTTP && a != edgeexp.BasisReconPlaybook {
		return basisGuardOutcome{}, fmt.Errorf("edgecompare: --assume-basis 的取值 %q 不是已知依据（只认 %q / %q）—— "+
			"拼错的假设会把整批记录标成错误的依据，而它与合法值在数据上完全同形",
			opts.AssumeBasis, edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook)
	}
	assume := strings.TrimSpace(opts.AssumeBasis)

	// 第一步：**逐条判依据**（"这条记录的标签是什么口径"），并**先过滤后判混类** ——
	// 顺序不能反：`targeted_ttp` 与 `recon_playbook` 同时存在时，侦察口径的记录本来就**不进**
	// 决策层指标（它们是背景测量），于是"混类"不是问题；真正的问题只在**都进指标**时（= 逃生开关）。
	// 先报混类再过滤，会把"本来就要被丢掉的那几条"当成错误（实测踩到：2 条目标 + 2 条侦察的
	// 数据集在缺省口径下被拒，而正确行为是"用那 2 条目标算"）。
	kept := make([]Record, 0, len(records))
	counts := map[string]int{}     // 逐条判定的依据分布（含被丢的与假设的）
	keptCounts := map[string]int{} // **参与决策层**那部分的依据分布（生效依据）
	skipped := map[string]int{}    // 被丢出决策层指标的条数
	assumed := 0
	for _, rec := range records {
		b := strings.TrimSpace(rec.GroundTruth.Basis)
		if b == "" {
			switch {
			case assume != "":
				// **不改记录本体**（记录是证据），只在本次评估的**指标**里按假设归类 ——
				// 假设必须可见（`Metrics.BasisAssumed`），否则"这批记录的标签口径是假设来的"
				// 这件事会静默消失。
				b, assumed = assume, assumed+1
			case opts.AllowMixedBasis:
				// 逃生开关：缺依据按**旧口径**理解（里程碑 B 之前 compromised 由"任意 link 成功"算出），
				// 且它仍会被当作侦察口径丢出决策层指标 —— 条数如实记进 `(未声明)`。
				skipped["(未声明)"]++
				counts["(未声明)"]++
				continue
			default:
				counts["(未声明)"]++
				continue
			}
		}
		switch b {
		case edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook:
		default:
			return basisGuardOutcome{}, fmt.Errorf("edgecompare: 记录里出现未知的 ground_truth.basis = %q —— "+
				"决策层指标只吃 %q 那一类；未知值不得被当成某一类静默算进去（那会让漏判率的口径无法追溯）",
				b, edgeexp.BasisTargetedTTP)
		}
		if b == edgeexp.BasisReconPlaybook && !opts.AllowMixedBasis {
			skipped[edgeexp.BasisReconPlaybook]++
			counts[b]++
			continue
		}
		counts[b]++
		// 报告头那一格（`参与决策层 N 条（…）`）统计的是**生效依据**：按 `--assume-basis` 归类的
		// 记录算在**假设的那一类**，而不是落在空串键上（Fix round 2 / Minor-2：上一版从记录原字段
		// 统计 ⇒ 报告头打印 `参与决策层 4 条（=4）`，JSON 里是 `"basis": {"": 4}`，那一格正好
		// 失去了"是哪一类"——而它是给人看的口径行）。
		keptCounts[b]++
		kept = append(kept, rec)
	}

	// 第二步：**缺依据 ⇒ 报错**（缺省口径）。它排在过滤之后：被丢掉的侦察口径记录不该让整批失败
	// （它们本来就不参与决策层指标）。
	if counts["(未声明)"] > 0 && assume == "" && !opts.AllowMixedBasis {
		return basisGuardOutcome{}, fmt.Errorf("edgecompare: %d/%d 条记录没有 ground_truth.basis —— 决策层指标无从判断这些标签是"+
			"『目标 TTP 是否成功』还是『任意 link 是否成功』（两者在数据上同形，而漏判率的口径由它决定）。"+
			"三条出路：用带 basis 的采集产物重采（Task 4D 起 edge_attack.sh 会写它）；"+
			"用 --assume-basis %s 显式声明这批记录的标签口径（假设的条数会写进指标本体）；"+
			"或用 --allow-mixed-basis 接受旧口径（缺依据的记录会被当作 %s 理解，条数如实记进 basis_skipped）",
			counts["(未声明)"], len(records), edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook)
	}

	// 第三步：**混类**。
	//
	// 两条互斥的分支（写成一条会把条件写反 —— 本轮实测踩到过：错误信息里声称
	// "`--allow-mixed-basis` 已开启"，而那一轮根本没开，读者据此会去关一个没开的东西）：
	//   · 缺省口径（`AllowMixedBasis=false`）⇒ 侦察口径的记录**已经**在上面的循环里被丢出指标
	//     （`skipped` 里有它们），故"混类"**不是**错误 —— 用剩下的那一类算就是了；
	//   · 逃生开关（`AllowMixedBasis=true`）⇒ 两类都要进指标 ⇒ 那才是真矛盾（混算的漏判率没有定义）。
	if counts[edgeexp.BasisTargetedTTP] > 0 && counts[edgeexp.BasisReconPlaybook] > 0 && opts.AllowMixedBasis {
		return basisGuardOutcome{}, fmt.Errorf("edgecompare: 记录里混了两种标签依据（%s=%d 条、%s=%d 条），"+
			"而 `--allow-mixed-basis` 让**两类都要进**决策层指标 —— 它们的 compromised 不是同一个量"+
			"（前者『目标 TTP 是否成功』、后者『任意 link 是否成功且在任何姿态下都成立』），混算出来的漏判率没有定义。"+
			"请只保留一类：去掉 `--allow-mixed-basis`（侦察口径的记录会被自动丢出决策层指标），"+
			"或先用 `--assume-basis` / 重采把这类记录的口径统一",
			edgeexp.BasisTargetedTTP, counts[edgeexp.BasisTargetedTTP],
			edgeexp.BasisReconPlaybook, counts[edgeexp.BasisReconPlaybook])
	}
	return basisGuardOutcome{kept: kept, determined: counts, keptCounts: keptCounts,
		skipped: skipped, assumed: assumed}, nil
}

// thresholdOf 返回该记录本次评估实际使用的阈值（覆盖优先，且覆盖值本身已由 CLI 校验为正）。
func thresholdOf(rec Record, opts EvaluateOptions) float64 {
	if opts.ThresholdOverride > 0 {
		return opts.ThresholdOverride
	}
	return rec.Observed.Threshold
}

// Evaluate 是 `EvaluateWith` 的缺省口径包装（不覆盖任何东西）。
func Evaluate(records []Record, p edgefactor.Params, weights map[string]float64) (Metrics, error) {
	return EvaluateWith(records, p, weights, EvaluateOptions{})
}

// sumCounts 是 map[string]int 的求和（`BasisSkipped` 的条数）。
func sumCounts(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

// EvaluateWith 在同一份真实数据上重算并计算三层指标（spec §2.1），并接受显式覆盖项
// （目前只有阈值；见 `EvaluateOptions`）。
//
// 决策层对齐规则（模型判定 ↔ 客观结果）：
//   - 模型判定：`acceptable = 重算分数 ≥ 本次阈值`。**缺省**阈值取自观测记录，四个候选共用
//     同一根判定线 —— 比较的是"同一份真实数据 + 同一判定线下谁的决定更接近现实"；
//     `opts.ThresholdOverride > 0` 时改用覆盖值（敏感性分析），此时"同一根线"依然成立。
//   - 客观结果：`compromised` 来自 `ground_truth`（真实攻防实验的客观结论，与任何模型无关）；
//   - 一致：`acceptable == !compromised`（判"可接受" ⇔ 客观未被攻陷）；
//   - 漏判 FN：`acceptable && compromised`（模型放行、实际被攻陷）—— 主判据之一；
//   - 误阻断 FP：`!acceptable && !compromised`（模型阻断、实际没被攻陷）—— 主判据之二；
//   - 两个率按 brief 给定定义取 `计数 / N`（占样本比，不是条件率）。四个候选共用同一个 N，
//     故占样本比在候选之间可比。
//
// 排序层用「模型分数 vs 客观严重度」，数值层用「危险度 (100−score) vs compromised」，
// 两层都只是辅助证据，不参与选优（选优在 Task 9 的 Compare）。
func EvaluateWith(records []Record, p edgefactor.Params, weights map[string]float64,
	opts EvaluateOptions) (Metrics, error) {
	var m Metrics
	if len(records) == 0 {
		return m, nil
	}
	// 标签依据守卫**排在一切计算之前**（Task 4D Step 4）：它是"这批数据的标签能不能放在一起算"
	// 的前置问题，先于"分数算得对不对"。过滤后为空 ⇒ 退回零值（与空输入同款：调用方
	// `CompareWith` 已在**过滤前**拒过零记录，这里的空只可能来自"全部记录都是侦察口径"，
	// 而 `CompareWith` 另有一道"过滤后 N == 0 也不给结论"的闸门 —— Fix round 2 / Minor-3）。
	guard, err := applyBasisGuard(records, opts)
	if err != nil {
		return Metrics{}, err
	}
	basisCounts, basisSkipped, basisAssumed := guard.keptCounts, guard.skipped, guard.assumed
	if len(guard.kept) == 0 {
		return Metrics{BasisSkipped: basisSkipped, RecordsTotal: len(records)}, nil
	}
	records = guard.kept
	m.RecordsTotal = len(records) + sumCounts(basisSkipped)
	m.BasisAssumed = basisAssumed
	// `Basis` = **参与决策层那部分**的生效依据分布（口径见 `Metrics.Basis` 与
	// `basisGuardOutcome.keptCounts`）：按 `--assume-basis` 归类的记录算在假设的那一类。
	m.Basis = basisCounts
	m.BasisSkipped = basisSkipped
	m.N = len(records)
	scores := make([]float64, 0, len(records))
	severity := make([]float64, 0, len(records))
	labels := make([]bool, 0, len(records))
	agree, fn, fp := 0, 0, 0

	for _, rec := range records {
		// 权重来源先解析（Task 3B Step 1）：**记录自带优先**，`weights` 只是回退表。
		// 下面两条判据必须与实际参与聚合的域集**同源** —— 域覆盖判据若仍按 `-weights` 走，
		// `-weights` 里多一个该部署没有聚合的域就会在**合法记录**上报"缺域"（门禁①）。
		w := recordWeights(rec, weights)
		// 解析后的表必须至少有一个正权重（Fix round 1 / Minor 1）：全零表绕过 CLI 守卫
		// （它是记录自带的，不是命令行输入）后会让分母恒 0、指标退化成"全阻断"而报告照常打印。
		if err := validateWeightsUsable(rec, w); err != nil {
			return Metrics{}, err
		}
		// 先校验域覆盖（评审 I2）：缺域会被当作 0 聚合、静默扭曲主判据，必须在算分之前拒绝。
		if err := validateDomainsCovered(rec, w); err != nil {
			return Metrics{}, err
		}
		score, err := OfflineScoreWithWeights(p, rec, w)
		if err != nil {
			// 返回零值 Metrics（而不是半填的 m）：错误必须让调用方无法把结果当成有效报告。
			return Metrics{}, fmt.Errorf("edgecompare: scenario %s: %w", rec.ScenarioID, err)
		}
		acceptable := score >= thresholdOf(rec, opts)
		compromised := rec.GroundTruth.Compromised
		scores = append(scores, score)
		severity = append(severity, severityOf(rec.GroundTruth))
		labels = append(labels, compromised)
		if acceptable == !compromised {
			agree++
		}
		if acceptable && compromised {
			fn++
		}
		if !acceptable && !compromised {
			fp++
		}
	}
	m.DecisionAgreement = float64(agree) / float64(m.N)
	m.FalseNegativeRate = float64(fn) / float64(m.N)
	m.FalsePositiveRate = float64(fp) / float64(m.N)
	m.Spearman = spearman(scores, severity)
	m.Kendall = kendall(scores, severity)
	m.AUC = auc(scores, labels)
	return m, nil
}

// severityOf 把客观受损程度折成单调严重度：攻陷越快、TTP 越多、节点越多越严重。
// 未被攻陷 ⇒ 0（与"分数越高越安全"的模型分数应呈负相关，故 Spearman/Kendall 期望为负）。
func severityOf(gt GroundTruth) float64 {
	if !gt.Compromised {
		return 0
	}
	return 1000.0/(gt.TimeToCompromiseS+1) + float64(gt.TTPsAchieved)*10 + float64(gt.NodesAffected)
}

// ranks 返回平均秩（并列取平均），用于 Spearman。
func ranks(values []float64) []float64 {
	idx := make([]int, len(values))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return values[idx[a]] < values[idx[b]] })
	out := make([]float64, len(values))
	for i := 0; i < len(idx); {
		j := i
		for j+1 < len(idx) && values[idx[j+1]] == values[idx[i]] {
			j++
		}
		avg := float64(i+j)/2 + 1
		for k := i; k <= j; k++ {
			out[idx[k]] = avg
		}
		i = j + 1
	}
	return out
}

func spearman(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	ra, rb := ranks(a), ranks(b)
	return pearson(ra, rb)
}

func pearson(a, b []float64) float64 {
	n := float64(len(a))
	var sa, sb, saa, sbb, sab float64
	for i := range a {
		sa += a[i]
		sb += b[i]
		saa += a[i] * a[i]
		sbb += b[i] * b[i]
		sab += a[i] * b[i]
	}
	num := n*sab - sa*sb
	den := math.Sqrt((n*saa - sa*sa) * (n*sbb - sb*sb))
	if den == 0 {
		return 0
	}
	return num / den
}

func kendall(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	concordant, discordant := 0, 0
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			da, db := a[i]-a[j], b[i]-b[j]
			switch {
			case da*db > 0:
				concordant++
			case da*db < 0:
				discordant++
			}
		}
	}
	total := concordant + discordant
	if total == 0 {
		return 0
	}
	return float64(concordant-discordant) / float64(total)
}

// auc 以 compromised 为正类、以"越危险分越低"的模型分数为排序依据。
// 使用 (100 − score) 作为危险度；未攻陷样本为负类。
//
// 100 是评分量纲上的上界（域分/总分按百分制）：这里的位移只影响数值，不影响顺序，
// 故 AUC 与位移量无关。
func auc(scores []float64, labels []bool) float64 {
	var pos, neg []float64
	for i, l := range labels {
		danger := 100 - scores[i]
		if l {
			pos = append(pos, danger)
		} else {
			neg = append(neg, danger)
		}
	}
	if len(pos) == 0 || len(neg) == 0 {
		return 0
	}
	wins := 0.0
	for _, p := range pos {
		for _, n := range neg {
			switch {
			case p > n:
				wins++
			case p == n:
				wins += 0.5
			}
		}
	}
	return wins / float64(len(pos)*len(neg))
}
