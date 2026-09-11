//go:build edgeexp

package main

import (
	"fmt"
	"io"
	"math"
	"math/rand"
	"sort"
	"strings"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// Task 10：含交互项的 logistic 拟合（先验候选边集）+ 系数→参数映射 + 可回填产物。
//
// 三条纪律（与 Task 8/9 同款）：
//
//  1. **"看起来有结论、实际没有"的产物一律变成错误**：零记录、空设计矩阵、折数 > 样本数、
//     重复 / 自环 / 越界 / 指向未建模因子的先验边、过不了 `Validate` 的基准参数 —— 全部
//     fail-fast。拟合产物的用途是"回填进配置"，一份能被解析但算出来不同的参数比报错更糟。
//  2. **确定性**：固定种子、特征顺序按因子 ID 字典序、自助法用 `rand.NewSource(Seed)`、
//     任何一步都不依赖 map 迭代序 —— 同一输入两次拟合必须逐位相同（含自助法区间）。
//     拟合产物要进论文与配置，抖动即不可归因。
//  3. **近似性如实标注**：本文件里的"系数 → 参数"映射是**启发式**的，不是极大似然意义上的
//     参数恢复（见 factorFromCoefficient / couplingFromCoefficient 与 design 的注释，
//     以及 task-10-report.md §拟合器设计）。
//
// 与在线评分共用**同一裁剪口径**：特征域集合取 `DefaultDomains ∩ λ`（legacy 例外，它不读 λ），
// 与 `offlinePlan` / `pruneToDomains` 逐条一致；基准参数先裁剪到该域集合再 `Validate`
// （这是 TestFitRejectsNonPositiveLambda 与合成夹具的共同前提）。

// FitOptions 是拟合的全部可调项（brief 给定的四字段 + 追加的 L1）。
//
// **`L2` 的语义（Task 10 Fix round 1 澄清：已改名换义，务必按实现理解）**：
// `L2` **不是**"绝对脊参数"，而是**相对收缩率**。实现的罚项是按列信息量归一过的：
// 标准化列上的罚项为 `½·L2·G_jj·w_j²`（`G_jj` = 该列未加罚的加权 Gram 对角元），
// 于是 `L2` 对**每一列**都是同一个相对收缩率 `1/(1+L2)`，与列的信息量无关。
// `L2 = 0.01` ⇒ 每列收缩 1%；`L2 = 0` 表示不收缩。
//
// 为什么不用绝对罚项 `½·L2·||w||²`（brief 示例代码的写法）：本书的 IRLS 权重
// `W = p(1−p) ≈ 0.21`，绝对罚项 `L2 = 0.01` 等价于对每列收缩 4.8%，而这一收缩会沿
// 高度共线的设计方向被放大成**耦合系数 +0.14 的系统偏置**（n = 60000 实测 +0.142，与 n 无关），
// 且每一组数据集单独看仍在 ±0.25 的逐数据集容差之内。推导与实测见 task-10-report.md §3.3。
//
// `L1` 是**追加字段**（brief 的接口只列了 L2）：`L1` 是标准的绝对 L1 罚项
// `L1·||w||₁`（作用于标准化尺度、截距除外），默认关闭（0），与 brief 的接口保持兼容。
// 之所以默认关闭：先验边集 ≤ 5 这条可辨识性约束本身已经承担了稀疏化职责，而在 22 场景的
// 真实数据上再套一层 L1 会让"边是否显著"的结论同时受两个旋钮影响。
type FitOptions struct {
	PriorEdges [][2]string
	L2         float64 // 相对收缩率：每列收缩 1/(1+L2)（见上）
	L1         float64 // 标准化尺度上的绝对 L1 罚项，默认 0
	Folds      int
	Seed       int64
}

// FitReport 是一次拟合的数值证据。四张表都必须非空 —— 返回零值会被读成"测过了"。
//
//	Coefficients     ：全部设计列（含 "(intercept)" 与边列）在**原始列尺度**上的系数
//	EdgeCoefficients ：只含边列（键形如 "A|B"），供"哪些边显著"的结论直接引用
//	CVErr            ：k 折交叉验证的平均对数损失
//	Bootstrap        ：自助法 95% 百分位区间，**与 Coefficients 同一尺度（原始列尺度）**
//
// `Bootstrap` 的尺度是 Task 10 Fix round 1 修正的：自助法重采样在标准化尺度上求解，
// 早期实现在那一尺度上取百分位，于是同一张报告里"系数"与"区间"量纲不同（区间看着总是
// 包不住系数），"区间是否覆盖真值"这条最有力的无偏性断言也就无从写起。现在每个重采样
// 样本都**先反归一化再取百分位**（非截距列是单调变换，截距列则逐样本换算后取百分位）。
type FitReport struct {
	Coefficients     map[string]float64    `json:"coefficients"`
	EdgeCoefficients map[string]float64    `json:"edge_coefficients"`
	CVErr            float64               `json:"cv_err"`
	Bootstrap        map[string][2]float64 `json:"bootstrap"`
}

const (
	// fitInterceptName 是截距列的列名（测试与报告都按这个名字取）。
	fitInterceptName = "(intercept)"
	// fitMaxPriorEdges 是可辨识性上限：22 个场景对不上"21 个主效应 + 边"的自由度，
	// 故先验边集硬上限 5 条（spec §6 / mandate 口径 1）。超限报错，绝不悄悄截断 ——
	// 截断会让报告里的边集与实际拟合的边集不是同一套。
	fitMaxPriorEdges = 5
	// fitBootstrapRounds 是自助法重采样次数（brief 给定 100）。
	fitBootstrapRounds = 100
	// fitMinFactor 是 `Factors[i] = clip(1 − β_i, 1e-3, 1)` 的下界。
	fitMinFactor = 1e-3
	// fitDefaultFolds / fitDefaultL2 / fitDefaultSeed 是零值选项的兜底（brief 给定）。
	fitDefaultFolds = 3
	fitDefaultL2    = 0.01
	fitDefaultSeed  = 1
	// fitMaxOuterIterations 是 IRLS 外层迭代上限：本问题是 4–7 维、n 上千，正常 6–12 轮收敛，
	// 上限只为防病态输入下不收敛时死循环（确定性：迭代次数只由数据决定）。
	fitMaxOuterIterations = 40
	// fitMaxInnerSweeps 是内层坐标下降的轮数上限（每轮 O(d²)，很便宜）。特征列高度共线，
	// 内层必须真的解到机器精度，否则外层牛顿步会被"没解完的二次子问题"拖成缓慢的迭代。
	fitMaxInnerSweeps = 10000
	// fitInnerTolerance 是内层坐标下降的停机阈值（一轮内最大坐标更新量）。
	fitInnerTolerance = 1e-12
	// fitOuterTolerance 是 IRLS 外层的停机阈值（整轮后系数的最大变化量）。
	fitOuterTolerance = 1e-10
	// fitMinHessian 是 IRLS 权重 p(1−p) 的下界：完全分离的数据会让 p → 0/1、工作响应炸掉；
	// 下界 + L2 一起把系数钉在有界范围内（宁可收敛慢，也不产出 ±Inf）。
	fitMinHessian = 1e-6
	// fitMaxWorkingResponse 是工作响应 z_i 的绝对值上限（同上，防分离数据下的数值爆掉）。
	fitMaxWorkingResponse = 50.0
)

// ============================================================================
// 系数 → 参数映射（mandate 口径 2，规则写死在此处）
// ============================================================================

// factorFromCoefficient 把主效应系数折成因子权重（mandate 给定的规则，逐字实现）：
//
//	β_i > 0 ⇒ Factors[i] = clip(1 − β_i, 1e-3, 1)
//	β_i ≤ 0 ⇒ Factors[i] = 1（不惩罚）
//
// **近似性标注**：这条映射不是"从数据里恢复 f_i"的统计学等价物。logistic 系数 β_i 是
// 对数优势比上的斜率，而 f_i 是乘性惩罚权重；两者只在"单因子、单域、小效应"的线性化邻域里
// 近似对应，且 `1 − β` 这种写法本身没有量纲依据（为什么不是 `exp(−β)` 或 `1/(1+β)`？）。
// 之所以仍然写死它：本轮的结论口径只到"**哪些边显著** + 决策层改善"（spec §6），
// 参数标定（把 β 映射成有量纲意义的 f_i）明确后置。β ≥ 1 时 clip 到 1e-3 的饱和行为同样
// 是字面语义而非统计结论 —— 它意味着"该因子几乎完全失效"，报告里必须连同这条说明一起引用。
func factorFromCoefficient(beta float64) float64 {
	if beta <= 0 {
		return 1
	}
	return math.Max(fitMinFactor, math.Min(1, 1-beta))
}

// couplingFromCoefficient 把交互项系数折成耦合强度（mandate 给定的规则，逐字实现）：
//
//	β_ij > 0 ⇒ Coupling[i][j] = min(β_ij, 1)
//	β_ij ≤ 0 ⇒ 不写，且**移除基准里该边已有的旧值**（见下方说明；Fix round 2 把规则行的
//	            "保持 0" 措辞改准 —— 语义不是"留着旧值当 0"，而是"这条边从产物里消失"）
//
// 返回的第二个值表示"是否写入"：`β ≤ 0` 时**不写**，而且 `Fit` 会把基准里已有的这条边
// **一并移除**（`removeCouplingEdge`）。两者在 `Synthesize` 里等价（`couplingValue` 取不到
// 就是 0），但"移除"是本任务选定的语义，理由有三：
//
//  1. 它是本规则的**唯一自洽读法**：报告行打印"coupling 不写（β ≤ 0）"，
//     产物里若仍带着基准的旧值，配置段与报告自相矛盾（Fix round 1 / C1）；
//  2. `-fit` 的基准就是 `config.Load` 读进来的配置 —— 真实配置带 C 模型的级联边，
//     或带上一轮的拟合产物；只跳过不删除会让**已经不再显著的边永久留存**，
//     参数段越粘越"满"，而读者从报告里看不出这件事；
//  3. 本拟合器的结论口径正是"哪些边显著"（spec §6），对不显著的边保留旧值等于替数据说话。
//
// 「冗余由 Σ_d v ≤ 1 吸收」这条不变：耦合项与主效应项共享同一个作用量上界，不写该边不会让
// 其它项的惩罚凭空变大。
//
// **近似性标注**：β_ij 是"两因子同时激活时的对数优势比超出主效应线性叠加的部分"，
// 而 c_ij 是逐域惩罚项 `c_ij·a_i·a_j` 的系数；两者的对应同样依赖线性化，
// 且 c_ij 的量纲随 `Σ_d v_i[d]`（本拟合器的作用列尺度）而定 —— 换一套向量口径，
// 同一个 β 会折成不同的 c。故拟合出的 c 只在"与生成它的那套基准参数同一口径"时可解释。
func couplingFromCoefficient(beta float64) (float64, bool) {
	if beta <= 0 {
		return 0, false
	}
	return math.Min(beta, 1), true
}

// ============================================================================
// Fit：拟合主效应与先验交互边
// ============================================================================

// Fit 在带标签的实验记录上拟合"主效应 + 先验边"的 logistic 模型，并把系数折回
// `edgefactor.Params`（mandate 口径 1 与 2）。
//
// 返回的 Params 是**基准参数的独立副本**：主效应列覆盖 `Factors`；`Coupling` 里**先验边集
// 覆盖到的边**由拟合结果决定 —— `β_ij > 0` 写入 `min(β_ij,1)`，`β_ij ≤ 0` **移除该边**
// （移除语义见 couplingFromCoefficient 的注释）；先验边集**之外**的边保持基准值不动
// （它们不进设计矩阵，无从估计，改动它们等于凭空造结论）。
// 其余字段（Model / PFloor / Lambda / Vectors / ChainWindowSeconds）原样保留。
// `base` 绝不会被就地修改（Caller 从配置装载它，随后还要用它）。
func Fit(records []Record, base edgefactor.Params, opts FitOptions) (edgefactor.Params, FitReport, error) {
	opts = normaliseFitOptions(opts)
	if err := validateFitRequest(records, base, opts); err != nil {
		return edgefactor.Params{}, FitReport{}, err
	}
	d, err := buildFitDesign(records, base, opts)
	if err != nil {
		return edgefactor.Params{}, FitReport{}, err
	}
	beta := d.pointEstimate()

	cvErr, err := crossValidate(d.X, d.y, opts, d.coef)
	if err != nil {
		return edgefactor.Params{}, FitReport{}, err
	}
	rep := FitReport{
		Coefficients:     make(map[string]float64, len(d.names)),
		EdgeCoefficients: make(map[string]float64, len(d.edges)),
		CVErr:            cvErr,
		Bootstrap:        bootstrapCoefficients(d.X, d.y, d.names, opts, d.coef, d.means, d.scales),
	}
	for i, name := range d.names {
		rep.Coefficients[name] = beta[i]
	}

	out := cloneParams(base)
	if out.Factors == nil {
		out.Factors = make(map[string]float64, len(d.names))
	}
	if out.Coupling == nil {
		out.Coupling = make(map[string]map[string]float64, len(d.edges))
	}
	firstEdge := len(d.names) - len(d.edges)
	for i, name := range d.names {
		switch {
		case i == 0:
			// 截距不映射成任何参数：它吸收的是"基线被攻陷概率"，不属于因子模型。
		case i >= firstEdge:
			e := d.edges[i-firstEdge]
			rep.EdgeCoefficients[edgeColumnName(e)] = beta[i]
			// **无论写值还是移除，都先清掉该边在这份产物里的全部旧表示**（Fix round 1 / C1
			// 与 Fix round 2 / ③ 的统一口径）。graph 的耦合是对称的 —— `couplingValue`
			// 双向查表 —— 于是"产物里的这条边"可能以 `A→B` 或 `B→A` 两种写法存在：
			//   · β ≤ 0：只 continue 会留下旧值，报告行却打印"coupling 不写（β ≤ 0）"；
			//   · β > 0：只写 `A→B` 会与基准的 `B→A = 旧值` **并存**，同一条对称边在产物里
			//     有了两个不同的值，而 RenderConfigSection 会把两者都写进配置段。
			// 两种情形都是"同一份产物自相矛盾"，故走同一个 removeCouplingEdge 收口。
			removeCouplingEdge(out, e)
			c, write := couplingFromCoefficient(beta[i])
			if !write {
				continue
			}
			if out.Coupling[e[0]] == nil {
				out.Coupling[e[0]] = make(map[string]float64, 1)
			}
			out.Coupling[e[0]][e[1]] = c
		default:
			out.Factors[name] = factorFromCoefficient(beta[i])
		}
	}
	return out, rep, nil
}

// removeCouplingEdge 从参数副本里删掉一条边在这份产物里的**全部表示**，口径与
// `couplingValue` 的查表口径一致：graph 的耦合是对称的（反向配置同样会被消费），故两个方向
// 都要删；chain 只删有向的那一条。
//
// 它在 `Fit` 的映射循环里**写值与移除两条分支之前**无条件调用：写值分支也必须先清反向旧值，
// 否则 graph 基准里以 `B→A` 存着的那条边会与新的 `A→B` 并存 —— 同一条对称边在产物里有两个
// 不同的值，`RenderConfigSection` 会把两者都写进配置段（Fix round 2 / ③）。
//
// 删空的内层 map 一并删掉，让"该边消失"在结构上看得见（`RenderConfigSection` 只遍历
// 实际存在的键，留着空 map 不会多写行，但会让 `Hash()` 与人的阅读都对不上）。
func removeCouplingEdge(p edgefactor.Params, e [2]string) {
	remove := func(from, to string) {
		tos, ok := p.Coupling[from]
		if !ok {
			return
		}
		delete(tos, to)
		if len(tos) == 0 {
			delete(p.Coupling, from)
		}
	}
	remove(e[0], e[1])
	if p.Model == edgefactor.ModelGraph {
		remove(e[1], e[0])
	}
}

// fitDesign 是拟合的**构造与求解结果**：裁剪域、先验边、设计矩阵、标准化参数与点估计系数。
//
// 之所以单独抽出来（Fix round 1 / I1）：偏置回归测试要跑几十组独立数据集，而 k 折交叉验证 +
// 100 次自助法占单次 `Fit` 九成以上的耗时、且与"估计量是否有偏"无关。测试直接用本结构体
// 复算点估计，走的是与 `Fit` **完全相同**的构造与求解函数（`design` / `standardise` /
// `fitElasticNet` / `denormaliseCoefficients`），不是产品路径的复制品。
type fitDesign struct {
	domains []string
	edges   [][2]string
	names   []string
	X       [][]float64
	y       []bool
	means   []float64
	scales  []float64
	coef    []float64
}

// pointEstimate 返回原始列尺度上的点估计系数（与 `Fit` 写入 `Coefficients` 的值逐位一致）。
func (d fitDesign) pointEstimate() []float64 {
	return denormaliseCoefficients(d.coef, d.means, d.scales)
}

// buildFitDesign 做「裁剪域 → 校验 → 设计矩阵 → 列标准化 → 求解」三步。
func buildFitDesign(records []Record, base edgefactor.Params, opts FitOptions) (fitDesign, error) {
	var d fitDesign
	// 与在线装配 / 离线重算**同一裁剪口径**：特征域 = DefaultDomains ∩ λ（legacy 例外）。
	domains, err := fitDomains(base)
	if err != nil {
		return fitDesign{}, err
	}
	// 基准参数必须先过裁剪域上的 Validate：λ ≤ 0 这类参数在 Synthesize 里就会被拒，
	// 在这里兜底（例如把它悄悄当 1.0 用）只会产出一份"能拟合、算不出"的参数。
	if err := pruneToDomains(base, domains).Validate(domains); err != nil {
		return fitDesign{}, fmt.Errorf(
			"edgecompare: 基准参数在拟合域 %v 上过不了 Validate —— 拟合前请先修好它（不得兜底）：%w", domains, err)
	}
	d.domains = domains
	d.edges = canonicalEdges(base, opts.PriorEdges)
	names, X, y := design(records, base, domains, d.edges)
	if len(names) <= 1 {
		return fitDesign{}, fmt.Errorf(
			"edgecompare: 设计矩阵只有截距列（基准既无因子也无先验边）—— 零列上的任何『系数』都只是正则项的产物")
	}
	d.names, d.X, d.y = names, X, y
	// 按列标准化（均值 0 / 标准差 1）保证数值稳定；系数随后反归一化回**原始列尺度**，
	// 这样报告里的 β 与"a_i = (1−eff_i)·Σ_d v_i[d]"同尺度，可直接与已知真值比对。
	d.means, d.scales = standardise(X)
	d.coef = fitElasticNet(X, y, opts.L1, opts.L2, nil)
	return d, nil
}

// validateLabelVariation 要求标签里**两类都出现**。
//
// 单类别标签下 logistic 回归没有有限解：似然随系数范数单调上升，IRLS 会被推向完全分离，
// 系数被迭代上限截停在"接近饱和"的位置。对本拟合器的后果尤其恶劣 ——
// `factorFromCoefficient` 在 β ≥ 1 时 clip 到 1e-3（"该因子几乎完全失效"），
// `couplingFromCoefficient` 在 β ≥ 1 时给 min(β,1) = 1（"耦合拉满"），
// 于是产物是一份**极端参数**；`CVErr` 则退化成常数预测器的对数损失，
// 看起来像一次正常的测量。全程没有任何错误或告警 ⇒ 必须在这里拒绝。
func validateLabelVariation(records []Record) error {
	compromised := 0
	for _, rec := range records {
		if rec.GroundTruth.Compromised {
			compromised++
		}
	}
	if compromised == 0 || compromised == len(records) {
		return fmt.Errorf("edgecompare: %d 条记录的 ground_truth.compromised 全是 %v —— 单类别标签下 logistic 似然被推向完全分离，"+
			"系数会被截停在饱和区（主效应 clip 到 1e-3、边系数 min(β,1)=1），CVErr 退化成常数预测器的损失："+
			"这份产物看起来正常，实际只是迭代上限的产物", len(records), compromised == len(records))
	}
	return nil
}

// normaliseFitOptions 把零值选项补成 brief 给定的默认值（Folds = 3、L2 = 0.01、Seed = 1）。
func normaliseFitOptions(opts FitOptions) FitOptions {
	if opts.Folds <= 1 {
		opts.Folds = fitDefaultFolds
	}
	if opts.L2 <= 0 {
		opts.L2 = fitDefaultL2
	}
	if opts.Seed == 0 {
		opts.Seed = fitDefaultSeed
	}
	if opts.L1 < 0 {
		opts.L1 = 0
	}
	return opts
}

// validateFitRequest 是拟合的前置条件检查（顺序即下面的分支顺序，错误信息点名问题所在）。
//
// 为什么每条都必须是错误而不是"尽力而为"：
//   - 零记录 ⇒ 任何系数都只是正则项的产物；
//   - 先验边 > 5 ⇒ 越过可辨识性上限（22 场景 vs 21 参数），悄悄截断会让报告里的边集失真；
//   - 先验边落在 legacy/vector 上 ⇒ 这两个模型不消费 Coupling，拟合出来的边"报告里有、模型里没有"；
//   - 自环边 ⇒ `Synthesize` 跳过 from == to，同样是假参数；
//   - 重复边 ⇒ 两个完全相同的列，设计矩阵奇异、边系数无意义；
//   - 未知因子 ⇒ 边列会退化成"拿主效应第 0 列相乘"的垃圾列，且边系数无处落；
//   - 折数 > 样本数 ⇒ 交叉验证无从进行，返回 0 会被读成"零泛化误差"。
func validateFitRequest(records []Record, base edgefactor.Params, opts FitOptions) error {
	if len(records) == 0 {
		return fmt.Errorf("edgecompare: 拟合需要至少一条带标签的记录 —— 零记录下任何系数都只是正则项的产物")
	}
	// 单类别标签（全部被攻陷 / 全部未攻陷）⇒ logistic 似然被推向完全分离区间：
	// IRLS 会把系数冲到饱和（主效应 clip 到"因子全失效"、边系数 min(β,1)="耦合全 1"），
	// CVErr 退化成常数预测器的损失，而**全程零错误零告警**。真实实验里单类别并不罕见
	// （某一轮只跑了一组被攻陷的场景），故必须 fail-fast —— 与本文件"不产出看起来有结论、
	// 实际没有的产物"是同一条纪律（Fix round 1 / I5）。
	if err := validateLabelVariation(records); err != nil {
		return err
	}
	if len(opts.PriorEdges) > fitMaxPriorEdges {
		return fmt.Errorf("edgecompare: 先验边集有 %d 条，超过可辨识性上限 %d 条 —— 超过就先验化了，请收窄边集而不是让它被悄悄截断",
			len(opts.PriorEdges), fitMaxPriorEdges)
	}
	if len(opts.PriorEdges) > 0 && base.Model != edgefactor.ModelGraph && base.Model != edgefactor.ModelChain {
		return fmt.Errorf("edgecompare: 模型 %s 不消费 Coupling，却给了 %d 条先验边 —— 拟合出来的边系数只会存在于报告里，模型里没有对应的项",
			base.Model, len(opts.PriorEdges))
	}
	seen := make(map[string]bool, len(opts.PriorEdges))
	for _, e := range opts.PriorEdges {
		from, to := normalizeFactorID(e[0]), normalizeFactorID(e[1])
		if from == "" || to == "" {
			return fmt.Errorf("edgecompare: 先验边 %q|%q 含空因子 ID —— 会产出畸形列名与畸形配置键", e[0], e[1])
		}
		if from == to {
			return fmt.Errorf("edgecompare: 先验边 %s|%s 是自环 —— Synthesize 跳过 from == to，拟合出来的耦合不会被任何代码消费", from, to)
		}
		key := edgeColumnName(canonicalEdge(base, [2]string{from, to}))
		if seen[key] {
			return fmt.Errorf("edgecompare: 先验边 %s 重复 —— 两列完全相同会让设计矩阵奇异，边系数没有意义", key)
		}
		seen[key] = true
		for _, id := range []string{from, to} {
			if _, ok := base.Factors[id]; !ok {
				return fmt.Errorf("edgecompare: 先验边 %s 引用了未建模因子 %q —— 该列会退化成垃圾列，边系数也无处落", key, id)
			}
		}
	}
	if opts.Folds > len(records) {
		return fmt.Errorf("edgecompare: 折数 %d > 样本数 %d —— 交叉验证无从进行，返回 0 会被读成『零泛化误差』",
			opts.Folds, len(records))
	}
	// 因子 ID 里含 "|" 会让主效应列与边列**同名**（边列的名字就是 "i|j"），
	// 于是报告里的系数表、自助法区间会互相覆盖，参数映射也会张冠李戴。
	for _, id := range sortedNames(base.Factors) {
		if strings.Contains(id, "|") {
			return fmt.Errorf("edgecompare: 因子 ID %q 含 %q —— 它与边列的命名约定撞车，主效应列与交互列会同名", id, "|")
		}
	}
	return nil
}

// fitDomains 返回本次拟合的特征域集合，口径与在线装配 / 离线重算完全一致：
// `DefaultDomains ∩ λ`（legacy 例外：它不读 λ，惩罚完全由 GlobalMultiplier 表达）。
//
// 一个 λ 都没覆盖到默认域（V/G/C）时直接报错，而不是退回"全部 5 个默认域"——
// 后者会让缺失的域以 0 参与求和、悄悄改变特征尺度。
func fitDomains(p edgefactor.Params) ([]string, error) {
	if p.Model == edgefactor.ModelLegacy {
		return edgefactor.DefaultDomains(), nil
	}
	all := edgefactor.DefaultDomains()
	requested := make([]string, 0, len(all))
	for _, d := range all {
		if _, ok := p.Lambda[d]; ok {
			requested = append(requested, d)
		}
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf(
			"edgecompare: 模型 %s 没有为任何默认域声明 lambda.<domain> —— 任何一个域都不会被修正，拟合特征无从构造", p.Model)
	}
	return requested, nil
}

// canonicalEdge 把一条边归一到"模型语义下的同一性"：
// graph 的耦合是对称的（`couplingValue` 双向查表），故 (A,B) 与 (B,A) 是同一条边，
// 归一为 ID 字典序；chain 是有向的，保持原顺序。
func canonicalEdge(p edgefactor.Params, e [2]string) [2]string {
	if p.Model == edgefactor.ModelGraph && e[1] < e[0] {
		return [2]string{e[1], e[0]}
	}
	return e
}

// edgeColumnName 是边列在报告与设计矩阵里的列名（"i|j"）。
func edgeColumnName(e [2]string) string { return e[0] + "|" + e[1] }

// canonicalEdges 归一先验边集：ID 大写归一（与消费侧 `normalizeFactorID` 同语义）、
// graph 下按字典序定向、最后按列名字典序排序。
//
// 排序是**确定性要求**：列序决定设计矩阵的列序，也决定 `Coefficients` 的写入顺序；
// 不排序的话同一份边集换个书写顺序就会得到不同（虽然数学等价）的中间量。
func canonicalEdges(p edgefactor.Params, edges [][2]string) [][2]string {
	out := make([][2]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, canonicalEdge(p, [2]string{normalizeFactorID(e[0]), normalizeFactorID(e[1])}))
	}
	sort.Slice(out, func(i, j int) bool { return edgeColumnName(out[i]) < edgeColumnName(out[j]) })
	return out
}

// ============================================================================
// 设计矩阵
// ============================================================================

// design 构造设计矩阵：列 = 截距 + 主效应（因子作用 a_i）+ 先验交互（a_i·a_j，键 "i|j"）。
//
// 列序（确定性，mandate 口径 1）："(intercept)" → 主效应按**因子 ID 字典序** → 边列按列名字典序。
//
// 作用项口径（与 spec §3.1 的 a_i[d] = (1 − effective_f_i)·v_i[d] 一致）：
//
//	a_i = (1 − eff_i) · Σ_{d ∈ D} v_i[d]
//
// eff_i 取自记录因子链经**装配层换算**后的值（`activationsOf`：对已衰减一次的
// effective_factor 再衰减一次 `EffectiveFactor(f, c)`），缺失时回落到 `p.Factors[i]`
// （与 `Synthesize.resolveEffective` 的"未提供"哨兵同语义）。D = `fitDomains` 的裁剪域集合。
//
// **近似性标注**：这是一个"把逐域向量折成一个标量"的汇总口径。`Σ_d a_i[d]·a_j[d]` 才是
// 逐域耦合项之和，而这里用的是 (Σ_d a_i[d])·(Σ_d a_j[d]) —— 两者只在向量的支撑集重叠时
// 才有一致解释。之所以这样取：spec §6 要求的结论口径是"哪些边显著"，标量汇总让"边系数"
// 与"主效应系数"处在同一个（对数优势比的）尺度上可比；精确的逐域还原属于后置的标定工作。
//
// 未声明向量的因子按 `Synthesize` 的文档化 fallback 处理（作用于全部请求域、强度 1）⇒ Σ = |D|。
func design(records []Record, p edgefactor.Params, domains []string, edges [][2]string) (names []string, X [][]float64, y []bool) {
	ids := sortedNames(p.Factors)
	names = make([]string, 0, 1+len(ids)+len(edges))
	names = append(names, fitInterceptName)
	names = append(names, ids...)
	for _, e := range edges {
		names = append(names, edgeColumnName(e))
	}

	X = make([][]float64, 0, len(records))
	y = make([]bool, 0, len(records))
	for _, rec := range records {
		acts := modelActivations(p, rec)
		eff := make(map[string]float64, len(acts))
		for _, a := range acts {
			eff[a.FactorID] = a.EffectiveFactor
		}
		row := make([]float64, len(names))
		row[0] = 1
		main := make(map[string]float64, len(ids))
		for idx, id := range ids {
			v, activated := eff[id]
			if !activated {
				// **该因子在这条记录里根本没被激活**（链上不存在）⇒ 作用为 0。
				// 这一条极易写错：map 的零值与"链上给了但值为 0"不可区分，若在这里统一回落
				// `p.Factors[id]`，就会给所有"未激活"的样本凭空安上一个 (1 − f_i) 的作用，
				// 设计矩阵与真实生成过程不一致（实测：合成数据上耦合系数被压到真值的 1/5）。
				row[1+idx] = 0
				continue
			}
			if v == 0 { // 链上给了、但值是 0（「未提供」哨兵）⇒ 回落配置权重
				v = p.Factors[id]
			}
			main[id] = (1 - v) * vectorMass(p.Vectors[id], domains)
			row[1+idx] = main[id]
		}
		for k, e := range edges {
			row[1+len(ids)+k] = main[e[0]] * main[e[1]]
		}
		X = append(X, row)
		y = append(y, rec.GroundTruth.Compromised)
	}
	return names, X, y
}

// vectorMass 返回因子在特征域集合上的强度之和。
//
// 未声明向量 ⇒ `Synthesize` 的 fallback 是"作用于全部请求域、强度 1"，故返回 len(domains)
// （而不是 1）—— 这条口径差在标量汇总里只是一个常数因子，但它决定"边系数 ↔ c_ij"的换算。
func vectorMass(vec map[string]float64, domains []string) float64 {
	if vec == nil {
		return float64(len(domains))
	}
	sum := 0.0
	for _, d := range domains {
		sum += vec[d]
	}
	return sum
}

// standardise 按列标准化（均值 0、标准差 1），返回用于**反归一化**的均值与尺度。
//
// 下标 0（截距列）不参与：它的均值就是 1、标准差 0，标准化会把它变成全零列。
// 标准差为 0 的列（常数特征，例如"从不激活的因子"）尺度取 1、只做中心化 —— 于是该列变成
// 全零列，系数被 L2 罚到 0，映射回参数时得到 `Factors[i] = 1`（不惩罚）。这是规则的字面语义，
// 但报告必须连同"该因子在数据里没有观测到任何变化"一起读。
func standardise(X [][]float64) (means, scales []float64) {
	if len(X) == 0 || len(X[0]) == 0 {
		return nil, nil
	}
	d, n := len(X[0]), float64(len(X))
	means = make([]float64, d)
	scales = make([]float64, d)
	for j := 0; j < d; j++ {
		if j == 0 {
			scales[j] = 1
			continue
		}
		mean := 0.0
		for i := range X {
			mean += X[i][j]
		}
		mean /= n
		variance := 0.0
		for i := range X {
			dev := X[i][j] - mean
			variance += dev * dev
		}
		variance /= n
		sd := math.Sqrt(variance)
		means[j] = mean
		if sd <= 1e-12 || math.IsNaN(sd) {
			scales[j] = 1
		} else {
			scales[j] = sd
		}
		for i := range X {
			X[i][j] = (X[i][j] - mean) / scales[j]
		}
	}
	return means, scales
}

// denormaliseCoefficients 把标准化尺度上的系数还原成原始列尺度的系数。
//
// 因 eta = β0' + Σ_j β_j'·(x_j − m_j)/s_j，故
//
//	β_j = β_j'/s_j  (j ≥ 1)
//	β_0 = β0' − Σ_{j≥1} β_j·m_j      （截距吸收所有中心化位移）
//
// 不做这一步的话，"系数"会随列尺度缩放（例如交互列的最大值是 0.9 而主效应列是 0.95，
// 于是两条边的系数不可比），"β → 参数"的映射规则也就失去意义。
func denormaliseCoefficients(coef, means, scales []float64) []float64 {
	if len(coef) == 0 {
		return nil
	}
	out := make([]float64, len(coef))
	shift := 0.0
	for j := range coef {
		if j == 0 {
			continue
		}
		s := scales[j]
		if s == 0 {
			s = 1
		}
		out[j] = coef[j] / s
		shift += out[j] * means[j]
	}
	out[0] = coef[0] - shift
	return out
}

// ============================================================================
// 求解器：elastic-net logistic（IRLS 外层 + 坐标下降内层）
// ============================================================================

// fitElasticNet 解的是下面这个**每轮 IRLS 的二次子问题**（`½` 因子与罚项按列归一是精确表述）：
//
//	min_w  ½·(1/n)Σ_i W_i(z_i − x_iᵀw)²  +  ½·l2·Σ_{j≥1} G_jj·w_j²  +  l1·Σ_{j≥1}|w_j|
//
// 其中 `G_jj = (1/n)Σ_i W_i·x_ij²` 是该列**未加罚**的加权 Gram 对角元，`j = 0` 是截距列
// （不参与任何惩罚 —— 惩罚截距会把基线概率硬拉向 0.5）。
//
// **罚项的口径（Fix round 1 / I2 明确化，实现与文档在此对齐）**：
// L2 罚的是 `½·l2·G_jj·w_j²`，不是 `½·l2·w_j²`。因为该子问题的坐标解是
// `w_j = S(c_j − Σ_{k≠j}G_jk·w_k, l1) / (G_jj·(1+l2))`，于是 `l2` 对**每一列**给出
// 同一个**相对收缩率** `1/(1+l2)`，与列的信息量无关。`FitOptions.L2` 的注释里有动机说明。
//
// 收敛点满足**罚正则负对数似然**的次梯度平稳条件（`j ≥ 1`）：
//
//	(1/n)Σ_i (p_i − y_i)·x_ij  +  l2·G_jj·w_j  +  l1·∂|w_j| = 0        （∂|·| 取次梯度）
//
// 等价写法（把首项反号、罚项一并反号）：
//
//	(1/n)Σ_i (y_i − p_i)·x_ij  −  l2·G_jj·w_j  −  l1·sgn(w_j) = 0
//
// 即**负对数似然的梯度与罚项的（次）梯度相消**；`l1 = 0` 时退化成标准的岭正则 logistic
// 平稳条件。整套迭代是 MM（优化-最小化）：二次近似是光滑损失的**上界**，加入精确的
// L1/L2 罚项后每一步都不增大原目标。
//
// **两个罚项必须反号（Fix round 2 更正）**：本注释初版误写成 `(1/n)Σ(y−p)x + l2·G_jj·w_j +
// l1·sgn(w_j) = 0`（首项取 y−p 却让罚项保持正号）—— 那条式子的解会把系数推**离** 0，
// 与坐标解 `G_jj(1+l2)w_j = S(R, l1)`、`TestElasticNetL1ShrinksToExactZero` 的收缩/精确置零、
// 以及 §3.3 的偏置符号全部矛盾。推导（把 `W_i(z_i−η_i) = y_i − p_i` 代入第 j 个加罚坐标方程
// `Ĝ w|_j = c_j − l1·sgn(w_j)`，其中 `Ĝ = G⁰ + l2·diag(G⁰_jj)`）：
//
//	(1/n)Σ W_i x_ij(z_i − η_i) = (1/n)Σ x_ij(y_i − p_i) = l2·G_jj·w_j + l1·sgn(w_j)
//
// 故 `(1/n)Σ(y_i−p_i)x_ij − l2·G_jj·w_j − l1·sgn(w_j) = 0` ✓。
//
// 为什么不用 brief 示例里的纯梯度下降（这是本实现相对 brief 示例代码的主要偏离，理由如下）：
//
//   - **收敛性**：本任务的特征列高度共线（交互列 ≈ 两个主效应列之积），梯度下降在可接受的
//     迭代次数内到不了"系数正确"的精度，而核心验收正是"已知 c_ij 必须被近似还原"。
//     实测：固定步长梯度下降 400 轮时还原出的 c 与真值差 0.3 以上（越界失败）。
//   - **成本**：自助法要跑 100 次重采样 × 多组种子；把内层加权最小二乘写成**预计算 Gram 矩阵**
//     （G = XᵀWX/n、c = XᵀWz/n，各 O(n·d²) 一次）后，每轮坐标下降只需 O(d²)，
//     于是内层可以迭代到机器精度，总耗时仍是秒级。
//   - **L1**：坐标下降天然支持 L1 的软阈值（这是精确解，不是近似）。
//
// 确定性：迭代次数只由数据决定（固定上限 + 固定停机阈值），无随机成分、无 map 迭代序。
func fitElasticNet(X [][]float64, y []bool, l1, l2 float64, start []float64) []float64 {
	n := len(X)
	if n == 0 || len(X[0]) == 0 {
		return nil
	}
	d := len(X[0])
	w := make([]float64, d)
	// 热启动（可选）：交叉验证与自助法都从**全量解**出发。它们是同一个优化问题的重启，
	// 解不因起点而变（内层精确求解 + 外层牛顿迭代），只是收敛更快；起点是确定的 ⇒ 结果确定。
	if len(start) == d {
		copy(w, start)
	}
	prev := make([]float64, d)
	eta := make([]float64, n)
	weight := make([]float64, n)
	response := make([]float64, n)
	gram := make([][]float64, d)
	for j := range gram {
		gram[j] = make([]float64, d)
	}
	rhs := make([]float64, d)
	invN := 1 / float64(n)

	for outer := 0; outer < fitMaxOuterIterations; outer++ {
		copy(prev, w)
		// ① 在当前 w 处做二次近似：工作响应 z_i 与权重 p_i(1−p_i)。
		for i := 0; i < n; i++ {
			eta[i] = dot(X[i], w)
			p := sigmoid(eta[i])
			wi := p * (1 - p)
			if wi < fitMinHessian {
				wi = fitMinHessian
			}
			weight[i] = wi
			yi := 0.0
			if y[i] {
				yi = 1
			}
			response[i] = clampWorkingResponse(eta[i] + (yi-p)/wi)
		}
		// ② 组装 Gram 矩阵与右端项（对称，只算下三角再加倍）。
		for j := 0; j < d; j++ {
			rhs[j] = 0
			for k := 0; k < d; k++ {
				gram[j][k] = 0
			}
		}
		for i := 0; i < n; i++ {
			wi, xi, zi := weight[i], X[i], response[i]
			for j := 0; j < d; j++ {
				wx := wi * xi[j]
				rhs[j] += wx * zi
				gram[j][j] += wx * xi[j]
				for k := 0; k < j; k++ {
					gram[j][k] += wx * xi[k]
				}
			}
		}
		for j := 0; j < d; j++ {
			rhs[j] *= invN
			for k := 0; k <= j; k++ {
				gram[j][k] *= invN
				gram[k][j] = gram[j][k]
			}
		}
		// **相对 L2**（本实现相对 brief 示例代码的第二处偏离，理由见 FitOptions.L2 的注释）：
		// 罚项按列信息量归一，即把 G_jj 放缩成 G_jj·(1+l2)，于是坐标解的分母变成
		// G_jj·(1+l2)，l2 对**每一列**都是同一个相对收缩率 1/(1+l2)，
		// 而不是"对信息量小的列罚得更重"。截距列不惩罚。
		// 等价说法：罚的是 ½·l2·G_jj·w_j²（而不是 ½·l2·w_j²）。
		//
		// 为什么必须这样做：本例的 IRLS 权重 W = p(1−p) ≈ 0.21，列又高度共线，
		// 绝对罚项 l2 = 0.01 相当于对每一列收缩 0.21/(0.21+0.01) ≈ 4.8%，
		// 而这 4.8% 会沿共线方向被放大成**耦合系数 +0.14 的系统偏置**（n = 60000 实测 +0.142）。
		// 偏置不随样本量下降，只随 l2 下降（绝对 l2 = 1e-4 时偏置 +0.0003），
		// 因此在"已知 c_ij 必须被近似还原"这条验收上，相对罚项是唯一既保留 L2、又不过度偏置的做法。
		for j := 1; j < d; j++ {
			gram[j][j] *= 1 + l2
		}
		// ③ 坐标下降精确求解该加权最小二乘问题（每轮 O(d²)，可迭代到机器精度）。
		for sweep := 0; sweep < fitMaxInnerSweeps; sweep++ {
			maxDelta := 0.0
			for j := 0; j < d; j++ {
				den := gram[j][j]
				if den <= 0 {
					continue
				}
				partial := rhs[j]
				for k := 0; k < d; k++ {
					if k != j {
						partial -= gram[j][k] * w[k]
					}
				}
				penalty := 0.0
				if j != 0 {
					penalty = l1
				}
				next := softThreshold(partial, penalty) / den
				if delta := math.Abs(next - w[j]); delta > maxDelta {
					maxDelta = delta
				}
				w[j] = next
			}
			if maxDelta < fitInnerTolerance {
				break
			}
		}
		// ④ 外层收敛判据：整轮更新后系数是否已经不动（IRLS 在 10–20 轮内收敛）。
		maxChange := 0.0
		for j := range w {
			if change := math.Abs(w[j] - prev[j]); change > maxChange {
				maxChange = change
			}
		}
		if outer > 0 && maxChange < fitOuterTolerance {
			break
		}
	}
	for j := range w {
		if math.IsNaN(w[j]) || math.IsInf(w[j], 0) {
			w[j] = 0 // 防御：非有限系数绝不能流进参数映射
		}
	}
	return w
}

// clampWorkingResponse 把工作响应 z_i 夹到 ±fitMaxWorkingResponse。
//
// 完全分离的数据会让某个 p_i → 0/1、z_i 冲到 ±1e6 量级；夹一下既保住数值稳定，
// 又不改变正常数据上的结果（正常数据的 |z| 远小于 50）。
func clampWorkingResponse(z float64) float64 {
	if math.IsNaN(z) {
		return 0
	}
	if z > fitMaxWorkingResponse {
		return fitMaxWorkingResponse
	}
	if z < -fitMaxWorkingResponse {
		return -fitMaxWorkingResponse
	}
	return z
}

// sigmoid 是 logistic 函数，对 ±Inf 输入安全（exp 溢出时返回 0 / 1 而不是 NaN）。
func sigmoid(z float64) float64 {
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}

// softThreshold 是 L1 的软阈值算子 S(x, t) = sign(x)·max(|x| − t, 0)。
func softThreshold(x, t float64) float64 {
	if t <= 0 {
		return x
	}
	switch {
	case x > t:
		return x - t
	case x < -t:
		return x + t
	default:
		return 0
	}
}

// dot 是点积（列数远小于样本数，无需分块优化）。
func dot(row, w []float64) float64 {
	sum := 0.0
	for j := range w {
		sum += w[j] * row[j]
	}
	return sum
}

// ============================================================================
// 交叉验证与自助法
// ============================================================================

// crossValidate 返回 k 折交叉验证的平均对数损失（留出法，按样本下标取模切片，顺序稳定）。
//
// 折数 > 样本数在这里再次拒绝（`validateFitRequest` 已拦过一次）：本函数是导出路径上的
// 中间层，返回 0 会被读成"零泛化误差"。
//
// `start` 是热启动向量（全量解）：每折的模型与全量模型同源，从全量解出发能把外层牛顿迭代
// 次数从十几个压到几个，而**不改变解**（求解器从任意起点都收敛到同一个 MLE）。
func crossValidate(X [][]float64, y []bool, opts FitOptions, start []float64) (float64, error) {
	n := len(X)
	folds := opts.Folds
	if folds < 2 {
		folds = fitDefaultFolds
	}
	if n < folds {
		return 0, fmt.Errorf("edgecompare: 折数 %d > 样本数 %d —— 交叉验证无从进行", folds, n)
	}
	total, used := 0.0, 0
	for fold := 0; fold < folds; fold++ {
		var trainX, testX [][]float64
		var trainY, testY []bool
		for i := 0; i < n; i++ {
			if i%folds == fold {
				testX = append(testX, X[i])
				testY = append(testY, y[i])
				continue
			}
			trainX = append(trainX, X[i])
			trainY = append(trainY, y[i])
		}
		if len(trainX) == 0 || len(testX) == 0 {
			continue
		}
		w := fitElasticNet(trainX, trainY, opts.L1, opts.L2, start)
		total += logLoss(w, testX, testY)
		used++
	}
	if used == 0 {
		return 0, fmt.Errorf("edgecompare: 交叉验证没有任何可用折（样本数 %d、折数 %d）", n, folds)
	}
	return total / float64(used), nil
}

// logLoss 是平均对数损失（每样本）。截断概率避免 log(0) 把结果污染成 ±Inf。
func logLoss(w []float64, X [][]float64, y []bool) float64 {
	if len(X) == 0 {
		return 0
	}
	const eps = 1e-12
	total := 0.0
	for i := range X {
		p := sigmoid(dot(X[i], w))
		if y[i] {
			total -= math.Log(p + eps)
		} else {
			total -= math.Log(1 - p + eps)
		}
	}
	return total / float64(len(X))
}

// bootstrapCoefficients 用**有放回重采样**给出每个系数的 95% 百分位区间（brief 给定的 100 次）。
//
// 随机源固定 `rand.NewSource(opts.Seed)`：自助法区间必须可复现（`TestFitIsDeterministic`
// 逐位比对两次拟合的报告）。重采样下标用 `Intn` 逐个抽 —— 不用 `Perm`/`Shuffle`，
// 因为 `Intn` 的消费序列与样本数一一对应，最不容易在重构时被改变。
//
// `start` 是热启动向量（全量解，glmnet 的 CV/自助法同样这么做）：重采样拟合与全量拟合是
// 同一个优化问题的重启，起点只影响收敛速度、不影响解，而 100 次重采样的总耗时因此降一个量级。
//
// **每个重采样样本都先反归一化再取百分位**（Fix round 1 / I1）：重采样是在标准化尺度上求解的，
// 若在该尺度上取百分位，`Bootstrap` 与 `Coefficients`（原始列尺度）量纲不同 —— 报告里区间
// 看着总是包不住系数，"区间是否覆盖真值"这条最有力的无偏性断言也就无从写起。
// 非截距列的反归一化是单调变换（除以正的列尺度），截距列则是各样本独立的线性组合，
// 故一律逐样本换算后再排序取百分位（对线性组合而言，逐样本换算严格正确，先取百分位再换算是错的）。
func bootstrapCoefficients(X [][]float64, y []bool, names []string, opts FitOptions,
	start, means, scales []float64) map[string][2]float64 {
	n := len(X)
	out := make(map[string][2]float64, len(names))
	if n == 0 {
		return out
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	samples := make([][]float64, len(names))
	bx := make([][]float64, n)
	by := make([]bool, n)
	for round := 0; round < fitBootstrapRounds; round++ {
		for i := 0; i < n; i++ {
			k := rng.Intn(n)
			bx[i], by[i] = X[k], y[k]
		}
		raw := denormaliseCoefficients(fitElasticNet(bx, by, opts.L1, opts.L2, start), means, scales)
		for j := range names {
			samples[j] = append(samples[j], raw[j])
		}
	}
	for j, name := range names {
		s := append([]float64(nil), samples[j]...)
		sort.Float64s(s)
		if len(s) == 0 {
			continue
		}
		lo := s[clampIndex(int(math.Floor(0.025*float64(len(s)))), len(s))]
		hi := s[clampIndex(int(math.Ceil(0.975*float64(len(s))))-1, len(s))]
		out[name] = [2]float64{lo, hi}
	}
	return out
}

// clampIndex 把百分位下标夹到 [0, m-1]（小样本 + 少重采样轮次时可能越界）。
func clampIndex(i, m int) int {
	if i < 0 {
		return 0
	}
	if i > m-1 {
		return m - 1
	}
	return i
}

// ============================================================================
// 工具
// ============================================================================

// cloneParams 深拷贝参数集（Factors / Lambda / Vectors / Coupling 全部新建）。
//
// 为什么必须深拷贝：`Fit` 的返回副本会被就地改写（写 Factors 与 Coupling），而基准参数是
// 调用方的财产（CLI 从配置装载、随后还要用）。浅拷贝会让"基准"与"拟合结果"静默变成同一份，
// 且 `TestFitDoesNotMutateBase` 的反向断言（改结果不影响基准）也会一起失败。
func cloneParams(p edgefactor.Params) edgefactor.Params {
	out := p
	if p.Lambda != nil {
		out.Lambda = make(map[string]float64, len(p.Lambda))
		for k, v := range p.Lambda {
			out.Lambda[k] = v
		}
	}
	if p.Vectors != nil {
		out.Vectors = make(map[string]map[string]float64, len(p.Vectors))
		for id, vec := range p.Vectors {
			cp := make(map[string]float64, len(vec))
			for d, v := range vec {
				cp[d] = v
			}
			out.Vectors[id] = cp
		}
	}
	if p.Coupling != nil {
		out.Coupling = make(map[string]map[string]float64, len(p.Coupling))
		for from, tos := range p.Coupling {
			cp := make(map[string]float64, len(tos))
			for to, c := range tos {
				cp[to] = c
			}
			out.Coupling[from] = cp
		}
	}
	if p.Factors != nil {
		out.Factors = make(map[string]float64, len(p.Factors))
		for id, f := range p.Factors {
			out.Factors[id] = f
		}
	}
	return out
}

// ============================================================================
// 报告渲染
// ============================================================================

// RenderFitReport 输出拟合产物的人类可读摘要：交叉验证误差、系数表、自助法区间、
// 折回参数后的取值，以及映射规则的近似性标注。
//
// 输出顺序全部确定（系数表按列名字典序），理由与 Task 9 的报告相同：这段会被 diff、
// 会被写进实验记录，抖动即不可归因。任何一处渲染失败都不得留下半份产物，
// 故本函数先整篇渲染进内存再一次性写出。
func RenderFitReport(w io.Writer, p edgefactor.Params, rep FitReport) error {
	if len(rep.Coefficients) == 0 {
		return fmt.Errorf("edgecompare: 拟合报告里没有任何系数 —— 空表会被误读成『拟合过了』")
	}
	var b strings.Builder
	b.WriteString("# 边缘因子拟合报告\n\n")
	fmt.Fprintf(&b, "交叉验证平均对数损失（k 折）: %.6f\n", rep.CVErr)
	fmt.Fprintf(&b, "模型: %s｜p_floor = %s｜先验边: %s\n\n",
		p.Model, formatParam(p.PFloor), edgeSummary(rep.EdgeCoefficients))

	b.WriteString("| 列 | 系数 β | 自助法 95% 区间 | 折回的参数 |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, name := range sortedNames(rep.Coefficients) {
		ci := rep.Bootstrap[name]
		fmt.Fprintf(&b, "| %s | %s | [%s, %s] | %s |\n",
			escapeCell(name), formatParam(rep.Coefficients[name]),
			formatParam(ci[0]), formatParam(ci[1]), mappedParamLabel(name, p, rep.Coefficients[name]))
	}
	b.WriteString("\n")
	b.WriteString("映射规则（写死，近似性见 fit.go 注释）：主效应 `β_i > 0 ⇒ Factors[i] = clip(1 − β_i, 1e-3, 1)`、")
	b.WriteString("`β_i ≤ 0 ⇒ Factors[i] = 1`；交互 `β_ij > 0 ⇒ Coupling[i][j] = min(β_ij, 1)`、")
	b.WriteString("`β_ij ≤ 0 ⇒ 不写`。该映射是对数优势比尺度的启发式换算，**不是**参数标定；")
	b.WriteString("本轮结论口径限『哪些边显著 + 决策层改善』，标定后置。\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// edgeSummary 给出边列的确定顺序摘要（报告行里只有一行，不能依赖 map 迭代序）。
func edgeSummary(edges map[string]float64) string {
	if len(edges) == 0 {
		return "(无先验边)"
	}
	parts := make([]string, 0, len(edges))
	for _, name := range sortedNames(edges) {
		parts = append(parts, fmt.Sprintf("%s=%s", name, formatParam(edges[name])))
	}
	return strings.Join(parts, " ")
}

// mappedParamLabel 说明某列折回了哪个参数（截距折不出任何参数）。
func mappedParamLabel(name string, p edgefactor.Params, beta float64) string {
	if name == fitInterceptName {
		return "(不映射：截距吸收基线概率)"
	}
	if strings.Contains(name, "|") {
		c, write := couplingFromCoefficient(beta)
		if !write {
			return "coupling 不写（β ≤ 0）"
		}
		return fmt.Sprintf("coupling = %s", formatParam(c))
	}
	return fmt.Sprintf("f_%s = %s", name, formatParam(factorFromCoefficient(beta)))
}
