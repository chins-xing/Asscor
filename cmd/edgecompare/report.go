//go:build edgeexp

package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 对比层 + 报告渲染 + 参数段导出（spec §2.1 / §5.2 第 4 步）。
//
// 本文件是「离线重算为主」这条对比范式的收口处：`Compare` 在同一份真实数据上评估全部候选并
// 按**决策层主判据**选优，`RenderMarkdown` 把结果落成可入档的对比报告，`RenderConfigSection`
// 把胜出候选的参数导出成能直接粘回 `[edge_factors.model]` 的配置段。
//
// 三者的共同纪律：**任何"看起来有结论、实际没有"的产物都必须变成错误**。空候选集、零记录、
// 空报告、与参数集不一致的模型名、漏域的向量、贴不回去的配置段 —— 一律 fail-fast，
// 绝不渲染出一份看似完整的产物。

// WeightSourceCounts 是本次评估里**权重表来源**的分布（Task 3B Fix round 1 / Important 1）。
//
// 为什么必须有它：`-weights` 在记录自带 `observed.effective_weights` 时**不参与计算**（记录赢，
// spec §5.1 前提 2），而它仍是必填参数、仍被逐条校验 —— 没有这两个计数，报告读起来就像
// "这次评估用的是命令行那串权重"。评审实测过：两串比例完全不同的 `-weights` 跑同一份真实记录
// 产出**逐字节相同**的报告，没有任何提示；计划里的复现命令因此会被误读，Task 6 的权重消融
// 实验会被读成"权重无关"。
//
// 它只做**可见性**，不改任何计算 —— 计数与"谁赢"共用同一条判据（`recordCarriesWeights`）。
type WeightSourceCounts struct {
	RecordCarried int `json:"record_carried"` // 取记录自带 observed.effective_weights 的记录数
	Fallback      int `json:"fallback"`       // 回退到 -weights 的记录数
}

// Report 是一次四候选对比的结果快照。
//
// `Best` 是**模型名**（候选在 paramsByModel 里的键），不是 Params.Model —— 与 RenderConfigSection
// 的第一参数同源，故 `RenderConfigSection(w, rep.Best, paramsByModel[rep.Best])` 是合法调用。
type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Records     int                `json:"records"`
	Models      map[string]Metrics `json:"models"`
	Best        string             `json:"best"`

	// WeightSource 是记录集的权重口径分布（`Compare` 填；手搓 Report 留零值 ⇒ 渲染成"未注明"）。
	WeightSource WeightSourceCounts `json:"weight_source"`

	// ThresholdOverride 是本次评估的**阈值覆盖值**（0 = 用每条记录自带的 observed.threshold）。
	//
	// 它必须进报告本体的理由与 `WeightSource` 完全同类：覆盖值一旦生效，报告里的漏判率/误阻断率
	// 就不再是部署判定线下的数字。少了这个字段，一份"敏感性分析"报告与一份"部署口径"报告在
	// 字面上完全一样 —— 而它们会被贴进论文的不同小节。
	ThresholdOverride float64 `json:"threshold_override"`
}

// Compare 在同一份真实数据上评估全部候选，并按决策层主判据选优（spec §2.1）。
//
// **必须走 `Evaluate`**（主控裁定 2）：它是带域覆盖校验的决策层入口。低阶原语
// `OfflineScore`/`OfflineScoreWithWeights` 对"有权重却无观测域分"的记录会照算 —— 缺失域以 0
// 参与聚合却仍占一份权重，静默压低总分并翻转 `acceptable`，而报告上看不出任何异常
// （Task 8 评审 I2）。绕过 Evaluate 就等于把这条校验从对比路径上摘掉，故本函数只用 Evaluate。
//
// 求值顺序按候选**名字典序**（而不是 map 迭代序）：这样多个候选同时失败时报出来的第一个错误
// 也是确定的 —— 同一份输入必须给出同一份报告，包括失败的形态。
func Compare(records []Record, paramsByModel map[string]edgefactor.Params, weights map[string]float64) (Report, error) {
	return CompareWith(records, paramsByModel, weights, EvaluateOptions{})
}

// CompareWith 是带显式覆盖项（阈值，见 `EvaluateOptions`）的对比入口；`Compare` 是它的零值包装。
//
// 覆盖项**必须**写进 `Report.ThresholdOverride`：否则"部署判定线"与"敏感性分析的覆盖线"两份
// 报告在文本上无法区分，而它们会被引用进论文的不同小节（spec §5.4 的敏感性要求）。
func CompareWith(records []Record, paramsByModel map[string]edgefactor.Params, weights map[string]float64,
	opts EvaluateOptions) (Report, error) {
	if len(paramsByModel) == 0 {
		return Report{}, fmt.Errorf("edgecompare: 没有任何候选模型可对比 —— 空对比会产出一张空表外加一个不存在的『选定模型』")
	}
	// 零记录同样必须 fail-fast（Fix round 1 / Important-2 ①）：`Evaluate` 对空输入返回零值
	// Metrics，于是每个候选三层全平、`Best` 只是名字字典序的产物，而报告会照常打印
	// 「场景数: 0」外加一个确定语气的「选定模型」—— 筛选条件写错（路径错、字段改名）时，
	// 操作者与下游产物文件看到的是一份**伪结论**。与"拒空候选集"是同一条纪律：比不了就别给结论。
	if len(records) == 0 {
		return Report{}, fmt.Errorf("edgecompare: 没有有效记录，无法比较 —— 零记录下每个候选的三层指标都是零值，选出来的『最优模型』只会是模型名字典序的产物")
	}
	rep := Report{
		GeneratedAt: time.Now().UTC(),
		Records:     len(records),
		Models:      make(map[string]Metrics, len(paramsByModel)),
		// 权重口径的分布只取决于**记录集**（与候选无关），故在候选循环外算一次：
		// 报告头据此说明"这次用的是记录自带的表还是 `-weights`"（Important 1）。
		WeightSource: countWeightSources(records),
		// 阈值覆盖值同样在候选循环外：它对本报告里的每一个候选都生效（见 Report 的说明）。
		ThresholdOverride: opts.ThresholdOverride,
	}
	for _, name := range sortedNames(paramsByModel) {
		m, err := EvaluateWith(records, paramsByModel[name], weights, opts)
		if err != nil {
			// 错误必须点名候选：四个候选共用同一份数据，只看 "scenario X: ..." 无法判断是
			// 数据有问题还是某个候选的参数有问题。
			return Report{}, fmt.Errorf("edgecompare: 候选 %s: %w", name, err)
		}
		rep.Models[name] = m
	}
	rep.Best = pickBest(rep.Models)
	return rep, nil
}

// pickBest 按**决策层主判据**选优。判据顺序就是下面的分支顺序（主控裁定 4）：
//
//	① `FalseNegativeRate` 低者胜 —— 漏判 = 放行了一个实际被攻陷的场景，代价最高，是主判据；
//	② 平则 `FalsePositiveRate` 低者胜 —— 误阻断 = 阻断了一个实际安全的场景；
//	③ 再平则 `AUC` 高者胜 —— 三层里唯一参与选优的辅助层（数值层）；
//	④ 三层全平 ⇒ 取**模型名字典序**靠前者。
//
// 第 ④ 条的唯一目的是**确定性**：模型是 map，若平局时"谁先遍历到谁胜"，同一份数据两次跑出
// 不同的 `Best` 就无从归因；而报告的用途正是入档与进论文。实现方式上它不需要额外分支 ——
// 先按字典序排好名字、再逐个只接受**严格更优**者，平局时先到者（即字典序靠前者）自然保留。
//
// 各层都是"先比、不等才返回"的短路结构，不存在"某层更差却掉到下一层"的路径。
func pickBest(models map[string]Metrics) string {
	best := ""
	for _, name := range sortedNames(models) {
		if best == "" || better(models[name], models[best]) {
			best = name
		}
	}
	return best
}

// better 报告 a 是否**严格优于** b（三层判据的顺序见 pickBest）。
func better(a, b Metrics) bool {
	if a.FalseNegativeRate != b.FalseNegativeRate {
		return a.FalseNegativeRate < b.FalseNegativeRate
	}
	if a.FalsePositiveRate != b.FalsePositiveRate {
		return a.FalsePositiveRate < b.FalsePositiveRate
	}
	return a.AUC > b.AUC
}

// sortedNames 返回 map 键的字典序切片。
//
// 报告里三处输出（模型表、向量、边）都经它定序：Go 的 map 迭代序随机，直接 range 会让
// 报告"同一输入两次不同"，而这类产物一旦进论文附录就再也无法归因（与重算层"不让 map 迭代序
// 影响分数"是同一条纪律 —— 域分加权求和已在 score.go 按权重键定序后再交给内仓公式）。
func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RenderMarkdown 输出对比表与结论行。
//
// 列序（模型｜决策一致率｜漏判率｜误阻断率｜Spearman｜Kendall｜AUC｜N）与 spec §2.1 的三层指标
// 顺序一致，且**不按选优判据重排**：报告是原始证据，判据顺序已经在结论行里写明。
//
// 表头之前先写两行口径：**判定口径**（C1 第 5 条）—— 离线分数 = 引擎总分（同一公式），阈值 =
// 引擎决策线；**权重口径**（Task 3B Fix round 1 / Important 1）—— N 条取记录自带
// `observed.effective_weights`／M 条回退 `-weights`（回退为 0 时注明"`-weights` 未参与计算"）。
// 这张表的全部价值在于"它描述的是部署行为"，口径不写明就无法被复核 —— 权重口径尤其如此：
// 它决定了读者是否该拿命令行那串权重去核对报告里的分数。
//
// 空候选集直接拒绝（而不是打印一张空表）：一份"表头齐全、零行、结论为空"的报告会被误读成
// "比过了"。整篇文档先渲染进内存再一次性写出，故任何校验失败都不会留下半份报告。
//
// 零记录（Fix round 1 / Important-2 ②）：仍然渲染（表格里每个候选的 N 都是 0，是有效信息），
// 但**不打印任何选模结论** —— 零记录下三层指标全是零值、`Best` 只是名字字典序的产物，
// 打印一个确定语气的「选定模型」就是凭空造结论。这里显式写明"无有效记录、未选模"，并且
// 无视调用方塞进来的 `rep.Best`（`RenderMarkdown` 是导出函数，可能被别的调用方直接喂一份
// 手搓 Report；与 `Compare` 的零记录 fail-fast 是两道独立闸门）。
func RenderMarkdown(w io.Writer, rep Report) error {
	if len(rep.Models) == 0 {
		return fmt.Errorf("edgecompare: 报告里没有任何候选模型 —— 空表会被误读成『已经比过了』")
	}
	var b strings.Builder
	b.WriteString("# 边缘因子模型对比报告\n\n")
	fmt.Fprintf(&b, "生成时间: %s｜场景数: %d\n\n", rep.GeneratedAt.Format(time.RFC3339), rep.Records)
	// 判定口径必须写在报告头上（主控裁定 C1 第 5 条）：这张表里的"分数"与部署引擎的分数是
	// **同一个量**（同一个 `ssam.SSAMV20Formula`），阈值就是引擎的决策线。少了这一行，
	// 读者无法判断报告里的漏判率/误阻断率是不是部署行为 —— 而这正是里程碑 B 的全部意义。
	b.WriteString("判定口径: 离线分数 = 引擎总分（`ssam.SSAMV20Formula`，与在线评分同一公式；")
	b.WriteString("域级修正经 `RegisterDomainAdjust`/`RegisterEdgeFactorStrategy` 注入，legacy 零注册）；")
	b.WriteString("阈值 = 引擎决策线（`Acceptable = 总分 ≥ threshold`）\n\n")
	// 阈值被覆盖时**必须**在报告头点名（spec §5.4 的敏感性分析）：覆盖值一旦生效，表里的
	// 漏判率/误阻断率就不再是部署判定线下的数字，而两份报告在字面上不能长得一样。
	if rep.ThresholdOverride > 0 {
		fmt.Fprintf(&b, "阈值口径: **敏感性分析覆盖值 `-threshold = %.4g`**（记录自带的 `observed.threshold` "+
			"被忽略；这一行**不是**部署判定线下的结果，不得作为选模默认路径的结论）\n\n", rep.ThresholdOverride)
	}
	// 权重口径同样必须写在报告头上（Task 3B Fix round 1 / Important 1）：`-weights` 在记录自带
	// `observed.effective_weights` 时**不参与计算**，而它仍是必填参数 —— 少了这一行，两串比例
	// 完全不同的 `-weights` 会产出**逐字节相同**的报告，计划里的复现命令会被误读、
	// Task 6 的权重消融会被读成"权重无关"。只报事实，不改任何计算。
	switch ws := rep.WeightSource; {
	case ws.RecordCarried+ws.Fallback == 0:
		// 手搓 Report（或未跑过 Compare 的调用方）：**不编** 0/0，如实写"未注明"。
		b.WriteString("权重口径: 未注明（该 Report 未携带权重来源统计）\n\n")
	case ws.Fallback == 0:
		fmt.Fprintf(&b, "权重口径: %d 条取记录自带 `observed.effective_weights`／%d 条回退 `-weights`"+
			"（`-weights` 本次未参与计算）\n\n", ws.RecordCarried, ws.Fallback)
	default:
		fmt.Fprintf(&b, "权重口径: %d 条取记录自带 `observed.effective_weights`／%d 条回退 `-weights`\n\n",
			ws.RecordCarried, ws.Fallback)
	}
	b.WriteString("| 模型 | 决策一致率 | 漏判率 | 误阻断率 | Spearman | Kendall | AUC | N |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, name := range sortedNames(rep.Models) {
		m := rep.Models[name]
		fmt.Fprintf(&b, "| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %d |\n",
			escapeCell(name), m.DecisionAgreement, m.FalseNegativeRate, m.FalsePositiveRate,
			m.Spearman, m.Kendall, m.AUC, m.N)
	}
	if rep.Records == 0 {
		b.WriteString("\n**无有效记录：未选模**（场景数为 0；零记录下三层指标全为零值，")
		b.WriteString("「最优候选」只会是模型名字典序的产物，故不给出结论）\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	// 三层判据全等（主控 I4 第 3 条）：此时 `Best` 只可能来自第四层兜底（模型名字典序），
	// 打印一个确定语气的「选定模型」就是凭空造结论 —— 与零记录分支同款纪律。
	// 判据直接由表格里的指标算出（而不是读一个 `Report` 字段），这样手搓 Report 的调用方
	// 也无法绕过它。
	if allMetricsTied(rep.Models) {
		b.WriteString("\n**本次比较无区分力：未选模**（全部候选的三层判据逐位相同：")
		b.WriteString("漏判率、误阻断率、AUC 全等；此时「最优候选」只会是模型名字典序的产物，故不给出结论）\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	// 结论行必须把四层判据全写出来（含字典序兜底）：报告读者要能据此复算出 Best，
	// 只写"漏判率 → 误阻断率 → AUC"会让平局情形的结论显得无从解释。
	fmt.Fprintf(&b, "\n**选定模型**: `%s`（判据：漏判率 ↓ → 误阻断率 ↓ → AUC ↑ → 模型名字典序）\n",
		escapeCell(rep.Best))
	_, err := io.WriteString(w, b.String())
	return err
}

// allMetricsTied 报告全部候选在**选优判据**上是否完全无法分辨（三层全平）。
//
// 判据就是 `better`（主判据 → 次判据 → AUC）：任意两个候选之间都不存在"严格更优"，
// 于是 `pickBest` 的结果只能来自第四层兜底（模型名字典序）—— 那时打印「选定模型」
// 就是把字典序当结论。
//
// 为什么用 `better` 而不是逐字段 `==`：判据是**分层短路**的。两个候选的排序层
// （Spearman/Kendall）可以不同而三层判据全等；此时选模仍然无据可依，报告同样只能写
// "无区分力"。反过来，只要有一层真的分出高下，`better` 就会为真，结论行照常打印。
//
// 单候选（len < 2）不算平局：那时不存在"比较"，报告里的「选定模型」读作
// "本次只评估了这一个候选"，而不是"它比别的候选更好"。
func allMetricsTied(models map[string]Metrics) bool {
	if len(models) < 2 {
		return false
	}
	names := sortedNames(models)
	for _, name := range names[1:] {
		if better(models[name], models[names[0]]) || better(models[names[0]], models[name]) {
			return false
		}
	}
	return true
}

// escapeCell 把模型名安全地放进 Markdown 表格单元格。
//
// `|` 会截断单元格、换行会截断整行 —— 两者都让报告**静默**错位（列错位、多出一行）而不是报错，
// 而错位的表格会被当成有效报告读下去。参数段的键值同理（换行会造出伪造的配置行），故
// RenderConfigSection 也会在写入前拒绝含换行的身份键。
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}

// RenderConfigSection 输出可直接粘贴的 `[edge_factors.model]` 段（spec §5.2 第 4 步）。
//
// 三个不显然但必须遵守的口径：
//
//  1. **向量必须写满 5 个域**（主控裁定 3）。参数集里的向量是按在线裁剪口径
//     `DefaultDomains ∩ λ` 声明的（只覆盖配了 λ 的域），而粘回去时在线装配期会用**完整**的
//     默认域列表跑 `edgefactor.Validate` —— 少任何一个域都会被拒
//     （`vector %q does not cover domain %q`）。未声明的域补 0：它在在线/离线路径上都会被
//     裁剪掉（不在 λ 里 ⇒ 不进请求域），故补 0 不改变任何口径，只让这份段成为"能被接受"的配置。
//     反过来，若某个**配了 λ 的域**没在向量里声明，这里直接报错（见 validateRenderable）——
//     那是"离线重算本来就跑不起来"的参数集，补 0 会产出一份"看起来能算、算出来不同"的配置。
//  2. **数值用最短往返表示**（`strconv.FormatFloat(v,'g',-1,64)`），不用 `%.4g`：导出段存在的
//     理由是"离线重算可复现"，而 4 位有效数字会把 1/3 写成 0.3333、0.1234567890123 写成
//     0.1235 —— 粘回去的参数与重算用的不再是同一份（`Params.Hash()` 变、分数变）。
//     配置解析侧走 `strconv.ParseFloat`，能逐位读回该表示。
//  3. **模型名必须与参数集一致**且是四个合法模型之一（见 validateRenderable）：否则粘回去的
//     配置要么被解析层拒绝，要么"用一个模型的名字描述另一套参数"。
//
// 输出顺序全部确定（λ 按 DefaultDomains 顺序、向量与边按因子 ID 字典序），因为这段会被 diff、
// 会被写进实验记录：抖动即不可归因。
//
// 已知边界（如实标注，不在本任务修正）：因子权重 f_i 不在本段内 —— 它对内置因子而言的单一事实
// 来源是 `[edge_factors]`（`[edge_factors.model]` 里没有对应的键，`config.ParseEdgeFactorModel`
// 也会拒绝未知键）。故本段覆盖的是**模型级**参数（模型/下限/λ/向量/耦合/窗口），
// 「离线重算可复现」由它们与同一份实验 JSONL 共同保证。
func RenderConfigSection(w io.Writer, model string, p edgefactor.Params) error {
	if err := validateRenderable(model, p); err != nil {
		return err
	}
	domains := edgefactor.DefaultDomains()

	var b strings.Builder
	b.WriteString("[edge_factors.model]\n")
	fmt.Fprintf(&b, "model = %s\n", model)
	fmt.Fprintf(&b, "p_floor = %s\n", formatParam(p.PFloor))
	for _, d := range domains {
		if l, ok := p.Lambda[d]; ok {
			fmt.Fprintf(&b, "lambda.%s = %s\n", d, formatParam(l))
		}
	}
	for _, id := range sortedNames(p.Vectors) {
		parts := make([]string, 0, len(domains))
		for _, d := range domains {
			parts = append(parts, formatParam(p.Vectors[id][d]))
		}
		fmt.Fprintf(&b, "vector.%s = %s\n", id, strings.Join(parts, ","))
	}
	type edge struct{ from, to string }
	var edges []edge
	for _, from := range sortedNames(p.Coupling) {
		for _, to := range sortedNames(p.Coupling[from]) {
			edges = append(edges, edge{from, to})
		}
	}
	for _, e := range edges {
		fmt.Fprintf(&b, "coupling.%s.%s = %s\n", e.from, e.to, formatParam(p.Coupling[e.from][e.to]))
	}
	// 窗口只在非零时输出：`chain.window_seconds` 仅对 chain 语义必需，而 0 会被解析层拒
	// （`must be a positive integer`）——输出一个必然被拒的键等于把这段配置变成废段。
	if p.ChainWindowSeconds > 0 {
		fmt.Fprintf(&b, "chain.window_seconds = %d\n", p.ChainWindowSeconds)
	}
	// 统一断言（Fix round 1 / Important-1）：把**最终要写出去的那串字符**重新解析成配置、
	// 重建参数并跑 Validate(DefaultDomains())，任一环节失败都不得写出任何内容。
	// 这条断言兜住的是"看起来能贴、实际贴不上"的一整类输入（非有限的 p_floor、Σ_d v > 1、
	// 未知 λ 域……）：不必为每个数值字段各写一条规则，也不会漏掉下一个。
	if err := renderRoundTrip(b.String()); err != nil {
		return err
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// renderRoundTrip 把渲染结果喂回**生产解析器与校验层**，证明这段配置真的贴得上。
//
// 三条链路缺一不可，因为在线装配期也正好走这三步：文本 → `config.ParseEdgeFactorModel`
// （`[edge_factors.model]` 的真解析器，含键名/个数/值域校验）→ `edgefactor.Validate(DefaultDomains())`
// （结构规则：p_floor ∈ (0,1)、已声明向量覆盖全部默认域、Σ_d v ≤ 1、λ 域已知、chain 需窗口）。
//
// 重建时**不带 `Factors`**：因子权重 f_i 不在本段内（单一事实来源是 `[edge_factors]`，见
// RenderConfigSection 的已知边界），而 `Validate` 只看已声明的键，nil 的 Factors 不影响它。
// 注意这里刻意**解析文本**而不是边渲染边攒 map：只有把最终的那串字符读回来，才能发现
// "键值拼接出事"这一类错误（例如身份键里混进 `=` ⇒ 配置键被腰斩、值里带上半截键）。
func renderRoundTrip(section string) error {
	sections, err := parseRenderedSections(section)
	if err != nil {
		return err
	}
	cfg, present, err := config.ParseEdgeFactorModel(sections)
	if err != nil {
		return fmt.Errorf("edgecompare: 渲染出的配置段不被 [edge_factors.model] 解析层接受（粘回去必然失败）：%w", err)
	}
	if !present {
		return fmt.Errorf("edgecompare: 渲染结果里没有 [edge_factors.model] 段")
	}
	rebuilt := edgefactor.Params{
		Model:              edgefactor.ModelID(cfg.Model),
		PFloor:             cfg.PFloor,
		Lambda:             cfg.Lambda,
		Vectors:            cfg.Vectors,
		Coupling:           cfg.Coupling,
		ChainWindowSeconds: cfg.ChainWindowSeconds,
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		return fmt.Errorf("edgecompare: 渲染出的配置段过不了 Validate(DefaultDomains())（在线装配期会以同样的理由拒绝它）：%w", err)
	}
	return nil
}

// parseRenderedSections 把渲染出的文本反解成 `config.ParseEdgeFactorModel` 需要的 sections 结构。
// 只处理本文件自己产出的形态（段头 + `key = value`），遇上任何别的行即报错 —— 那意味着渲染
// 出来的东西已经偏离契约，宁可拒绝也不要"读个大概"。
//
// 测试里另有一份独立实现的同名解析（`report_test.go` 的 parseRenderedSection）：那是刻意的
// 第二实现 —— 用它来做格式契约（5 个逗号分隔值、域顺序、逐位数值）的独立核对，
// 避免"拿生产代码的解析器去验证生产代码的输出"这种自证。
func parseRenderedSections(section string) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := ""
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.Trim(line, "[]"))
			if sections[current] == nil {
				sections[current] = map[string]string{}
			}
			continue
		}
		if current == "" {
			return nil, fmt.Errorf("edgecompare: 渲染结果里出现了段外的行 %q", line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("edgecompare: 渲染结果里出现了不是 key = value 的行 %q", line)
		}
		sections[current][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return sections, nil
}

// validateRenderable 是参数段导出前的 fail-fast（错误一律在**写出任何内容之前**返回：
// 半段配置是最容易被误粘的形态）。
//
// 五条规则：
//   - 模型名是四个合法模型之一。解析层 `config.ParseEdgeFactorModel` 只认
//     legacy|vector|graph|chain，写别的进去只会得到一份被拒的配置；
//   - 模型名与 `p.Model` 一致。两者不一致意味着这份段会用模型 A 的名字描述模型 B 的参数，
//     粘回去以后"配置写的"和"离线算的"是两套东西 —— 正是本方向最忌讳的假溯源；
//   - 每个已声明向量都覆盖了**配了 λ 的域**。漏了就是离线重算本身也会被 `Synthesize` 拒绝的
//     参数集（"vector does not cover domain"），补 0 蒙混会得到一份能算但算得不同的配置；
//   - chain 必须有正窗口（Fix round 1 / Important-1）：`chain.window_seconds` 只在 > 0 时输出，
//     而解析层对"缺窗口的 chain"是硬拒（`model=chain requires chain.window_seconds`）、
//     `Validate` 同样要求 > 0 ⇒ 不在这里拦，就会渲染出一份**必然贴不上**的配置段；
//   - λ 与向量的域必须都是**默认域**（见 validateDefaultDomainKeys）：非默认域的键不会被渲染，
//     于是产出的段"能贴、但与参数集不是同一套"。
//
// 数值层面的"贴不上"（非有限 p_floor、Σ_d v > 1 等）不在这里逐项枚举：由
// RenderConfigSection 末尾的 renderRoundTrip 统一兜住。身份键里出现换行同样拒绝
// （它会伪造出额外的配置行；`escapeCell` 只覆盖 Markdown 表格）。
func validateRenderable(model string, p edgefactor.Params) error {
	switch edgefactor.ModelID(model) {
	case edgefactor.ModelLegacy, edgefactor.ModelVector, edgefactor.ModelGraph, edgefactor.ModelChain:
	default:
		return fmt.Errorf("edgecompare: 未知模型 %q（[edge_factors.model] 只接受 legacy|vector|graph|chain）", model)
	}
	if model != string(p.Model) {
		return fmt.Errorf("edgecompare: 渲染的 model = %q 与参数集的 Model = %q 不一致 —— 粘回去的配置会用 %q 的名字描述 %q 的参数",
			model, p.Model, model, p.Model)
	}
	if p.Model == edgefactor.ModelChain && p.ChainWindowSeconds <= 0 {
		return fmt.Errorf("edgecompare: chain 候选的 chain_window_seconds = %d 不是正数 —— 该段缺窗口会被解析层拒绝（model=chain requires chain.window_seconds），粘不回去的配置段不算导出",
			p.ChainWindowSeconds)
	}
	if err := validateDefaultDomainKeys(p); err != nil {
		return err
	}
	if err := validateIdentityKeys(p); err != nil {
		return err
	}
	if err := validateCaseFoldCollisions(p); err != nil {
		return err
	}
	for _, id := range sortedNames(p.Vectors) {
		for _, d := range edgefactor.DefaultDomains() {
			if _, isLambda := p.Lambda[d]; !isLambda {
				continue
			}
			if _, ok := p.Vectors[id][d]; !ok {
				return fmt.Errorf("edgecompare: 向量 %s 未声明域 %q，而该域配了 lambda —— 这套参数在离线重算时会被 Synthesize 拒绝；渲染时补 0 会得到一份『看起来能算、算出来不同』的配置",
					id, d)
			}
		}
	}
	return nil
}

// validateDefaultDomainKeys 要求 λ 的域与向量的域都是**默认域**。
//
// 渲染只输出 `DefaultDomains()` 覆盖到的键（λ 按默认域顺序、向量的每个分量都来自默认域），
// 于是非默认域的键会被**静默丢掉**。这会产出一份"能贴、但与参数集不是同一套"的配置段 ——
// 而这段配置的全部意义就是"贴回去等于刚才算的那套参数"。两条既定路径对这类键都不友好：
// 离线重算的裁剪口径是 `DefaultDomains ∩ λ`（会静默丢掉），在线装配期直接拒绝
// （`lambda for unknown domain`）。生产路径（`ssam.ParamsFromConfig`）本来就不可能产出这类参数，
// 故最诚实的行为是拒绝导出，而不是悄悄少写几行。
func validateDefaultDomainKeys(p edgefactor.Params) error {
	known := map[string]bool{}
	for _, d := range edgefactor.DefaultDomains() {
		known[d] = true
	}
	for _, d := range sortedNames(p.Lambda) {
		if !known[d] {
			return fmt.Errorf("edgecompare: lambda.%s 的域不是默认域 —— 它不会被渲染出去（离线重算会丢掉它、在线装配会直接拒绝），导出的段与参数集将不是同一套", d)
		}
	}
	for _, id := range sortedNames(p.Vectors) {
		for _, d := range sortedNames(p.Vectors[id]) {
			if !known[d] {
				return fmt.Errorf("edgecompare: vector.%s 的分量域 %q 不是默认域 —— 它不会被渲染出去，导出的段与参数集将不是同一套", id, d)
			}
		}
	}
	return nil
}

// validateIdentityKeys 拒绝身份键（因子 ID、域、λ 键）里的换行与空值。
//
// 这些键会直接拼进 `vector.<id>` / `lambda.<d>` / `coupling.<from>.<to>`：含换行的键会**伪造**
// 出额外的配置行，含等号的键会伪造出键值对 —— 生成出来的段与参数集不再对应，而它看起来完全
// 正常。键为空则直接产出畸形键（`vector.`），解析层会拒，但错误信息会指向一个使用者没写过的键。
// validateCaseFoldCollisions 拒绝"仅大小写不同"的重复因子 ID（评审对 Task 9 fix round 1
// 的越界观察 ① 的收口）。
//
// 渲染出去的键会经解析层折叠（配置键大小写不敏感），于是 `EF-A` 与 `ef-a` 会在**重建参数时
// 静默合并成同一个因子**：导出的段与参数集不再是同一套，而 `renderRoundTrip` 抓不到它 ——
// 折叠后的参数各自都合法，断言只证明"这段配置贴得上"，证明不了"贴出来还是同一套参数"。
// 这正是"统一断言只覆盖贴不上、不覆盖贴得上的缺失"这一已知盲区里最可执行的一半。
//
// 检查三处身份键（`vector.<id>` / `coupling.<from>.<to>` / `p.Factors` 的键），因为它们都会被
// 写成配置键。λ 的域不受影响：域名已经由 `validateDefaultDomainKeys` 限定在默认域内。
func validateCaseFoldCollisions(p edgefactor.Params) error {
	seen := map[string]string{} // 折叠后的键 → 首次出现时的原拼写
	check := func(kind, id string) error {
		folded := strings.ToLower(id)
		if prev, ok := seen[kind+"\x00"+folded]; ok && prev != id {
			return fmt.Errorf("edgecompare: %s 的身份键 %q 与 %q 只有大小写不同 —— 配置键大小写不敏感，粘回去会静默合并成同一个因子，导出的段与参数集不再是同一套",
				kind, prev, id)
		}
		seen[kind+"\x00"+folded] = id
		return nil
	}
	for _, id := range sortedNames(p.Vectors) {
		if err := check("vector 因子", id); err != nil {
			return err
		}
	}
	for _, id := range sortedNames(p.Factors) {
		if err := check("因素权重", id); err != nil {
			return err
		}
	}
	for _, from := range sortedNames(p.Coupling) {
		if err := check("coupling 因子", from); err != nil {
			return err
		}
		for _, to := range sortedNames(p.Coupling[from]) {
			if err := check("coupling 因子", to); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateIdentityKeys(p edgefactor.Params) error {
	bad := func(kind, key string) error {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("edgecompare: %s 的身份键为空 —— 会渲染出畸形配置键", kind)
		}
		if strings.ContainsAny(key, "\n\r") {
			return fmt.Errorf("edgecompare: %s 的身份键 %q 含换行 —— 会伪造出额外的配置行", kind, key)
		}
		return nil
	}
	for _, d := range sortedNames(p.Lambda) {
		if err := bad("lambda 域", d); err != nil {
			return err
		}
	}
	for _, id := range sortedNames(p.Vectors) {
		if err := bad("vector 因子", id); err != nil {
			return err
		}
		for _, d := range sortedNames(p.Vectors[id]) {
			if err := bad("vector 域", d); err != nil {
				return err
			}
		}
	}
	for _, from := range sortedNames(p.Coupling) {
		if err := bad("coupling 源因子", from); err != nil {
			return err
		}
		for _, to := range sortedNames(p.Coupling[from]) {
			if err := bad("coupling 目标因子", to); err != nil {
				return err
			}
		}
	}
	return nil
}

// formatParam 用最短往返表示输出参数值（理由见 RenderConfigSection 口径 2）。
func formatParam(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}
