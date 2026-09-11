//go:build edgeexp

package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 对比层 + 报告渲染 + 参数段导出（spec §2.1 / §5.2 第 4 步）。
//
// 本文件是「离线重算为主」这条对比范式的收口处：`Compare` 在同一份真实数据上评估全部候选并
// 按**决策层主判据**选优，`RenderMarkdown` 把结果落成可入档的对比报告，`RenderConfigSection`
// 把胜出候选的参数导出成能直接粘回 `[edge_factors.model]` 的配置段。
//
// 三者的共同纪律：**任何"看起来有结论、实际没有"的产物都必须变成错误**。空候选集、空报告、
// 与参数集不一致的模型名、漏域的向量 —— 一律 fail-fast，绝不渲染出一份看似完整的产物。

// Report 是一次四候选对比的结果快照。
//
// `Best` 是**模型名**（候选在 paramsByModel 里的键），不是 Params.Model —— 与 RenderConfigSection
// 的第一参数同源，故 `RenderConfigSection(w, rep.Best, paramsByModel[rep.Best])` 是合法调用。
type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Records     int                `json:"records"`
	Models      map[string]Metrics `json:"models"`
	Best        string             `json:"best"`
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
	if len(paramsByModel) == 0 {
		return Report{}, fmt.Errorf("edgecompare: 没有任何候选模型可对比 —— 空对比会产出一张空表外加一个不存在的『选定模型』")
	}
	rep := Report{
		GeneratedAt: time.Now().UTC(),
		Records:     len(records),
		Models:      make(map[string]Metrics, len(paramsByModel)),
	}
	for _, name := range sortedNames(paramsByModel) {
		m, err := Evaluate(records, paramsByModel[name], weights)
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
// 报告"同一输入两次不同"，而这类产物一旦进论文附录就再也无法归因（与 Task 8 的
// weightedSum 定序是同一条纪律）。
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
// 空候选集直接拒绝（而不是打印一张空表）：一份"表头齐全、零行、结论为空"的报告会被误读成
// "比过了"。整篇文档先渲染进内存再一次性写出，故任何校验失败都不会留下半份报告。
func RenderMarkdown(w io.Writer, rep Report) error {
	if len(rep.Models) == 0 {
		return fmt.Errorf("edgecompare: 报告里没有任何候选模型 —— 空表会被误读成『已经比过了』")
	}
	var b strings.Builder
	b.WriteString("# 边缘因子模型对比报告\n\n")
	fmt.Fprintf(&b, "生成时间: %s｜场景数: %d\n\n", rep.GeneratedAt.Format(time.RFC3339), rep.Records)
	b.WriteString("| 模型 | 决策一致率 | 漏判率 | 误阻断率 | Spearman | Kendall | AUC | N |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, name := range sortedNames(rep.Models) {
		m := rep.Models[name]
		fmt.Fprintf(&b, "| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %d |\n",
			escapeCell(name), m.DecisionAgreement, m.FalseNegativeRate, m.FalsePositiveRate,
			m.Spearman, m.Kendall, m.AUC, m.N)
	}
	// 结论行必须把四层判据全写出来（含字典序兜底）：报告读者要能据此复算出 Best，
	// 只写"漏判率 → 误阻断率 → AUC"会让平局情形的结论显得无从解释。
	fmt.Fprintf(&b, "\n**选定模型**: `%s`（判据：漏判率 ↓ → 误阻断率 ↓ → AUC ↑ → 模型名字典序）\n",
		escapeCell(rep.Best))
	_, err := io.WriteString(w, b.String())
	return err
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
	_, err := io.WriteString(w, b.String())
	return err
}

// validateRenderable 是参数段导出前的 fail-fast（错误一律在**写出任何内容之前**返回：
// 半段配置是最容易被误粘的形态）。
//
// 三条规则：
//   - 模型名是四个合法模型之一。解析层 `config.ParseEdgeFactorModel` 只认
//     legacy|vector|graph|chain，写别的进去只会得到一份被拒的配置；
//   - 模型名与 `p.Model` 一致。两者不一致意味着这份段会用模型 A 的名字描述模型 B 的参数，
//     粘回去以后"配置写的"和"离线算的"是两套东西 —— 正是本方向最忌讳的假溯源；
//   - 每个已声明向量都覆盖了**配了 λ 的域**。漏了就是离线重算本身也会被 `Synthesize` 拒绝的
//     参数集（"vector does not cover domain"），补 0 蒙混会得到一份能算但算得不同的配置。
//
// 身份键里出现换行同样拒绝：它会伪造出额外的配置行（`escapeCell` 只覆盖 Markdown 表格）。
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
	if err := validateIdentityKeys(p); err != nil {
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

// validateIdentityKeys 拒绝身份键（因子 ID、域、λ 键）里的换行与空值。
//
// 这些键会直接拼进 `vector.<id>` / `lambda.<d>` / `coupling.<from>.<to>`：含换行的键会**伪造**
// 出额外的配置行，含等号的键会伪造出键值对 —— 生成出来的段与参数集不再对应，而它看起来完全
// 正常。键为空则直接产出畸形键（`vector.`），解析层会拒，但错误信息会指向一个使用者没写过的键。
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
