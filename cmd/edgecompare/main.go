//go:build edgeexp

// Command edgecompare 是方向② 的离线重算工具（spec §5.2）。
//
// 三种模式（`runCLI` 是唯一入口，`main` 只负责把退出码交给操作系统）：
//
//	自检（默认，仅 -records）：把实验 JSONL 读进来做数据集自检；
//	对比（-candidate）：在同一份数据上评估候选模型，按决策层主判据选优并导出参数段（Task 9）；
//	拟合（-fit）：在带标签的记录上拟合"主效应 + 先验边"并把结果折回配置段（Task 10）。
//
// 退出码约定（CLI 错误面，Task 10 mandate 口径 4 + 本轮 I4）：
//
//	0 成功；1 运行期失败（读取层 / Compare / RenderConfigSection / Fit 返回的错误，
//	以及 `-factors` 未覆盖记录里用到的因子这类**数据相关**的拒绝）；
//	2 用法错误（缺必填开关、权重表非法、`-factors` 整表为空、-candidate 形式错误、
//	-fit 与 -candidate 冲突）。
//
// 两条纪律贯穿全文件：
//
//  1. **如实报错，不造兜底**：`Compare`（空记录 fail-fast）与 `RenderConfigSection`
//     （chain 零窗口、非默认域键、渲染后重解析校验不过）都会返回错误；CLI 是操作者唯一能
//     看见这些错误的地方，故一律转述到 stderr 并用非零退出码结束，绝不"降级成某个默认口径继续跑"。
//  2. **不产出半份产物**：报告与参数段先在内存里全部渲染成功，再一次性写出（文件或 stdout）。
//     "表头齐全但缺参数段"的输出是最容易被误粘/误读的形态，故失败时 stdout 必须为空、
//     `-out` 指向的文件必须不存在。
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 退出码：与 README/脚本约定一致，不要改动这些数值。
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

// stringList 是可重复开关的值类型（`-candidate` 可以给多次，或一次给逗号分隔的多项）。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// runCLI 是 CLI 的全部逻辑（可注入输出流，故测试能直接断言 stdout/stderr 与退出码）。
func runCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("edgecompare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordsPath := fs.String("records", "", "实验 JSONL 路径（spec §5.1 schema）")
	verbose := fs.Bool("v", false, "逐条打印场景摘要")
	outPath := fs.String("out", "", "产物输出路径（缺省写 stdout）")
	var candidateFlags stringList
	fs.Var(&candidateFlags, "candidate", "候选模型 NAME=CONFIG.INI（可重复；逗号分隔多项）")
	weightsSpec := fs.String("weights", "", "域权重表 domain=w[,...]（对比模式必填）")
	fitMode := fs.Bool("fit", false, "拟合模式：在带标签记录上拟合主效应 + 先验边")
	configPath := fs.String("config", "", "拟合基准配置路径（须含 [edge_factors.model] 段）")
	factorsSpec := fs.String("factors", "", "因子权重 f_i：ID=v[,...]（对比/拟合模式必填；须覆盖记录里用到的全部因子）")
	edgesSpec := fs.String("edges", "", "先验候选边 i|j[,...]（上限 5 条）")
	seed := fs.Int64("seed", fitDefaultSeed, "拟合随机种子（自助法可复现）")
	folds := fs.Int("folds", fitDefaultFolds, "交叉验证折数")
	l2 := fs.Float64("l2", fitDefaultL2, "L2 相对收缩率：标准化后每一列收缩 1/(1+l2)（不是绝对脊参数，见 FitOptions.L2 注释）")
	l1 := fs.Float64("l1", 0, "L1 正则系数（默认 0：稀疏化由先验边集上限承担）")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*recordsPath) == "" {
		fmt.Fprintln(stderr, "edgecompare: -records 是必填项（实验 JSONL 路径）")
		fs.Usage()
		return exitUsage
	}
	// -fit 与 -candidate 是两种不同的产物（拟合参数 vs 候选对比），同时给出会让"这份报告
	// 到底选了谁"无从解释 —— 用法错误，在读取任何文件之前就拒绝。
	if *fitMode && len(candidateFlags) > 0 {
		fmt.Fprintln(stderr, "edgecompare: -fit 与 -candidate 不能同时给出 —— 前者产出拟合参数段，后者产出候选对比报告，混在一起就无法归因")
		return exitUsage
	}

	// 用法校验先于任何 IO：开关写错时不该先看见"文件打不开"。
	var (
		weights map[string]float64
		pairs   []candidateRef
		base    edgefactor.Params
		factors map[string]float64
		edges   [][2]string
	)
	switch {
	case *fitMode:
		if strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*factorsSpec) == "" {
			fmt.Fprintln(stderr, "edgecompare: -fit 需要 -config（基准配置，含 [edge_factors.model] 段）与 -factors（因子权重 f_i）—— 凭空造一份基准会让拟合结果与任何真实部署都没有关系")
			return exitUsage
		}
		var err error
		if factors, err = parseFactors(*factorsSpec); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		// I4 第 1 条在 -fit 模式下的对应面：`parseFactors("")` 返回 nil，而空因子表会让基准
		// 参数集里没有任何因子、设计矩阵只剩截距列 —— 拟合出来的"系数"只是正则项的产物。
		// （上面的开关校验已拦住空串，这里是"解析后仍为空"的第二道防线：`-factors " , "`
		// 这类形式错误由 parseFactors 自己报。）
		if len(factors) == 0 {
			fmt.Fprintln(stderr, "edgecompare: -fit 需要至少一个因子权重（-factors ID=v）—— 空表下设计矩阵只剩截距列")
			return exitUsage
		}
		if edges, err = parseEdges(*edgesSpec); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
	case len(candidateFlags) > 0:
		var err error
		if weights, err = parseWeights(*weightsSpec); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		if pairs, err = parseCandidateFlags(candidateFlags); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		if factors, err = parseFactors(*factorsSpec); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		// I4 第 1 条：整表为空是**用法错误**（与 parseWeights 同款纪律），不再只打一行
		// stderr 警告后照常出报告 —— 空表意味着观测链上的每个因子都被丢弃，离线重算退化
		// 成"不修正任何域分"，而报告会以完全正常的语气打印一份与部署无关的对比结论。
		if len(factors) == 0 {
			fmt.Fprintln(stderr, "edgecompare: -factors 是必填项且不得为空 —— 它是『这套部署的因子权重』的唯一声明面（[edge_factors.model] 段没有对应键）；空表会让观测链上的每个因子都被丢弃、离线重算退化为不修正任何域分，报告里的决策层指标与任何真实部署都没有关系")
			return exitUsage
		}
	}

	records, err := LoadRecords(*recordsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}

	// I4 第 2 条（数据类错误 ⇒ 退出码 1，与 Compare/Evaluate 同档）：`-factors` 必须覆盖记录里
	// **实际用到**的每个因子。少一个就会让该因子被静默丢弃（候选的因子集合就是过滤器），
	// 分数被悄悄抬高、漏判率被低估，而报告里看不出少了谁。两种模式都查。
	if len(factors) > 0 {
		if err := validateFactorsCoverage(records, factors); err != nil {
			fmt.Fprintln(stderr, err)
			return exitFailure
		}
	}

	switch {
	case *fitMode:
		if base, err = loadBaseParams(*configPath); err != nil {
			fmt.Fprintln(stderr, err)
			return exitFailure
		}
		return runFit(records, base, factors, edges,
			FitOptions{L2: *l2, L1: *l1, Folds: *folds, Seed: *seed}, *outPath, stdout, stderr)
	case len(candidateFlags) > 0:
		return runCompare(records, weights, pairs, factors, *outPath, stdout, stderr)
	default:
		return runSelfCheck(records, *verbose, stdout)
	}
}

// ============================================================================
// 自检模式（Task 8 的既有行为，不得回归）
// ============================================================================

func runSelfCheck(records []Record, verbose bool, stdout io.Writer) int {
	compromised, factored, chained := 0, 0, 0
	envs := map[string]int{}
	factors := map[string]int{}
	for _, rec := range records {
		if rec.GroundTruth.Compromised {
			compromised++
		}
		if len(rec.Factors) > 0 {
			factored++
		}
		if len(rec.Observed.EdgeFactorChain) > 0 {
			chained++
		}
		envs[rec.Meta.Env]++
		for _, c := range rec.Observed.EdgeFactorChain {
			factors[edgefactor.NormalizeFactorID(c.Factor)]++
		}
	}

	fmt.Fprintf(stdout, "记录数: %d\n", len(records))
	// 判定口径（主控裁定 C1 第 5 条）：自检打印的 `观测总分`/`判` 是引擎输出的**观测值**；
	// 对比模式的"分数"则是同一条引擎公式的重算结果（见 RenderMarkdown 的表头）。
	fmt.Fprintln(stdout, "判定口径: 观测分数/判定来自引擎输出（`SSAMV20Formula`）；对比模式的离线分数与它同公式同口径")
	fmt.Fprintf(stdout, "客观被攻陷: %d/%d\n", compromised, len(records))
	fmt.Fprintf(stdout, "含因子场景: %d｜含因子链观测: %d\n", factored, chained)
	fmt.Fprintf(stdout, "环境: %s\n", formatCounts(envs))
	fmt.Fprintf(stdout, "因子出现次数: %s\n", formatCounts(factors))
	if verbose {
		fmt.Fprintln(stdout, "\n场景明细:")
		for _, rec := range records {
			fmt.Fprintf(stdout, "  %-28s 阈值=%.4g 观测总分=%.4g 判=%v 攻陷=%v 链=%d 因子=%s\n",
				rec.ScenarioID, rec.Observed.Threshold, rec.Observed.FinalScore,
				rec.Observed.Acceptable, rec.GroundTruth.Compromised,
				len(rec.Observed.EdgeFactorChain), strings.Join(rec.Factors, ","))
		}
	}
	return exitOK
}

// ============================================================================
// 对比模式（Task 9）
// ============================================================================

// runCompare 评估全部候选、按决策层主判据选优、导出胜出候选的参数段。
//
// 失败路径的纪律：`Compare` 与 `RenderConfigSection` 的错误一律如实转述（退出码 1），
// 且**在渲染全部成功之前不写任何东西** —— 失败时 stdout 为空、`-out` 文件不存在。
func runCompare(records []Record, weights map[string]float64, pairs []candidateRef,
	factors map[string]float64, outPath string, stdout, stderr io.Writer) int {

	paramsByModel := make(map[string]edgefactor.Params, len(pairs))
	for _, ref := range pairs {
		p, err := loadCandidateParams(ref)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitFailure
		}
		// -factors 是**显式**输入的因子权重（f_i）。CLI 刻意不读 [edge_factors]：
		// 内置因子 ID ↔ 配置字段的映射唯一事实来源是引擎的带 tag 适配层
		// （internal/engine/ssam，离线工具不能 import 它），在这里重抄一份就成了第二份真相。
		//
		// 空表已在 runCLI 处以用法错误拒绝（I4 第 1 条），故这里不再有"警告 + 照常出报告"
		// 的退化路径。
		if p.Factors == nil {
			p.Factors = make(map[string]float64, len(factors))
		}
		for id, f := range factors {
			p.Factors[id] = f
		}
		paramsByModel[ref.name] = p
	}

	rep, err := Compare(records, paramsByModel, weights)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	// `-weights` 是**回退表**（Task 3B）：记录自带 `observed.effective_weights` 时它根本不参与
	// 计算。全部记录都自带时在 stderr 上说一句 —— 否则"改了 `-weights` 报告一字不变"没有任何
	// 提示（评审实测：两串比例完全不同的 `-weights` 产出逐字节相同的报告），计划里的复现命令
	// 会被误读成"这次用的是那串权重"，Task 6 的权重消融实验会被读成"权重无关"。
	// 报告头另有一行写明分布（`RenderMarkdown`），这里只是把"未被用到"这件事显式化。
	if rep.WeightSource.Fallback == 0 && rep.WeightSource.RecordCarried > 0 {
		fmt.Fprintf(stderr, "edgecompare: -weights 本次未参与计算（%d 条记录全部自带 observed.effective_weights，权重口径以记录为准）\n",
			rep.WeightSource.RecordCarried)
	}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	buf.WriteString("\n")
	if err := RenderConfigSection(&buf, rep.Best, paramsByModel[rep.Best]); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	if err := emit(outPath, buf.Bytes(), stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	return exitOK
}

// ============================================================================
// 拟合模式（Task 10）
// ============================================================================

func runFit(records []Record, base edgefactor.Params, factors map[string]float64,
	edges [][2]string, opts FitOptions, outPath string, stdout, stderr io.Writer) int {

	if base.Factors == nil {
		base.Factors = make(map[string]float64, len(factors))
	}
	for id, f := range factors {
		base.Factors[id] = f
	}
	opts.PriorEdges = edges
	fitted, rep, err := Fit(records, base, opts)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	var buf bytes.Buffer
	if err := RenderFitReport(&buf, fitted, rep); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	buf.WriteString("\n")
	// 拟合产物的**唯一用途**是回填：这里直接走 Task 9 的导出器（它本身带"渲染后重解析 + Validate"
	// 的断言），故写出来的段一定贴得回去；一旦贴不回去就报错而不是输出半份产物。
	if err := RenderConfigSection(&buf, string(fitted.Model), fitted); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	if err := emit(outPath, buf.Bytes(), stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	return exitOK
}

// emit 一次性写出产物：`-out` 为空时写 stdout，否则**新建/覆盖**该文件。
//
// 只在调用方整篇渲染成功之后调用 —— 这样任何失败路径都不会留下半份产物文件。
func emit(outPath string, data []byte, stdout io.Writer) error {
	if strings.TrimSpace(outPath) == "" {
		_, err := stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return fmt.Errorf("edgecompare: 写产物 %s: %w", outPath, err)
	}
	return nil
}

// loadBaseParams 装载拟合基准参数（生产解析层 + 结构校验**不在此处**：`Fit` 会先按
// `DefaultDomains ∩ λ` 裁剪再 `Validate`，避免在这里重复一遍域口径）。
func loadBaseParams(path string) (edgefactor.Params, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return edgefactor.Params{}, fmt.Errorf("edgecompare: 装载基准配置 %s: %w", path, err)
	}
	if cfg.EdgeFactorModel.Model == "" {
		return edgefactor.Params{}, fmt.Errorf("edgecompare: 配置 %s 缺少 [edge_factors.model] 段 —— 拟合基准必须来自真实配置，不得静默回落到 legacy", path)
	}
	m := cfg.EdgeFactorModel
	return edgefactor.Params{
		Model:              edgefactor.ModelID(m.Model),
		PFloor:             m.PFloor,
		Lambda:             m.Lambda,
		Vectors:            m.Vectors,
		Coupling:           m.Coupling,
		ChainWindowSeconds: m.ChainWindowSeconds,
	}, nil
}

// loadCandidateParams 装载一个候选模型参数集（同样走生产解析层）。
func loadCandidateParams(ref candidateRef) (edgefactor.Params, error) {
	cfg, err := config.Load(ref.path)
	if err != nil {
		return edgefactor.Params{}, fmt.Errorf("edgecompare: 候选 %s: 装载配置 %s: %w", ref.name, ref.path, err)
	}
	if cfg.EdgeFactorModel.Model == "" {
		return edgefactor.Params{}, fmt.Errorf(
			"edgecompare: 候选 %s 的配置 %s 缺少 [edge_factors.model] 段 —— 候选参数必须来自真实配置，不得静默回落到 legacy", ref.name, ref.path)
	}
	m := cfg.EdgeFactorModel
	return edgefactor.Params{
		Model:              edgefactor.ModelID(m.Model),
		PFloor:             m.PFloor,
		Lambda:             m.Lambda,
		Vectors:            m.Vectors,
		Coupling:           m.Coupling,
		ChainWindowSeconds: m.ChainWindowSeconds,
	}, nil
}

// ============================================================================
// 开关解析（全部是**用法错误** ⇒ 退出码 2）
// ============================================================================

// candidateRef 是一个 NAME=CONFIG.INI 形式的候选。
type candidateRef struct{ name, path string }

// parseCandidateFlags 解析 `-candidate`（可重复；单个值可用逗号分隔多项）。
//
// 形式错误必须是用法错误：把 `nopath` 当成路径去打开会报"文件不存在"，
// 而那会让操作者去查文件而不是查自己的命令行。
func parseCandidateFlags(values []string) ([]candidateRef, error) {
	var out []candidateRef
	seen := map[string]bool{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, fmt.Errorf("edgecompare: -candidate %q 里有空项（应为 NAME=CONFIG.INI）", value)
			}
			name, path, ok := strings.Cut(item, "=")
			name, path = strings.TrimSpace(name), strings.TrimSpace(path)
			if !ok || name == "" || path == "" || strings.Contains(path, "=") {
				return nil, fmt.Errorf("edgecompare: -candidate %q 不是 NAME=CONFIG.INI 形式", item)
			}
			if seen[name] {
				return nil, fmt.Errorf("edgecompare: 候选名 %q 重复 —— 同名候选会在报告里互相覆盖", name)
			}
			seen[name] = true
			out = append(out, candidateRef{name: name, path: path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// parseWeights 解析域权重表。
//
// 三条拒绝（Task 9 遗留的 minor 交 Task 10 CLI 外层拦）：
//   - 空表：所有分数恒为 0、决策层指标全部退化为零值，却仍会渲染出一份"看起来比过了"的报告；
//   - 全零表：同上；
//   - 非默认域的键：它不会被合成层理解，写进权重表只会让"评估口径"与"参数口径"不是同一套。
//
// 一律**拒绝**而不是"降级成某个默认口径继续跑"。
func parseWeights(spec string) (map[string]float64, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("edgecompare: -weights 是必填项且不得为空 —— 空权重表会让所有分数恒为 0、决策层指标全部退化为零值，却仍会渲染出一份『看起来比过了』的报告")
	}
	known := map[string]bool{}
	for _, d := range edgefactor.DefaultDomains() {
		known[d] = true
	}
	out := map[string]float64{}
	for _, item := range strings.Split(trimmed, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("edgecompare: -weights %q 里有空项（应为 domain=weight）", spec)
		}
		domain, raw, ok := strings.Cut(item, "=")
		domain, raw = strings.TrimSpace(domain), strings.TrimSpace(raw)
		if !ok || domain == "" || raw == "" {
			return nil, fmt.Errorf("edgecompare: -weights %q 不是 domain=weight 形式", item)
		}
		if !known[domain] {
			return nil, fmt.Errorf("edgecompare: -weights 里的域 %q 不是默认域（%s）—— 非默认域的权重键不会被合成层理解，评估口径与参数口径会变成两套",
				domain, strings.Join(edgefactor.DefaultDomains(), ","))
		}
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return nil, fmt.Errorf("edgecompare: -weights %s = %q 不是非负数字", domain, raw)
		}
		out[domain] = f
	}
	positive := false
	for _, w := range out {
		if w > 0 {
			positive = true
		}
	}
	if !positive {
		return nil, fmt.Errorf("edgecompare: -weights 全为零 —— 全零权重表会让所有分数恒为 0、决策层指标全部退化为零值，却仍会渲染出一份『看起来比过了』的报告")
	}
	return out, nil
}

// parseFactors 解析因子权重表 `ID=v[,...]`（空串合法：表示不提供）。
//
// 值域与 `edgefactor.Validate` 对齐（f ∈ (0,1]）：越界值会被 `Synthesize` 拒绝，
// 提前在命令行拦下来能让操作者少一次"跑到一半才报错"。
func parseFactors(spec string) (map[string]float64, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	out := map[string]float64{}
	for _, item := range strings.Split(trimmed, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("edgecompare: -factors %q 里有空项（应为 ID=value）", spec)
		}
		id, raw, ok := strings.Cut(item, "=")
		id, raw = strings.TrimSpace(id), strings.TrimSpace(raw)
		if !ok || id == "" || raw == "" {
			return nil, fmt.Errorf("edgecompare: -factors %q 不是 ID=value 形式", item)
		}
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1 {
			return nil, fmt.Errorf("edgecompare: -factors %s = %q 不在 (0,1] 内（Validate 会以同样的理由拒绝它）", id, raw)
		}
		out[edgefactor.NormalizeFactorID(id)] = f
	}
	return out, nil
}

// parseEdges 解析先验候选边 `i|j[,...]`（空串合法：表示不提供先验边）。
//
// 上限校验留给 `Fit`（它才是边集语义的归属地）：这里只做**形式**校验。
func parseEdges(spec string) ([][2]string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	out := make([][2]string, 0, strings.Count(trimmed, ",")+1)
	for _, item := range strings.Split(trimmed, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("edgecompare: -edges %q 里有空项（应为 i|j）", spec)
		}
		from, to, ok := strings.Cut(item, "|")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" || strings.Contains(to, "|") {
			return nil, fmt.Errorf("edgecompare: -edges %q 不是 i|j 形式", item)
		}
		out = append(out, [2]string{from, to})
	}
	return out, nil
}

// validateFactorsCoverage 校验 `-factors` 覆盖了记录里**实际用到**的每个因子 ID（I4 第 2 条）。
//
// 为什么必须拒绝而不是静默丢弃：候选模型的因子集合（`Params.Factors`）同时也是
// `engineEdgeFactors` 的过滤器 —— 链上出现、却没在 `-factors` 里声明权重的因子会被丢掉，
// 于是它**不产生任何惩罚**，分数被悄悄抬高、漏判率被低估（偏保守的一侧，但同样失真），
// 而报告里完全看不出少了一个因子。
//
// 错误列出**具体 ID**（按字典序，确定性）：操作者要能直接照着补一行，而不是去猜哪个因子
// 没被建模。空表由上层的用法错误拦下（退出码 2），这里只处理"部分缺失"（数据类错误，退出码 1）。
func validateFactorsCoverage(records []Record, factors map[string]float64) error {
	missing := map[string]bool{}
	for _, rec := range records {
		for _, c := range rec.Observed.EdgeFactorChain {
			id := edgefactor.NormalizeFactorID(c.Factor)
			if id == "" {
				continue // 空 ID 已在读取层按行拒绝，这里只是防御
			}
			if _, ok := factors[id]; !ok {
				missing[id] = true
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	ids := make([]string, 0, len(missing))
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Errorf("edgecompare: -factors 未覆盖记录里用到的因子 %s —— 未声明权重的因子会被静默丢弃（不产生任何惩罚），"+
		"分数被抬高、漏判率被低估，而报告里看不出少了一个因子；请为它们补上 f_i 或确认这些条目不该出现在链上",
		strings.Join(ids, ", "))
}

// formatCounts 以稳定的字典序输出计数表（报告/日志必须可复现，不能依赖 map 迭代序）。
func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "(无)"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			k = "(未填写)"
		}
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}
