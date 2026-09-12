//go:build expr && engine && checks

// Command edgescen 是边缘因子耦合实验（spec §5.1）的**场景采集器**。
//
// 它做三件事，缺一不可：
//
//  1. **注入 + 观测**：取目标机的真实检查结果，按场景规格强制指定检查失败，用**生产同一条**
//     装配链（`internal/engine.Assessor` + ssam 适配器）评分，读出引擎输出的域分、总分、
//     边缘因子观测链与溯源戳；
//  2. **join 客观结果**：解析攻击 harness 产物（`compromised` / `ttc` / `ttps` / `nodes` /
//     `block_effective` + 每个注入检查的时刻），装配成一条 spec §5.1 记录；
//  3. **严格写出**：任何一条生产者自检失败都**不写半条记录**并以非零退出码结束。
//
// 退出码约定（与 `cmd/edgecompare` 同款，脚本据此判失败）：
//
//	0 成功；1 运行期失败（配置/harness 读取失败、装配失败、自检失败、写文件失败）；
//	2 用法错误（缺必填开关、未知场景、-list 之外的参数组合错误）。
//
// 三条纪律贯穿全文件：
//
//  1. **如实采集，不造兜底**：注入时刻缺失、触发检查没注册、引擎没装载模型、链上有惩罚却为空
//     —— 一律报错退出，绝不"降级成某个默认口径继续跑"。一条静默降级的记录比一次失败危险得多：
//     它会以完全正常的语气进入报告与论文证据链。
//  2. **不写半条记录**：整条记录在内存里装配并自检通过之后才追加写出；失败时 `--out` 文件
//     保持原样（既不新建、也不追加）。
//  3. **单份契约**：记录的读写共用 `internal/edgeexp`（生产者与消费者不是两份判据）。
//
// CLI 形状（Task 4 的 `edge_collect.sh` 按它调用）：
//
//	edgescen --scenario S2-selinux-apparmor --config configs/edgeexp/vector.ini \
//	  --attack-out data/edgefactors/attack-S2-selinux-apparmor.json \
//	  --out data/edgefactors/records-wsl-clab-14.jsonl --run 1 --env wsl-clab-14
//
// 构建用的是**最小 tag 集** `expr,engine,checks`（三个都不是可有可无的：`engine` 提供评分链、
// `checks` 提供真实检查登记表、`expr` 是实验工具的构建约束），见 observe.go 的说明。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgeexp"
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

// runCLI 是 CLI 的全部逻辑（输出流可注入，故测试能直接断言 stdout/stderr 与退出码）。
func runCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("edgescen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	scenarioName := fs.String("scenario", "", "场景名（spec §5 矩阵项；见 -list）")
	configPath := fs.String("config", "", "实验配置路径（必须含 [edge_factors.model] 段）")
	attackPath := fs.String("attack-out", "", "攻击 harness 产物 JSON（客观结果 + 每个检查的注入时刻）")
	outPath := fs.String("out", "", "记录输出路径（JSONL，追加写出）")
	runIndex := fs.Int("run", 1, "本次运行的重复号（A-1 每场景 3 次：1..3）")
	envName := fs.String("env", "wsl-clab-14", "环境标识（写进 meta.env，spec §5.3）")
	playbookHash := fs.String("playbook-hash", "", "剧本哈希覆盖（缺省取 harness 产物里的 playbook_hash）")
	listScenarios := fs.Bool("list", false, "列出全部场景（矩阵脚本用）并退出")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *listScenarios {
		printScenarioTable(stdout)
		return exitOK
	}

	// 用法校验先于任何 IO：开关写错时不该先看见"文件打不开"。
	if strings.TrimSpace(*scenarioName) == "" {
		fmt.Fprintln(stderr, "edgescen: -scenario 是必填项（spec §5 的实验矩阵项，见 -list）")
		fs.Usage()
		return exitUsage
	}
	if _, err := lookupScenario(*scenarioName); err != nil {
		fmt.Fprintln(stderr, "edgescen:", err)
		return exitUsage
	}
	for _, required := range []struct {
		value, flag, why string
	}{
		{*configPath, "-config", "实验配置（权重、阈值、边缘因子模型段都来自它）"},
		{*attackPath, "-attack-out", "攻击 harness 产物（客观结果是 join 的另一半，凭空造标签等于伪造证据）"},
		{*outPath, "-out", "记录输出路径"},
	} {
		if strings.TrimSpace(required.value) == "" {
			fmt.Fprintf(stderr, "edgescen: %s 是必填项 —— %s\n", required.flag, required.why)
			fs.Usage()
			return exitUsage
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "edgescen: 装载配置 %s: %v\n", *configPath, err)
		return exitFailure
	}
	gt, err := loadGroundTruth(*attackPath, *scenarioName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}

	rec, err := buildRecord(context.Background(), *scenarioName, cfg, gt, *runIndex)
	if err != nil {
		// 装配失败：转述原因并**不写任何产物**。`meta.assembly_error` 与 error 是同一句话的
		// 两个出口（前者给记录/日志，后者给退出码），故这里两个都打。
		fmt.Fprintln(stderr, err)
		return exitFailure
	}

	// 运行元数据（环境名、配置指纹）只有 CLI 知道，在写出前补进记录；它们都是可选字段，
	// 不参与任何判据，故放在自检之后（自检失败时不会假装记录"已经完整"）。
	rec.Meta.Env = *envName
	hash, err := configHash(*configPath)
	if err != nil {
		// `meta.config_hash` 是溯源注记的锚点（"这份权重从哪来"就指着它）。读不出来时
		// **不能**回落成空串静默写出 —— 一条 config_hash 为空的记录在报告里与"没记"同形，
		// 而它恰恰是唯一能把记录归因到具体配置文件的东西（评审 M8）。
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	rec.Meta.ConfigHash = hash
	if strings.TrimSpace(*playbookHash) != "" {
		rec.Meta.PlaybookHash = strings.TrimSpace(*playbookHash)
	}
	// 防御：装配期记过错的记录绝不允许走到写出口（正常路径上 err != nil 已经返回，
	// 这里是为了让"将来有人在装配后补写"这件事不可能悄悄发生）。
	if rec.Meta.AssemblyError != "" {
		fmt.Fprintf(stderr, "edgescen: 记录带着装配错误，拒绝写出: %s\n", rec.Meta.AssemblyError)
		return exitFailure
	}

	line, err := edgeexp.MarshalRecord(rec)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	if err := appendRecord(*outPath, line); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	printSummary(stdout, rec, *configPath, *outPath, gt)
	return exitOK
}

// appendRecord 把**一整条** JSONL 追加到输出文件（不存在则新建，父目录自动创建）。
//
// 为什么是"先在内存里装配好再追加一行"：`MarshalRecord` 只在全部生产者自检通过后才返回字节，
// 故这次 `Write` 要么完整写入一行、要么根本不发生 —— 不会留下"半条记录"这种最容易被误读的产物。
func appendRecord(path string, line []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("edgescen: 创建输出目录 %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("edgescen: 打开输出文件 %s: %w", path, err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("edgescen: 写记录 %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("edgescen: 关闭输出文件 %s: %w", path, err)
	}
	return nil
}

// configHash 是配置文件的指纹（sha256 前 16 位十六进制）。
//
// 它是溯源注记的锚点（spec §5.1 前提 2）：一份记录的权重口径必须能归因到**具体哪一份配置**，
// 否则"这份权重从哪来"只能靠猜。取文件字节而不是"解析后的结构体"，因为运营者要能拿它去比对
// 文件（含注释与格式）。
//
// 读失败即报错（**不**回落成空串）：调用点刚成功装载过同一路径，此时读不到说明文件在中途被
// 换掉/删掉（或权限变了）—— 那正是一次"配置在采集途中变了"的事故信号，空串会把它伪装成
// "这条记录没记指纹"（评审 M8）。
func configHash(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("edgescen: 读配置 %s 计算指纹: %w（meta.config_hash 是溯源注记的锚点，不得留空）", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16], nil
}

// printSummary 打印自检摘要（场景 / 因子 / 权重来源 / 链条目 ts / 装配错误），让每一轮实验都在
// 日志里留下可核对的痕迹 —— 只有"文件写出来了"不足以说明这次采集是完整的。
//
// "权重来源"与"链条目 ts"两行分别直接打印 `meta.weight_source` / `meta.ts_source`：它们是记录里
// 的那两句话，不是另算的一份 —— 日志与记录因此永远同源。
//
// **为什么 ts 基准必须有自己的一行**（Task 3B Fix round 1 恢复）：它决定这条记录到底带不带时间
// 结构（C ≡ V 还是 C ≠ V）。25 场景 × 3 次的矩阵里，操作者先看摘要、远早于去解析 JSONL ——
// 只在记录里留痕等于"跑完一轮也没人看见"。
func printSummary(stdout io.Writer, rec edgeexp.Record, configPath, outPath string, gt groundTruth) {
	fmt.Fprintf(stdout, "edgescen: 场景 %s（表内共 %d 组场景）\n", rec.ScenarioID, len(scenarios))
	fmt.Fprintf(stdout, "  因子 %d：%s\n", len(rec.Factors), orNone(strings.Join(rec.Factors, ", ")))
	fmt.Fprintf(stdout, "  权重来源：%d 域｜%s\n", len(rec.Observed.EffectiveWeights), rec.Meta.WeightSource)
	fmt.Fprintf(stdout, "  链条目 ts：%s\n", rec.Meta.TSSource)
	fmt.Fprintf(stdout, "  注入：%s；注入时刻：%s\n", rec.Injection, gt.injectionSummary())
	fmt.Fprintf(stdout, "  观测链 %d 条｜失败检查 %d 条｜总分 %.4g（阈值 %.4g，判 %v）｜配置 %s（指纹 %s）\n",
		len(rec.Observed.EdgeFactorChain), len(rec.Observed.Checks),
		rec.Observed.FinalScore, rec.Observed.Threshold, rec.Observed.Acceptable,
		filepath.Base(configPath), rec.Meta.ConfigHash)
	// round-trip 的偏差打出来（自检已在装配点做过：不一致时根本不会走到这里）。
	// 它是 Task 4 门禁②（逐条 |复算 − 记录| == 0）在日志侧的同一份证据。
	fmt.Fprintf(stdout, "  round-trip: 复算 %.4f − 记录 %.4f = %+.4g（容差 %v）\n",
		recomputeFinalScore(rec), rec.Observed.FinalScore, recomputeFinalScore(rec)-rec.Observed.FinalScore, roundTripTolerance)
	fmt.Fprintf(stdout, "  装配错误：%s\n", orNone(rec.Meta.AssemblyError))
	fmt.Fprintf(stdout, "  写出：%s\n", outPath)
}

// printScenarioTable 打印场景表（Task 4 的矩阵脚本据此迭代，避免脚本里再抄一份场景名单 ——
// 两份名单必然漂移，"少场景而人不知"就是这么发生的）。
//
// `级联目标=` 是 Fix round 3 加上的**additive** 字段（本轮评审的第 4 项）：在此之前 harness
// （`edge_attack.sh`）自己维护了一张"哪个场景级联到哪个因子"的表，与这里的 `CascadeTo` 是
// 两份真源 —— 只在一边加场景时，harness 的**相等**断言会拒绝一条完全合法的链。
// 现在把 `CascadeTo` 直接输出给调用方消费，harness 的表退化为"旧二进制时的兜底"。
func printScenarioTable(stdout io.Writer) {
	fmt.Fprintf(stdout, "edgescen: 场景表（%d 组，spec §5：S0–S5 = 22 组 + R = 3 组真实缺失对照）\n", len(scenarios))
	for _, name := range scenarioNames() {
		spec := scenarios[name]
		fmt.Fprintf(stdout, "  %-28s 注入=%-12s 因子=%s", name, spec.injectionKind(), orNone(strings.Join(spec.Factors, ",")))
		if spec.sequential() {
			fmt.Fprintf(stdout, " 阶段=%d", len(spec.Inject))
		}
		if len(spec.RealMissing) > 0 {
			fmt.Fprintf(stdout, " 真实缺失=%s", strings.Join(spec.RealMissing, ","))
		}
		if spec.CascadeTo != "" {
			fmt.Fprintf(stdout, " 级联目标=%s", spec.CascadeTo)
		}
		fmt.Fprintln(stdout)
	}
}

func orNone(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(无)"
	}
	return v
}
