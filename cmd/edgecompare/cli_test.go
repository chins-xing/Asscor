//go:build edgeexp

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// CLI 错误面（mandate 口径 4）
// ============================================================================
//
// `Compare` 与 `RenderConfigSection` 都会**返回错误**（空记录、chain 零窗口、非默认域键、
// 渲染后校验不过等）。CLI 是操作者唯一能看见这些错误的地方，故此处逐条钉住三件事：
//
//	1. 错误一律如实上报（stderr + 非零退出码），不吞；
//	2. **不产出半份产物**：报告与参数段先在内存里全部渲染成功，再一次性写出 ——
//	   "表头齐全但缺参数段"的输出是最容易被误粘/误读的形态；
//	3. 不静默跳过：空/全零权重表、非默认域权重键、无 [edge_factors.model] 段的候选配置
//	   一律拒绝，而不是"降级成某个默认口径继续跑"。

// writeRecordsJSONL 把记录序列化成 spec §5.1 的 JSONL（CLI 走的是真实读取层）。
func writeRecordsJSONL(t *testing.T, name string, recs []Record) string {
	t.Helper()
	var b strings.Builder
	for _, rec := range recs {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		b.Write(raw)
		b.WriteString("\n")
	}
	return writeJSONL(t, name, b.String())
}

// writeConfig 写一个配置 ini 文件（CLI 的候选参数只能来自真实配置）。
func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// runCLIForTest 跑一次 CLI 并返回退出码与两个输出流。
func runCLIForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runCLI(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestCLIRejectsMissingRecordsFlag：-records 是必填项（既有的用法错误面，退出码 2）。
func TestCLIRejectsMissingRecordsFlag(t *testing.T) {
	code, _, stderr := runCLIForTest(t)
	if code != 2 {
		t.Fatalf("退出码 = %d, want 2（用法错误）；stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "-records") {
		t.Errorf("用法错误必须点名 -records：%s", stderr)
	}
}

// TestCLISelfCheckStillWorks：不给新模式开关时仍是数据集自检（Task 8 的既有行为不得回归）。
func TestCLISelfCheckStillWorks(t *testing.T) {
	code, stdout, stderr := runCLIForTest(t, "-records", writeSample(t))
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "记录数: 1") {
		t.Errorf("自检输出丢失：%s", stdout)
	}
}

// TestCLIReportsCompareErrorOnEmptyRecords：零记录时 `Compare` fail-fast，CLI 必须如实报错
// （退出码 1 + stderr 带原因），而不是打印一份"零场景对比报告"。
func TestCLIReportsCompareErrorOnEmptyRecords(t *testing.T) {
	records := writeJSONL(t, "empty.jsonl", "\n\n")
	cfg := writeConfig(t, "cand-legacy.ini", "[edge_factors.model]\nmodel = legacy\np_floor = 0.2\n")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "legacy="+cfg, "-weights", "attack_surface=1", "-factors", "EF-SELINUX=0.8")
	if code != 1 {
		t.Fatalf("退出码 = %d, want 1；stdout=%s stderr=%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "没有有效记录") {
		t.Errorf("stderr 必须转述 Compare 的原因：%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("失败时不得产出任何报告：%s", stdout)
	}
}

// TestCLIRejectsAllZeroWeights：全零权重表会让所有分数恒为 0、决策层指标全部退化为零值，
// 却仍然渲染出一份"看起来比过了"的报告（Task 9 遗留的 minor，交 Task 10 CLI 外层拦）。
// 权重表问题是**命令行输入问题** ⇒ 退出码 2（与"运行期失败"的 1 区分开）。
func TestCLIRejectsAllZeroWeights(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "cand-vector.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	for _, weights := range []string{"attack_surface=0", ""} {
		code, stdout, stderr := runCLIForTest(t,
			"-records", records, "-candidate", "vector="+cfg, "-weights", weights)
		if code != 2 {
			t.Fatalf("-weights %q：退出码 = %d, want 2；stderr=%s", weights, code, stderr)
		}
		if !strings.Contains(stderr, "权重") {
			t.Errorf("-weights %q：stderr 必须说明权重表的问题：%s", weights, stderr)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("-weights %q：失败时不得产出报告：%s", weights, stdout)
		}
	}
}

// TestCLIRejectsNonDefaultWeightDomain：非默认域的权重键不会被渲染/不会被合成层理解，
// 写进权重表只会让"评估口径"与"参数口径"不是同一套 —— 拒绝而不是静默带上。
func TestCLIRejectsNonDefaultWeightDomain(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "cand-vector.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	code, _, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "vector="+cfg, "-weights", "made_up=1")
	if code != 2 || !strings.Contains(stderr, "默认域") {
		t.Fatalf("退出码 = %d, stderr = %s", code, stderr)
	}
}

// TestCLIRejectsCandidateWithoutModelSection：候选参数必须来自真实配置；缺
// `[edge_factors.model]` 段时**不得**静默回落到 legacy。
func TestCLIRejectsCandidateWithoutModelSection(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "no-model.ini", "[weights]\nattack_surface = 35\n")
	code, _, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "x="+cfg, "-weights", "attack_surface=1", "-factors", "EF-SELINUX=0.8")
	if code != 1 {
		t.Fatalf("退出码 = %d, want 1；stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "edge_factors.model") {
		t.Errorf("stderr 必须点名缺失的段：%s", stderr)
	}
}

// TestCLIReportsRenderErrorWithoutPartialOutput：候选参数里的 λ 键落在**非默认域**上时，
// 决策层照常算（裁剪会把该键丢掉），但参数段导出必须拒绝 —— 若 CLI 把报告先写出去再报错，
// 操作者手里就会留下一份"有结论、缺参数段"的文件。
func TestCLIReportsRenderErrorWithoutPartialOutput(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "cand-baddomain.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nlambda.made_up = 0.5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	out := filepath.Join(t.TempDir(), "report.md")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "vector="+cfg, "-weights", "attack_surface=1", "-factors", "EF-SELINUX=0.8", "-out", out)
	if code != 1 {
		t.Fatalf("退出码 = %d, want 1；stdout=%s stderr=%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "made_up") {
		t.Errorf("stderr 必须转述 RenderConfigSection 的原因：%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("失败时不得写任何内容到 stdout：%s", stdout)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(out)
		t.Errorf("失败时不得留下半份产物文件：%v / %q", err, raw)
	}
}

// TestCLICompareWritesReportAndSection：成功路径 —— 报告与参数段一次性写出，且参数段可被
// 生产解析层 + 校验层接受（与 Task 9 的"渲染后重解析"同款断言）。
func TestCLICompareWritesReportAndSection(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "cand-vector.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	out := filepath.Join(t.TempDir(), "report.md")
	code, _, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "vector="+cfg, "-weights", "attack_surface=1", "-factors", "EF-SELINUX=0.8", "-out", out)
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0；stderr=%s", code, stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("读报告：%v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "选定模型") || !strings.Contains(text, "[edge_factors.model]") {
		t.Fatalf("报告或参数段缺失：\n%s", text)
	}
	sections := extractConfigSection(t, text)
	cfgParsed, present, err := config.ParseEdgeFactorModel(sections)
	if err != nil || !present {
		t.Fatalf("导出的参数段不可解析：%v (present=%v)", err, present)
	}
	rebuilt := edgefactor.Params{
		Model:    edgefactor.ModelID(cfgParsed.Model),
		PFloor:   cfgParsed.PFloor,
		Lambda:   cfgParsed.Lambda,
		Vectors:  cfgParsed.Vectors,
		Coupling: cfgParsed.Coupling,
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		t.Fatalf("导出的参数段过不了 Validate：%v", err)
	}
}

// TestCLIFitExportsReparseableSection：-fit 的完整链路（载入基准 → 拟合 → 渲染参数段），
// 产物必须可回填（mandate 口径 5）。
func TestCLIFitExportsReparseableSection(t *testing.T) {
	records := writeRecordsJSONL(t, "syn.jsonl", syntheticRecords(t, 0.4, 7))
	cfg := writeConfig(t, "base.ini",
		"[edge_factors.model]\nmodel = graph\np_floor = 0.5\nlambda.attack_surface = 1\nvector.A = 1,0,0,0,0\nvector.B = 1,0,0,0,0\n")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-fit", "-config", cfg, "-factors", "A=0.5,B=0.5", "-edges", "A|B",
		"-seed", "7", "-folds", "3", "-l2", "0.01")
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "[edge_factors.model]") || !strings.Contains(stdout, "coupling.A.B") {
		t.Fatalf("拟合产物缺少参数段或耦合：\n%s", stdout)
	}
	if !strings.Contains(stdout, "交叉验证") {
		t.Errorf("拟合报告应含交叉验证误差：\n%s", stdout)
	}
	sections := extractConfigSection(t, stdout)
	cfgParsed, present, err := config.ParseEdgeFactorModel(sections)
	if err != nil || !present {
		t.Fatalf("拟合产物不可解析：%v (present=%v)", err, present)
	}
	rebuilt := edgefactor.Params{
		Model:    edgefactor.ModelID(cfgParsed.Model),
		PFloor:   cfgParsed.PFloor,
		Lambda:   cfgParsed.Lambda,
		Vectors:  cfgParsed.Vectors,
		Coupling: cfgParsed.Coupling,
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		t.Fatalf("拟合产物过不了 Validate(DefaultDomains())：%v", err)
	}
}

// TestCLIFitRequiresBaseParams：拟合必须有基准参数（-config + -factors），
// 缺一不可 —— 凭空造一份基准会让拟合结果与任何真实部署都没有关系。
func TestCLIFitRequiresBaseParams(t *testing.T) {
	records := writeRecordsJSONL(t, "syn.jsonl", syntheticRecords(t, 0.4, 7))
	for _, args := range [][]string{
		{"-records", records, "-fit"},
		{"-records", records, "-fit", "-config", writeConfig(t, "base.ini", "[edge_factors.model]\nmodel = graph\np_floor = 0.5\nlambda.attack_surface = 1\nvector.A = 1,0,0,0,0\n")},
	} {
		code, _, stderr := runCLIForTest(t, args...)
		if code != 2 {
			t.Errorf("args=%v：退出码 = %d, want 2（用法错误）；stderr=%s", args, code, stderr)
		}
	}
}

// TestCLIRejectsConflictingModes：-fit 与 -candidate 是两种不同的产物，同时给出即用法错误。
func TestCLIRejectsConflictingModes(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "base.ini",
		"[edge_factors.model]\nmodel = graph\np_floor = 0.5\nlambda.attack_surface = 1\nvector.A = 1,0,0,0,0\n")
	code, _, stderr := runCLIForTest(t,
		"-records", records, "-fit", "-config", cfg, "-factors", "A=0.5",
		"-candidate", "graph="+cfg)
	if code != 2 {
		t.Fatalf("退出码 = %d, want 2；stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "-fit") {
		t.Errorf("用法错误必须点名冲突的开关：%s", stderr)
	}
}

// TestCLIRejectsMalformedCandidateFlag：-candidate 必须是 NAME=PATH。
func TestCLIRejectsMalformedCandidateFlag(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	for _, bad := range []string{"nopath", "=cfg.ini", "a=cfg.ini,b=cfg2.ini=b"} {
		code, _, _ := runCLIForTest(t, "-records", records, "-candidate", bad, "-weights", "attack_surface=1")
		if code != 2 {
			t.Errorf("-candidate %q：退出码 = %d, want 2", bad, code)
		}
	}
}

// ============================================================================
// I4：-factors 的产物纪律（整表为空 / 部分缺失）与"无区分力"的产物纪律
// ============================================================================

// TestCLIRejectsEmptyFactors（主控 I4 第 1 条）：`-factors` 整表为空必须是**用法错误**
// （退出码 2，与 parseWeights 同款纪律），而不是打一行 stderr 警告后照常出报告。
//
// 为什么：`-factors` 是"这套部署的因子权重"的唯一声明面（`[edge_factors.model]` 段里没有
// 对应键），空表意味着候选的因子集合为空 ⇒ 观测链上的**每个**因子都会被丢弃 ⇒ 离线重算
// 退化成"不做任何域级修正"。这样算出来的决策层指标与任何真实部署都没有关系，而报告会以
// 完全正常的语气打印出一份"比过了"的结论。
func TestCLIRejectsEmptyFactors(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	cfg := writeConfig(t, "cand-vector.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	for _, factors := range []string{"", "   "} {
		code, stdout, stderr := runCLIForTest(t,
			"-records", records, "-candidate", "vector="+cfg, "-weights", "attack_surface=1", "-factors", factors)
		if code != 2 {
			t.Fatalf("-factors %q：退出码 = %d, want 2（用法错误）；stderr=%s", factors, code, stderr)
		}
		if !strings.Contains(stderr, "-factors") {
			t.Errorf("-factors %q：stderr 必须点名该开关：%s", factors, stderr)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("-factors %q：失败时不得产出报告：%s", factors, stdout)
		}
	}
	// 正向对照：给出覆盖观测因子的表就照常出报告。
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "vector="+cfg, "-weights", "attack_surface=1",
		"-factors", "EF-SELINUX=0.8")
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "选定模型") {
		t.Errorf("正向对照应产出报告：%s", stdout)
	}
}

// TestCLIRejectsFactorsMissingObservedIDs（主控 I4 第 2 条）：记录里**用到**、而 `-factors`
// 没给权重的因子必须被**列出并拒绝**（退出码 1，与 Compare/Evaluate 的数据类错误同一档），
// 而不是静默丢弃。
//
// 为什么：被丢弃的因子不产生任何惩罚（`engineEdgeFactors` 按候选的因子集合过滤），于是
// 分数被静默抬高、漏判率被低估 —— 而报告里看不出少了一个因子。列出 ID 才能让操作者知道
// 该补哪一行。
func TestCLIRejectsFactorsMissingObservedIDs(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL) // 链条目用的是 EF-SELINUX
	cfg := writeConfig(t, "cand-vector.ini",
		"[edge_factors.model]\nmodel = vector\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-NO-IDS = 0.5,0,0,0,0\n")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "vector="+cfg, "-weights", "attack_surface=1",
		"-factors", "EF-NO-IDS=0.9")
	if code != 1 {
		t.Fatalf("退出码 = %d, want 1；stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "EF-SELINUX") {
		t.Errorf("错误必须列出被丢弃的因子 ID：%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("失败时不得产出报告：%s", stdout)
	}
}

// TestCLIRejectsPartialFactorsInFitMode：同一条纪律在 -fit 模式下也成立（拟合的基准因子
// 集合同样来自 -factors，缺一个就会让该因子在设计矩阵里消失）。
func TestCLIRejectsPartialFactorsInFitMode(t *testing.T) {
	records := writeRecordsJSONL(t, "syn.jsonl", syntheticRecordsN(t, 0.4, 7, 12))
	cfg := writeConfig(t, "base.ini",
		"[edge_factors.model]\nmodel = graph\np_floor = 0.5\nlambda.attack_surface = 1\nvector.A = 1,0,0,0,0\nvector.B = 1,0,0,0,0\n")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-fit", "-config", cfg, "-factors", "A=0.5", "-edges", "A|B")
	if code != 1 {
		t.Fatalf("退出码 = %d, want 1；stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "B") {
		t.Errorf("错误必须列出未声明权重的因子 ID：%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("失败时不得产出产物：%s", stdout)
	}
}

// TestCLIRendersNoSelectionWhenAllCandidatesTie（主控 I4 第 3 条）：三层指标全等时，
// 报告必须打印"本次比较无区分力，未选模"，且**不得**打印 `选定模型` 结论行 —— 与 Task 9
// 对"零记录"的处理同款：比不出来就别给结论，绝不能把名字字典序的产物当成选模结果。
func TestCLIRendersNoSelectionWhenAllCandidatesTie(t *testing.T) {
	records := writeJSONL(t, "t9.jsonl", t9FixtureJSONL)
	// graph 与 chain 在本夹具（单因子、无耦合边）下数学同构 ⇒ 三层指标逐位相同。
	graph := writeConfig(t, "cand-graph.ini",
		"[edge_factors.model]\nmodel = graph\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\n")
	chain := writeConfig(t, "cand-chain.ini",
		"[edge_factors.model]\nmodel = chain\np_floor = 0.2\nlambda.attack_surface = 5\nvector.EF-SELINUX = 0.5,0,0,0,0\nchain.window_seconds = 60\n")
	code, stdout, stderr := runCLIForTest(t,
		"-records", records, "-candidate", "graph="+graph+",chain="+chain,
		"-weights", "attack_surface=1", "-factors", "EF-SELINUX=0.8")
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "无区分力") || !strings.Contains(stdout, "未选模") {
		t.Errorf("全平局必须写明『无区分力、未选模』：\n%s", stdout)
	}
	if strings.Contains(stdout, "**选定模型**:") {
		t.Errorf("全平局不得打印选模结论行：\n%s", stdout)
	}
}

// extractConfigSection 从 CLI 输出里取出参数段（`[edge_factors.model]` 起的全部行）。
func extractConfigSection(t *testing.T, out string) map[string]map[string]string {
	t.Helper()
	idx := strings.Index(out, "[edge_factors.model]")
	if idx < 0 {
		t.Fatalf("输出里没有参数段：\n%s", out)
	}
	sections, err := parseRenderedSections(out[idx:])
	if err != nil {
		t.Fatalf("参数段解析失败：%v", err)
	}
	return sections
}
