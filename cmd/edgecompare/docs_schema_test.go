//go:build edgeexp

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// spec §5.1 示例记录 ↔ 读取层的契约门禁
// ============================================================================
//
// **为什么要这条门禁**：C1 裁定给 `observed` 加了两个必填字段（`spc_score` / `threat_coeff`），
// 读取层随即开始对它们的**存在性**fail-fast —— 而 spec §5.1 里的示例记录当时没同步，
// 于是**规范自己给的样例会被自己的读取层拒绝**。这不是笔误级的文档问题：里程碑 B 的采集器
// 是照着 §5.1 写的，若示例与读取层不一致，采集器落地的第一天就会产出"一条都读不进来"的数据集，
// 而离线重算的门禁全绿（因为根本没读到记录）。
//
// 故把这条契约变成可执行的：直接解析设计文档里的示例记录，喂给**真实的** `LoadRecords`。
// 文档与读取层任何一侧漂移，这条测试就红。
//
// 反向对照（有牙齿的证明）：把示例里的必填项抹掉后，读取层**必须**拒绝、且理由必须是"缺失"
// —— 否则本测试只证明"某个 JSON 能读进来"，而不能证明它在守这些字段的存在性（详见测试内注释）。

const designDocPath = "../../docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md"

// compactLine 把 §5.1 里**缩进打印**的示例压成 JSONL 的真实形态（一条记录一行）。
//
// 压缩只动结构空白、不动字符串内容；示例本身不合法 JSON 时直接 fail（那是文档坏了）。
func compactLine(t *testing.T, sample string) string {
	t.Helper()
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, []byte(sample)); err != nil {
		t.Fatalf("§5.1 的示例不是合法 JSON（连读取层之前的解析都过不了）: %v", err)
	}
	return compacted.String()
}

// extractSection51Sample 取 §5.1 标题之后第一个 ```json 围栏的内容。
func extractSection51Sample(t *testing.T, doc string) string {
	t.Helper()
	sec := strings.Index(doc, "### 5.1 ")
	if sec < 0 {
		t.Fatalf("%s: 找不到 §5.1 标题（文档结构变了？）", designDocPath)
	}
	rest := doc[sec:]
	open := strings.Index(rest, "```json")
	if open < 0 {
		t.Fatalf("%s §5.1: 找不到 ```json 围栏", designDocPath)
	}
	rest = rest[open+len("```json"):]
	closeIdx := strings.Index(rest, "```")
	if closeIdx < 0 {
		t.Fatalf("%s §5.1: json 围栏没有闭合", designDocPath)
	}
	return strings.TrimSpace(rest[:closeIdx])
}

// TestSpecSection51SampleIsAcceptedByLoader 锁定「spec 示例 == 读取层可接受的记录」。
func TestSpecSection51SampleIsAcceptedByLoader(t *testing.T) {
	raw, err := os.ReadFile(designDocPath)
	if err != nil {
		t.Fatalf("读设计文档: %v", err)
	}
	sample := extractSection51Sample(t, string(raw))
	if !strings.HasPrefix(sample, "{") {
		t.Fatalf("§5.1 的 json 围栏内容不像一条记录:\n%s", sample)
	}
	oneLine := compactLine(t, sample)

	recs, err := LoadRecords(writeJSONL(t, "spec51.jsonl", oneLine+"\n"))
	if err != nil {
		t.Fatalf("spec §5.1 的示例记录被读取层拒绝 —— 文档与 load.go 已漂移，采集器照此实现会一条都读不进来:\n%v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("期望 1 条记录，得到 %d 条", len(recs))
	}

	// 不只断言"能读"，还钉住两个 C1 新增必填项确实**在示例里被写出来**（而不是靠零值蒙混）。
	//
	// 存在性标记是 `internal/edgeexp` 的非导出字段，跨包只能经只读访问器读
	// （`SPCScoreSet()` 等；口径由 `internal/edgeexp` 的
	// `TestExistenceAccessorsMirrorJSONPresence` 单独钉住）。除此之外本测试一个字都没改。
	r := recs[0]
	if r.ScenarioID == "" || !r.Observed.SPCScoreSet() || !r.Observed.ThreatCoeffSet() {
		t.Fatalf("示例记录缺少 scenario_id / spc_score / threat_coeff: id=%q spcSet=%v threatSet=%v",
			r.ScenarioID, r.Observed.SPCScoreSet(), r.Observed.ThreatCoeffSet())
	}
	if len(r.Observed.EdgeFactorChain) == 0 {
		t.Fatal("示例记录的 edge_factor_chain 为空 —— 链上字段（c_trigger/effective_factor）的存在性契约就没被覆盖")
	}
	for i, c := range r.Observed.EdgeFactorChain {
		if !c.CTriggerSet() || !c.EffectiveFactorSet() {
			t.Fatalf("edge_factor_chain[%d] 缺 c_trigger/effective_factor", i)
		}
	}

	// 反向对照：抹掉 C1 新增的**两个**必填项后必须被拒，且拒绝理由必须指向「缺失」（存在性
	// 检查），而不是「存在但越界」（值域检查）。
	//
	// 这个区分是刻意的、也是实测出来的：只断言"错误串里出现字段名"的版本在**读取层悄悄放宽
	// 存在性校验**时依然是绿的 —— `spc_score` 缺失会读成 0，随后仍被值域检查（`0 ∉ (0,1]`）
	// 拦下，错误串里照样有 `spc_score` 字样。那样的反向对照只证明了"零值非法"，证明不了
	// "缺失被拒"，也就守不住里程碑 B 采集器的契约。
	for _, tc := range []struct {
		name   string
		field  *regexp.Regexp // 在压缩后的行内定位该字段（**与取值无关**：示例改数值不应让门禁误报）
		needle string         // 必须出现在错误串里的「缺失」判据
	}{
		{"spc_score", regexp.MustCompile(`"spc_score":[0-9.]+,`), "spc_score: missing"},
		{"threat_coeff", regexp.MustCompile(`"threat_coeff":[0-9.]+,`), "threat_coeff: missing"},
	} {
		broken := tc.field.ReplaceAllString(oneLine, "")
		if broken == oneLine {
			t.Fatalf("压缩后的示例里找不到 %s，无法构造反向对照（示例改过？）", tc.name)
		}
		_, err := LoadRecords(writeJSONL(t, "spec51-broken-"+tc.name+".jsonl", broken+"\n"))
		if err == nil {
			t.Fatalf("抹掉 %s 后读取层仍然接受 —— 本门禁没有守到该字段", tc.name)
		}
		if !strings.Contains(err.Error(), tc.needle) {
			t.Fatalf("抹掉 %s 后读取层拒绝了，但理由不是『缺失』——存在性校验可能已被放宽，只是被值域检查兜住: %v", tc.name, err)
		}
	}
}

// specSampleLegacyCandidate 是"示例记录是在哪个候选下产生的"的可执行说明：出厂 legacy 权重
// （`configs/config.ini` 的 `EF-SELINUX = 0.80` / `EF-APPARMOR = 0.82`）。
//
// 为什么必须显式写出候选：离线重算的惩罚集是**候选声明的因子集**，不是记录里的因子集 ——
// 未在候选里声明的因子会被**静默丢掉**（实测：只声明 EF-SELINUX 时同一条记录算出 84.68，
// 声明两个才是 80.02）。这正是 CLI 的 `-factors` 覆盖校验要拦的那类静默偏差，故示例的
// round-trip 只有在"候选与记录因子集一致"时才有定义。
func specSampleLegacyCandidate() edgefactor.Params {
	return edgefactor.Params{
		Model:  edgefactor.ModelLegacy,
		PFloor: 0.5,
		Factors: map[string]float64{
			"EF-SELINUX":  0.80,
			"EF-APPARMOR": 0.82,
		},
	}
}

// equalDomainWeights 是全部默认域各一份权重（引擎的加权平均退化为等权平均）。
func equalDomainWeights() map[string]float64 {
	w := map[string]float64{}
	for _, d := range edgefactor.DefaultDomains() {
		w[d] = 1
	}
	return w
}

// TestSpecSection51SampleRoundTripsThroughEngineFormula 锁定"示例记录自洽"。
//
// 这条测试有**双重**作用：
//  1. 落地 §5.1 里那句 round-trip 承诺 —— 示例的 `final_score` 必须能被 `cmd/edgecompare`
//     用记录自身的输入（域分 + `spc_score`/`threat_coeff` + 链上 `effective_factor`）复算出来。
//     评审实测旧示例的 69.4 **在任何合法权重下都不可能**（base 是域分加权平均 ⇒ 与权重无关地
//     ∈[55,82]，再乘因子、代入 `round2(0.5·base+30·E+20·T)` 后落在 [78.45,89.52]），而当时
//     的门禁只查"能不能解析"，抓不到数值自相矛盾 —— 里程碑 B 的采集器照抄就会产出一批
//     与引擎对不上的记录。
//  2. 钉住三处"示例必须自洽"的口径：因子 ID 必须是**规范 ID**（`EF-SELINUX` 而非展示名
//     `selinux_disabled` —— 写错会让离线查不到 `Vectors` 而静默走"全 1"fallback，改变 V/G/C
//     惩罚强度）；`trigger_check` 必须与出厂触发表一致（`EF-SELINUX`/`EF-APPARMOR` 共用
//     `OT-005`，评审实测旧示例写的 `OT-007` 与出厂表、与本文档附录三处不符）；
//     `acceptable` 必须等于 `final_score ≥ threshold`。
func TestSpecSection51SampleRoundTripsThroughEngineFormula(t *testing.T) {
	raw, err := os.ReadFile(designDocPath)
	if err != nil {
		t.Fatalf("读设计文档: %v", err)
	}
	recs, err := LoadRecords(writeJSONL(t, "spec51-roundtrip.jsonl",
		compactLine(t, extractSection51Sample(t, string(raw)))+"\n"))
	if err != nil {
		t.Fatalf("spec §5.1 示例被读取层拒绝: %v", err)
	}
	rec := recs[0]
	cand := specSampleLegacyCandidate()
	triggers := config.DefaultEdgeFactorTriggerMap()

	// (a) 因子 ID 规范 + 触发检查与出厂表一致 + 链上因子确实在候选里声明。
	seen := map[string]bool{}
	for _, id := range rec.Factors {
		if edgefactor.NormalizeFactorID(id) != id {
			t.Errorf("factors 里的 %q 不是规范因子 ID（规范形为 %q）—— 采集器照抄会让离线静默改变惩罚强度",
				id, edgefactor.NormalizeFactorID(id))
		}
		if _, ok := cand.Factors[id]; !ok {
			t.Errorf("factors 里的 %q 未在示例候选里声明 —— 离线会**静默丢掉**它的惩罚（这就是 round-trip 口径的一部分）", id)
		}
		seen[id] = true
	}
	// 触发检查必须在 checks[] 里以"失败"出现（`c_trigger > 0` 时）——这是因子被激活的原因本身
	// （引擎按"触发检查失败"激活因子）。**`c_trigger = 0` 必须豁免**：那是"仅由级联激活、
	// 自身触发检查未失败"的既有形态（`EF-3FA → EF-002FA`，spec §5 的 S5 组），此时该检查
	// 本来就不该失败。
	failedChecks := map[string]bool{}
	for _, ck := range rec.Observed.Checks {
		if !ck.Passed {
			failedChecks[ck.ID] = true
		}
	}
	for i, c := range rec.Observed.EdgeFactorChain {
		if edgefactor.NormalizeFactorID(c.Factor) != c.Factor {
			t.Errorf("edge_factor_chain[%d].factor = %q 不是规范因子 ID", i, c.Factor)
		}
		if !seen[c.Factor] {
			t.Errorf("edge_factor_chain[%d].factor = %q 不在 factors 列表里 —— 记录自相矛盾", i, c.Factor)
		}
		// 出厂表成员资格是**硬要求**，查不到即失败（旧写法 `want != "" &&` 会让"表里没有的
		// 因子 ID"静默跳过本条断言 —— 评审指出的加固点）。
		//
		// 口径说明（第四轮复审的修正，第五轮补正触发来源归属）：这里的锚点是**文档示例**
		// 必须用出厂内置因子分类内的 ID。对**真实采集数据**不能这样硬判 ——
		//   ① `[edge_factors.custom]` 的自定义因子不在出厂表内，其触发检查由
		//      `[edge_factors.custom_triggers]` 提供（`ConfigToEdgeFactors`），再被
		//      `trigger.<FACTOR-ID>` 覆盖，**不在** `ResolveEdgeFactorTriggerMap` 的表里；
		//   ② 内置因子的锚点是解析值 `config.ResolveEdgeFactorTriggerMap()`
		//      （出厂表 + `[edge_factors.model]` 的 `trigger.<ID>` 覆盖）；
		//   ③ 出厂 config.ini / configs/*.ini 并没有 `[edge_factors.model]` 段，各配置里的
		//      触发值写在 `[edge_factors.custom_triggers]`。
		// 本门禁是"文档示例契约"，不是"采集器契约"；采集器那侧的要求写在 spec §5.1 的
		// 记录构造要求里（按解析出的触发检查校验，且按上面的机制区分内置/自定义）。
		want, known := triggers[c.Factor]
		if !known {
			t.Errorf("edge_factor_chain[%d].factor = %q 不在出厂触发表里 —— 文档示例必须用出厂分类内的因子 ID（自定义因子需在此登记允许集；真实采集数据不受本条约束，见本段注释）", i, c.Factor)
			continue
		}
		if c.TriggerCheck != want {
			t.Errorf("edge_factor_chain[%d] (%s) 的 trigger_check = %q，出厂内置触发表是 %q（示例未使用 trigger.* 覆盖，故以出厂表为准；覆盖过的部署应以 ResolveEdgeFactorTriggerMap 的解析值为准，自定义因子则以 [edge_factors.custom_triggers] + 覆盖为准）",
				i, c.Factor, c.TriggerCheck, want)
		}
		if c.CTrigger > 0 && !failedChecks[c.TriggerCheck] {
			t.Errorf("edge_factor_chain[%d] (%s) 的 c_trigger = %v > 0，但触发检查 %s 没有以 passed=false 出现在 checks[] 里 —— 因子被激活的原因不可追溯（c_trigger=0 的纯级联形态豁免，如 EF-3FA→EF-002FA）",
				i, c.Factor, c.CTrigger, c.TriggerCheck)
		}
	}

	// (b) round-trip：示例自己的输入必须复算出 final_score。
	weights := equalDomainWeights()
	got, err := OfflineScoreWithWeights(cand, rec, weights)
	if err != nil {
		t.Fatalf("用示例自身的输入重算失败: %v", err)
	}
	if got != rec.Observed.FinalScore {
		t.Errorf("round-trip 失败: 复算 = %v，记录里写的是 %v —— 示例数值自相矛盾（采集器照此实现会产出与引擎对不上的记录）",
			got, rec.Observed.FinalScore)
	}
	if want := got >= rec.Observed.Threshold; rec.Observed.Acceptable != want {
		t.Errorf("acceptable = %v，但由 final_score %v 与 threshold %v 推出的应是 %v",
			rec.Observed.Acceptable, rec.Observed.FinalScore, rec.Observed.Threshold, want)
	}

	// (c) 反向对照：只声明一个因子时**不能**复现同一个分数 —— 证明 (b) 不是恒真，
	// 同时把"因子集不一致 = 静默改分"这一危险语义钉成可执行证据。
	partial := cand
	partial.Factors = map[string]float64{"EF-SELINUX": 0.80}
	other, err := OfflineScoreWithWeights(partial, rec, weights)
	if err != nil {
		t.Fatalf("反向对照重算失败: %v", err)
	}
	if other == rec.Observed.FinalScore {
		t.Errorf("只声明一个因子时也得到 %v —— (b) 的 round-trip 断言无区分力（它并没有真正检验记录的数值自洽性）", other)
	}
}
