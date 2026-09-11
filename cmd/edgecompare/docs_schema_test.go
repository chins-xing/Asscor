//go:build edgeexp

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
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
// 反向对照（有牙齿的证明）：把示例里的 `spc_score` 抹掉后，读取层**必须**拒绝 ——
// 否则本测试只证明"某个 JSON 能读进来"，而不能证明它在守 spc_score 的存在性。

const designDocPath = "../../docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md"

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
	// §5.1 为了可读性是**缩进打印**的，而 JSONL 要求一条记录压成一行：这里按 JSONL 的真实
	// 形态压缩空白后再喂给读取层（压缩只动结构空白，不动字符串内容）。
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, []byte(sample)); err != nil {
		t.Fatalf("§5.1 的示例不是合法 JSON（连读取层之前的解析都过不了）: %v", err)
	}
	oneLine := compacted.String()

	recs, err := LoadRecords(writeJSONL(t, "spec51.jsonl", oneLine+"\n"))
	if err != nil {
		t.Fatalf("spec §5.1 的示例记录被读取层拒绝 —— 文档与 load.go 已漂移，采集器照此实现会一条都读不进来:\n%v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("期望 1 条记录，得到 %d 条", len(recs))
	}

	// 不只断言"能读"，还钉住两个 C1 新增必填项确实**在示例里被写出来**（而不是靠零值蒙混）。
	r := recs[0]
	if r.ScenarioID == "" || !r.Observed.spcScoreSet || !r.Observed.threatCoeffSet {
		t.Fatalf("示例记录缺少 scenario_id / spc_score / threat_coeff: id=%q spcSet=%v threatSet=%v",
			r.ScenarioID, r.Observed.spcScoreSet, r.Observed.threatCoeffSet)
	}
	if len(r.Observed.EdgeFactorChain) == 0 {
		t.Fatal("示例记录的 edge_factor_chain 为空 —— 链上字段（c_trigger/effective_factor）的存在性契约就没被覆盖")
	}
	for i, c := range r.Observed.EdgeFactorChain {
		if !c.cTriggerSet || !c.effectiveFactorSet {
			t.Fatalf("edge_factor_chain[%d] 缺 c_trigger/effective_factor", i)
		}
	}

	// 反向对照：抹掉 spc_score 后必须被拒（证明这条门禁真的在守该字段）。
	broken := strings.Replace(oneLine, `"spc_score":0.93,`, "", 1)
	if broken == oneLine {
		t.Fatalf("压缩后的示例里找不到 `\"spc_score\":0.93,`，无法构造反向对照（示例改过？）")
	}
	if _, err := LoadRecords(writeJSONL(t, "spec51-broken.jsonl", broken+"\n")); err == nil {
		t.Fatal("抹掉 spc_score 后读取层仍然接受 —— 本门禁没有守到该字段")
	} else if !strings.Contains(err.Error(), "spc_score") {
		t.Fatalf("拒绝原因不是 spc_score 缺失，而是: %v", err)
	}
}
