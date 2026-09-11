//go:build edgeexp

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleJSONL 是 spec §5.1 schema 的一条样例记录（brief Task 8 Step 1 的夹具）。
//
// **偏离 brief 的两处（均已裁定，见报告 §问题与自决）**：
//
//  1. 必须是**一行**。brief 原文把它写成跨多行的 JSON 文本，而 brief 自己的读取层是
//     行式扫描、spec §5.1 也写明「每场景一条 JSONL」—— 跨行夹具会让每条记录的第一行就
//     报 `unexpected end of JSON input`，Step 4 的 PASS 不可能达到。以 JSONL 语义为准
//     （一行一个完整 JSON 对象）；读取层**不放宽**成"跨行拼接"，那会让被截断的行与下一条
//     记录静默粘连。
//  2. `domain_scores` 由 {attack_surface:80, operation_trust:60}（聚合分 70）改为 90/90。
//     原数字与同一夹具的断言（「legacy 候选仍判 acceptable=true ⇒ 漏判」）不可能同时成立：
//     legacy 候选的口径是「∏effective_f 作用于聚合总分」（mandate 口径 4），本记录的因子链
//     乘子为 0.82（在线单次衰减）/0.838（离线双衰减口径，mandate 口径 2），70×0.82 = 57.4 < 60
//     ⇒ 必然判 not acceptable ⇒ 漏判率 0，与断言矛盾（brief 自己的注释「分数不变(70)」也只在
//     乘子恒为 1 时才成立）。断言的**意图**（被接受但客观被攻陷 ⇒ 计漏判）是对的，错的是夹具
//     数字，故按 Task 3 先例（brief 夹具与权威口径冲突时以口径为准、修正夹具）把域分抬到 90/90：
//     - 在线 legacy 观测：90 × 0.82 = 73.8 ≥ 60 ⇒ acceptable=true（与 final_score 自洽）；
//     - 离线 legacy 重算：90 × 0.838 = 75.42 ≥ 60 ⇒ 仍 acceptable ⇒ 漏判计 1（断言成立）。
const sampleJSONL = `{"scenario_id":"S1-selinux","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90,"operation_trust":90},"final_score":73.8,"acceptable":true,"threshold":60,"checks":[{"id":"OT-005","domain":"operation_trust","passed":false,"delta":-8,"confidence":0.9}],"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","playbook_hash":"abc","config_hash":"def","run":1}}`

func writeSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	if err := os.WriteFile(path, []byte(sampleJSONL+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// writeJSONL 把给定内容写成临时 JSONL 并返回路径。
func writeJSONL(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadRecordsParsesSchema(t *testing.T) {
	recs, err := LoadRecords(writeSample(t))
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.ScenarioID != "S1-selinux" || !r.GroundTruth.Compromised || r.GroundTruth.TTPsAchieved != 4 {
		t.Errorf("unexpected record: %+v", r)
	}
	if r.Observed.EdgeFactorChain[0].EffectiveFactor != 0.82 {
		t.Errorf("chain not parsed: %+v", r.Observed.EdgeFactorChain)
	}
	if r.Observed.Checks[0].ID != "OT-005" || r.Observed.Checks[0].Passed {
		t.Errorf("checks not parsed: %+v", r.Observed.Checks)
	}
	if r.Meta.Env != "wsl-clab-14" || r.Meta.Run != 1 || r.Observed.Threshold != 60 {
		t.Errorf("meta/observed not parsed: %+v / %+v", r.Meta, r.Observed)
	}
}

// TestLoadRecordsSkipsBlankLines：空行不产生记录、不报错（JSONL 常见尾部空行）。
func TestLoadRecordsSkipsBlankLines(t *testing.T) {
	path := writeJSONL(t, "blank.jsonl", sampleJSONL+"\n\n")
	recs, err := LoadRecords(path)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
}

// TestLoadRecordsReportsBadLine：坏行必须带**行号**报错，绝不静默跳过。
// 第 1 行必须是**完全合法**的记录，否则先报的会是第 1 行的字段问题，测不到第 2 行的解析失败。
func TestLoadRecordsReportsBadLine(t *testing.T) {
	path := writeJSONL(t, "bad.jsonl", sampleJSONL+"\n{not json}\n")
	_, err := LoadRecords(path)
	if err == nil {
		t.Fatal("expected an error for a malformed line, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error must carry the line number: %v", err)
	}
}

// TestLoadRecordsRejectsMissingScenarioID：缺 scenario_id 的记录无法定位，必须拒绝。
func TestLoadRecordsRejectsMissingScenarioID(t *testing.T) {
	path := writeJSONL(t, "noid.jsonl", "{\"factors\":[\"EF-SELINUX\"]}\n")
	_, err := LoadRecords(path)
	if err == nil {
		t.Fatal("expected an error for a record without scenario_id, got nil")
	}
	if !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "scenario_id") {
		t.Errorf("error must name the line and the missing field: %v", err)
	}
}

// TestLoadRecordsRejectsUnparsableTimestamp：chain 的时间戳是离线 chain 模型的唯一时间来源
// （mandate 口径 3），解析不了就必须在读取层带行号拒绝 —— 否则它会以零值进入合成层，
// 被 chain 的 fail-fast 当成"没时间戳"，错误信息丢失行号、也分不清是坏数据还是缺数据。
func TestLoadRecordsRejectsUnparsableTimestamp(t *testing.T) {
	rec := `{"scenario_id":"S5-cascade","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"EF-3FA","c_trigger":1.0,"effective_factor":0.82,"ts":"not-a-time"}]},"ground_truth":{"compromised":true}}`
	_, err := LoadRecords(writeJSONL(t, "bads.jsonl", rec+"\n"))
	if err == nil {
		t.Fatal("expected an error for an unparsable ts, got nil")
	}
	if !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "ts") {
		t.Errorf("error must name the line and the offending field: %v", err)
	}
}

// TestLoadRecordsRejectsEmptyFactorID：链里没有因子 ID 的条目无法参与合成，必须拒绝。
func TestLoadRecordsRejectsEmptyFactorID(t *testing.T) {
	rec := `{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"  ","c_trigger":1.0,"effective_factor":0.82}]},"ground_truth":{"compromised":true}}`
	_, err := LoadRecords(writeJSONL(t, "nofactor.jsonl", rec+"\n"))
	if err == nil {
		t.Fatal("expected an error for an empty factor id, got nil")
	}
	if !strings.Contains(err.Error(), "factor") {
		t.Errorf("error must name the offending field: %v", err)
	}
}

// --- Fix round 2 / 评审 I2：必需字段的**存在性**与值域 -------------------------------

// mustRejectRecord 断言一条记录被读取层拒绝，且错误带行号与指定字段名（评审 I2 要求）。
func mustRejectRecord(t *testing.T, name, recordJSON string, wantFields ...string) {
	t.Helper()
	_, err := LoadRecords(writeJSONL(t, name, recordJSON+"\n"))
	if err == nil {
		t.Fatalf("expected the record to be rejected, got nil error:\n%s", recordJSON)
	}
	msg := err.Error()
	if !strings.Contains(msg, "line 1") {
		t.Errorf("error must carry the line number: %v", err)
	}
	for _, want := range wantFields {
		if !strings.Contains(msg, want) {
			t.Errorf("error must name %q: %v", want, err)
		}
	}
}

// TestLoadRecordsRejectsMissingThreshold：threshold 缺失 ⇒ 零值 0 ⇒ 任何非负分数都判
// acceptable ⇒ 决策层退化为"全放行"（FNR = 攻陷数/N，FPR ≡ 0），而报告照常打印 —— 必须拒绝。
func TestLoadRecordsRejectsMissingThreshold(t *testing.T) {
	mustRejectRecord(t, "no-threshold.jsonl", `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"final_score":90,"acceptable":true},"ground_truth":{"compromised":false}}`, "threshold")
}

// TestLoadRecordsRejectsNonPositiveThreshold：0 与负值都不是合法阈值（`score >= threshold` 恒真）。
func TestLoadRecordsRejectsNonPositiveThreshold(t *testing.T) {
	mustRejectRecord(t, "zero-threshold.jsonl", `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"threshold":0},"ground_truth":{"compromised":false}}`, "threshold")
	mustRejectRecord(t, "neg-threshold.jsonl", `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"threshold":-1},"ground_truth":{"compromised":false}}`, "threshold")
}

// TestLoadRecordsRejectsEmptyDomainScores：没有域分就无从重算总分。
func TestLoadRecordsRejectsEmptyDomainScores(t *testing.T) {
	mustRejectRecord(t, "no-domains.jsonl", `{"scenario_id":"S0-baseline","observed":{"threshold":60},"ground_truth":{"compromised":false}}`, "domain_scores")
	mustRejectRecord(t, "empty-domains.jsonl", `{"scenario_id":"S0-baseline","observed":{"threshold":60,"domain_scores":{}},"ground_truth":{"compromised":false}}`, "domain_scores")
}

// TestLoadRecordsRejectsMissingCTrigger：c_trigger 缺失 ⇒ 0 ⇒ EffectiveFactor 返回 1
// ⇒ a_i = 0 ⇒ 该因子的惩罚静默消失。
//
// 断言里要求出现 "missing"：字段缺失必须报"缺失"，而不是报一个看起来像数值越界的错误
// —— 前者告诉操作员"记录不完整"，后者会把人引向"值写错了"。这两条信息不可互换。
func TestLoadRecordsRejectsMissingCTrigger(t *testing.T) {
	mustRejectRecord(t, "no-ctrigger.jsonl",
		`{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"EF-SELINUX","effective_factor":0.82}]},"ground_truth":{"compromised":true}}`,
		"c_trigger", "missing")
}

// TestLoadRecordsRejectsMissingEffectiveFactor：effective_factor 缺失 ⇒ 0 ⇒ 命中 Synthesize
// 的"未提供"哨兵 ⇒ 静默回落到配置权重（与真实观测值无关）。
//
// 断言同样要求 "missing"：仅靠值域检查（`0 ∉ (0,1]`）虽然也会拒绝，但报出来的是"值越界"，
// 会掩盖"这条记录根本没写这个字段"这一事实（变异 M9 正是用来钉住这条诊断口径的）。
func TestLoadRecordsRejectsMissingEffectiveFactor(t *testing.T) {
	mustRejectRecord(t, "no-eff.jsonl",
		`{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":0.9}]},"ground_truth":{"compromised":true}}`,
		"effective_factor", "missing")
}

// TestLoadRecordsRejectsOutOfRangeChainValues：越界值会让 L/P 失真（eff > 1 时 a < 0 ⇒ P > 1，
// 反向抬高域分），必须在读取层拒绝。
func TestLoadRecordsRejectsOutOfRangeChainValues(t *testing.T) {
	base := `{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":%s,"effective_factor":%s}]},"ground_truth":{"compromised":true}}`
	mustRejectRecord(t, "c-high.jsonl", fmt.Sprintf(base, "1.5", "0.82"), "c_trigger")
	mustRejectRecord(t, "c-neg.jsonl", fmt.Sprintf(base, "-0.1", "0.82"), "c_trigger")
	mustRejectRecord(t, "eff-zero.jsonl", fmt.Sprintf(base, "0.9", "0"), "effective_factor")
	mustRejectRecord(t, "eff-high.jsonl", fmt.Sprintf(base, "0.9", "1.5"), "effective_factor")
}

// TestLoadRecordsAcceptsBoundaryChainValues：`c_trigger = 0` 与 `effective_factor = 1` 是**合法**
// 边界值，必须放行。
//
// c_trigger = 0 不是坏数据：ssam-lib 的 `ApplyEdgeFactorsToChecksPolicy` 在"因子仅由级联激活、
// 自身触发检查未失败"时只把 Active 置真、不动 TriggerConfidence，于是 tc 保持 0
// （spec §5 的 S5 级联组正会产出这种记录）。被拒的是**缺失**，不是这个值本身。
func TestLoadRecordsAcceptsBoundaryChainValues(t *testing.T) {
	rec := `{"scenario_id":"S5-cascade","factors":["EF-3FA","EF-002FA"],"observed":{"domain_scores":{"attack_surface":90},"threshold":60,"edge_factor_chain":[{"factor":"EF-3FA","trigger_check":"EF-002","c_trigger":0,"effective_factor":1}]},"ground_truth":{"compromised":true,"ttps_achieved":4}}`
	recs, err := LoadRecords(writeJSONL(t, "boundary.jsonl", rec+"\n"))
	if err != nil {
		t.Fatalf("边界值应被接受，却被拒绝：%v", err)
	}
	if len(recs) != 1 || recs[0].Observed.EdgeFactorChain[0].CTrigger != 0 {
		t.Fatalf("unexpected records: %+v", recs)
	}
}

// TestLoadRecordsRejectsMissingGroundTruth：整段 `ground_truth` 缺失 ⇒ compromised 读成 false
// ⇒ 该场景被静默标成"未攻陷"。
func TestLoadRecordsRejectsMissingGroundTruth(t *testing.T) {
	mustRejectRecord(t, "no-gt.jsonl",
		`{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60}}`,
		"compromised")
}

// TestLoadRecordsRejectsMissingCompromised：`ground_truth` 在场但没写 `compromised` 同样要拒绝
// —— 这正是"false（真的没被攻陷）"与"没写（缺失）"必须区分的场合。
func TestLoadRecordsRejectsMissingCompromised(t *testing.T) {
	mustRejectRecord(t, "no-compromised.jsonl",
		`{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60},"ground_truth":{"ttps_achieved":4}}`,
		"compromised")
}

// TestLoadRecordsExplicitFalseCompromisedIsAccepted：显式 `false` 必须被接受，且如实读成 false
// （不能与"缺失"混为一谈）。
func TestLoadRecordsExplicitFalseCompromisedIsAccepted(t *testing.T) {
	recs, err := LoadRecords(writeJSONL(t, "explicit-false.jsonl",
		`{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":95},"threshold":60},"ground_truth":{"compromised":false}}`+"\n"))
	if err != nil {
		t.Fatalf("显式 false 应被接受：%v", err)
	}
	if recs[0].GroundTruth.Compromised {
		t.Errorf("compromised = true, want false")
	}
}

// TestLoadRecordsReportsMissingFile：路径不存在时错误必须含路径（不是裸的 os 错误）。
func TestLoadRecordsReportsMissingFile(t *testing.T) {
	_, err := LoadRecords(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), "nope.jsonl") {
		t.Errorf("error must carry the path: %v", err)
	}
}
