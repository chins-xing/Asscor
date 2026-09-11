//go:build edgeexp

package main

import (
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
func TestLoadRecordsReportsBadLine(t *testing.T) {
	path := writeJSONL(t, "bad.jsonl", "{\"scenario_id\":\"S1\"}\n{not json}\n")
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
	rec := `{"scenario_id":"S5-cascade","observed":{"edge_factor_chain":[{"factor":"EF-3FA","c_trigger":1.0,"effective_factor":0.82,"ts":"not-a-time"}]}}`
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
	rec := `{"scenario_id":"S1-selinux","observed":{"edge_factor_chain":[{"factor":"  ","c_trigger":1.0,"effective_factor":0.82}]}}`
	_, err := LoadRecords(writeJSONL(t, "nofactor.jsonl", rec+"\n"))
	if err == nil {
		t.Fatal("expected an error for an empty factor id, got nil")
	}
	if !strings.Contains(err.Error(), "factor") {
		t.Errorf("error must name the offending field: %v", err)
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
