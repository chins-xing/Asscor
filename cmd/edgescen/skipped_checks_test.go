//go:build expr && engine && checks

// 本文件是 Task 4D Fix round 2 的用例：**被跳过的检查必须写进记录**
// （`meta.skipped_checks`，additive；见 `internal/edgeexp` 的 `Meta.SkippedChecks`）。
//
// 为什么必须有它：`observed.checks[]` 只落盘**失败**检查（那条语义有硬门禁，本轮不动），而框架会把
// "只因读不到证据而失败"的检查转成 skip（`passed=true`、`Δ=0`）。于是"某个条件让证据读不到 ⇒
// 该检查被跳过 ⇒ **分数被推高**"在记录里**完全不可见** —— 而它与"安全真的变好"在数据上同形。
// A-1 的实测就是这一形态（AppArmor 拒读 `/etc/shadow` ⇒ `AS-012` 被跳过 ⇒ 失败 42→41、
// 总分 68.78→69.72），而两条记录的字面完全一致。
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/model"
)

// skipFixtureCheck 造一条**被跳过**的检查结果（形态与 `model.CheckItem.Run` 的 skip 分支逐字相同）。
func skipFixtureCheck(id string) model.CheckResult {
	return model.CheckResult{
		CheckID: id,
		Domain:  model.DomainAttackSurface,
		Name:    "幽灵账户检测（夹具）",
		Passed:  true,
		Delta:   0,
		Detail:  "skipped — requires root privileges (无法读取/etc/shadow: open /etc/shadow: permission denied)",
	}
}

// TestSkippedChecksAreRecordedAdditively 判据四条：
//  1. 跳过的检查**进** `meta.skipped_checks`（含原文理由），且**不进** `observed.checks[]`；
//  2. 它对分数**零影响**（这正是 skip 的定义，也是"分数被推高"的机制：少扣一次分）；
//  3. 没有跳过项时字段**缺席**（`omitempty` ⇒ 既有夹具与既有记录逐字节不变）；
//  4. 编解码往返不丢字段（记录是证据；丢了就等于没记）。
func TestSkippedChecksAreRecordedAdditively(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	gt := newGroundTruth(true, 100, 2, 1, false)

	base := fixtureHostChecks()
	withSkip := append(append([]model.CheckResult{}, base...), skipFixtureCheck("AS-902"))

	recBase, err := assembleRecord(context.Background(), cfg, "S1-selinux", gt, 1, base, "")
	if err != nil {
		t.Fatalf("assembleRecord(基线): %v", err)
	}
	recSkip, err := assembleRecord(context.Background(), cfg, "S1-selinux", gt, 1, withSkip, "")
	if err != nil {
		t.Fatalf("assembleRecord(带跳过项): %v", err)
	}

	// ① 字段在场且内容正确。
	if len(recSkip.Meta.SkippedChecks) != 1 {
		t.Fatalf("meta.skipped_checks = %+v, want 恰好 1 条（AS-902）", recSkip.Meta.SkippedChecks)
	}
	if got := recSkip.Meta.SkippedChecks[0]; got.ID != "AS-902" || !strings.Contains(got.Reason, "permission denied") {
		t.Errorf("跳过项内容不对：%+v（理由必须是**检查自己给出的原文**，排障靠它）", got)
	}
	// ①b 它**不得**出现在 checks[] 里（"checks[] 只落失败项"这条语义不许改）。
	for _, c := range recSkip.Observed.Checks {
		if c.ID == "AS-902" {
			t.Fatalf("被跳过的检查混进了 observed.checks[]：%+v", c)
		}
	}
	// ② 对分数零影响。注意：这不只是"看起来一样"——它是**机制**：skip = 不扣分，
	//    于是"让证据读不到"会**推高**分数（A-1 的 +0.94 就是这么来的）。
	if recSkip.Observed.FinalScore != recBase.Observed.FinalScore {
		t.Errorf("被跳过的检查不应影响总分：%v vs %v", recSkip.Observed.FinalScore, recBase.Observed.FinalScore)
	}
	if recSkip.Observed.Threshold != recBase.Observed.Threshold {
		t.Errorf("阈值也不应变化：%v vs %v", recSkip.Observed.Threshold, recBase.Observed.Threshold)
	}
	// ③ 没有跳过项 ⇒ 字段缺席（否则既有夹具的 JSON 会多一个键，旧断言与"逐字节不变"一起破）。
	if len(recBase.Meta.SkippedChecks) != 0 {
		t.Errorf("基线不该有跳过项：%+v", recBase.Meta.SkippedChecks)
	}
	rawBase, err := json.Marshal(recBase)
	if err != nil {
		t.Fatalf("json.Marshal(基线): %v", err)
	}
	if strings.Contains(string(rawBase), "skipped_checks") {
		t.Errorf("没有跳过项时 JSON 里不得出现 skipped_checks（omitempty）：%s", trunc(rawBase, 400))
	}
	// ④ 编解码往返不丢字段（`MarshalRecord` → `LoadFileAs` 是采集器与读取层之间那条真实路径）。
	raw, err := edgeexp.MarshalRecord(recSkip)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	if !strings.Contains(string(raw), `"skipped_checks":[{"id":"AS-902"`) {
		t.Fatalf("序列化后看不到 skipped_checks：%s", trunc(raw, 400))
	}
	var round edgeexp.Record
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("反序列化: %v", err)
	}
	if len(round.Meta.SkippedChecks) != 1 || round.Meta.SkippedChecks[0].ID != "AS-902" {
		t.Errorf("往返后跳过项丢了：%+v", round.Meta.SkippedChecks)
	}
}

// TestSkippedCheckDetectionIsSingleSourced：`skippedChecks` 只认 `model.IsSkippedDetail`，
// 而该判据必须同时认下 `skipResult` 的**两种**形态（非 root 兜底、权限被拒转换）并拒绝普通失败。
//
// 为什么单列：`skipResult` 有两个调用点，若判据与它们各写一份字面量，改一处就会让
// `meta.skipped_checks` **静默恒空** —— 而"记录里看不出评估器变瞎"正是本轮要堵的形态。
func TestSkippedCheckDetectionIsSingleSourced(t *testing.T) {
	cases := []struct {
		detail string
		want   bool
	}{
		{"skipped — requires root privileges", true},
		{skipFixtureCheck("AS-902").Detail, true},
		{"skipped — requires root privileges (operation not permitted)", true},
		{"  skipped — requires root privileges  ", true}, // 两侧空白不影响判据
		{"/etc/shadow 权限=0640 (期望=000)", false},          // 真失败：不得被当成跳过
		{"fixture: pass", false},
		{"", false},
	}
	for _, c := range cases {
		if got := model.IsSkippedDetail(c.detail); got != c.want {
			t.Errorf("IsSkippedDetail(%q) = %v, want %v", c.detail, got, c.want)
		}
	}
	// 判据的**消费侧**：只有被 IsSkippedDetail 认下的条目会被记进 meta.skipped_checks。
	host := []model.CheckResult{
		skipFixtureCheck("AS-901"),
		{CheckID: "OT-001", Domain: model.DomainOperationTrust, Passed: false, Delta: -5, Detail: "/etc/shadow 权限=0640 (期望=000)"},
		{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: true, Delta: 0, Detail: "fixture: pass"},
	}
	got := skippedChecks(host)
	if len(got) != 1 || got[0].ID != "AS-901" {
		t.Fatalf("skippedChecks = %+v, want 只有 AS-901（失败的 OT-001 与通过的 EF-001 都不算跳过）", got)
	}
}

// trunc 只用于把失败信息里的长 JSON 截断（不影响判据）。
func trunc(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
