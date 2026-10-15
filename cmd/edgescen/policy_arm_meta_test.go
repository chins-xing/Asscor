//go:build expr && engine && checks

// 本文件是 Task 10 的用例：**「策略在/不在」两条臂必须只靠记录本身可分辨**
// （`meta.policy_on`，additive；用户 2026-10-13 裁定「甲」）。
//
// 为什么必须有它：矩阵现在给同一个 `targeted_ttp` 场景跑**两条臂** —— 同一个目标 TTP、同一个
// pair 剧本、同组、同 config、同观察窗，**只在 `POLICY_ON` 上不同**。策略卸掉时目标 TTP 必然成功
// （`compromised=true`），装上时被挡住（`compromised=false`）—— 决策层的两类标签就靠这对数据。
// 而"两臂只差策略"这句话**必须能在记录里被检验**：否则读者只能靠文件名、运行顺序或场景 id 的
// 尾号去猜哪条是哪个臂（那正是本仓反复在堵的"第二份真源"）。
//
// 判据五条：
//  1. 产物写了策略状态 ⇒ 记录 `meta.policy_on` 在场且取值正确（`"0"` / `"1"`）；
//  2. **不动评分**：总分 / 阈值 / 链上因子集与不写该字段时**逐位相同**（它是证据，不是输入）；
//  3. 产物没写 ⇒ 键**缺席**（`omitempty`）⇒ 既有记录与既有夹具的 JSON 逐字节不变；
//  4. 取值**归一**：`true/false/on/off/带空白` 等写法归一到 `"1"`/`"0"`；
//  5. 非法取值 ⇒ 缺席（**不猜**：把一个读不懂的串当成 `"0"` 会让"没写"与"写错"在数据里同形）。
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// policyArmGroundTruth 造一份"带策略状态"的 harness 客观结果（其余字段与既有夹具同形）。
func policyArmGroundTruth(policyOn string, compromised bool) groundTruth {
	gt := newGroundTruth(compromised, 100, 2, 1, !compromised)
	gt.ExpectedChainFactors = []string{"EF-APPARMOR"}
	gt.ExpectedBaselineFactors = []string{"EF-APPARMOR", "EF-SELINUX"}
	gt.ExpectedBaselineFactorsSource = "PVE CT 基质：OT-005 结构性不可观测 ⇒ 两个因子恒在链上"
	gt.PolicyOn = policyOn
	return gt
}

func TestPolicyArmIsRecordedAdditively(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	host := fixtureHostChecks()

	// 不带策略状态（老路径：键缺席）
	gtPlain := newGroundTruth(true, 100, 2, 1, false)
	gtPlain.ExpectedChainFactors = []string{"EF-APPARMOR"}
	gtPlain.ExpectedBaselineFactors = []string{"EF-APPARMOR", "EF-SELINUX"}
	gtPlain.ExpectedBaselineFactorsSource = "PVE CT 基质：OT-005 结构性不可观测 ⇒ 两个因子恒在链上"
	recPlain, err := assembleRecord(context.Background(), cfg, "S1-apparmor", gtPlain, 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(不写策略): %v", err)
	}

	// 策略**不在**（臂 1）与策略**在**（臂 2）—— 同一个场景、同一个 run，只差这一个字段
	recOff, err := assembleRecord(context.Background(), cfg, "S1-apparmor", policyArmGroundTruth("0", true), 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(policy_on=0): %v", err)
	}
	recOn, err := assembleRecord(context.Background(), cfg, "S1-apparmor", policyArmGroundTruth("1", false), 2, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(policy_on=1): %v", err)
	}

	// ① 在场且取值正确。
	if recOff.Meta.PolicyOn != "0" {
		t.Errorf("meta.policy_on = %q, want \"0\"（策略不在的臂）", recOff.Meta.PolicyOn)
	}
	if recOn.Meta.PolicyOn != "1" {
		t.Errorf("meta.policy_on = %q, want \"1\"（策略在的臂）", recOn.Meta.PolicyOn)
	}
	// **两臂靠记录本身可分辨**：这一条是它存在的理由 —— 判据是"只看 meta 就能分开"。
	if recOff.Meta.PolicyOn == recOn.Meta.PolicyOn {
		t.Errorf("两条臂的 meta.policy_on 相同（%q）⇒ 记录本身分不出哪个是策略在的臂", recOff.Meta.PolicyOn)
	}

	// ② 不动评分：策略状态**不是**评分输入。
	if recOn.Observed.FinalScore != recPlain.Observed.FinalScore {
		t.Errorf("策略状态不得影响总分：%v vs %v", recOn.Observed.FinalScore, recPlain.Observed.FinalScore)
	}
	if recOn.Observed.Threshold != recPlain.Observed.Threshold {
		t.Errorf("策略状态不得影响阈值：%v vs %v", recOn.Observed.Threshold, recPlain.Observed.Threshold)
	}
	if len(recOn.Observed.EdgeFactorChain) != len(recPlain.Observed.EdgeFactorChain) {
		t.Errorf("策略状态不得改变链：%d vs %d", len(recOn.Observed.EdgeFactorChain), len(recPlain.Observed.EdgeFactorChain))
	}

	// ③ 不写 ⇒ 键缺席（否则既有夹具/既有记录的 JSON 会多一个键，"逐字节不变"一起破）。
	rawPlain, err := json.Marshal(recPlain)
	if err != nil {
		t.Fatalf("json.Marshal(不写策略): %v", err)
	}
	if strings.Contains(string(rawPlain), `"policy_on"`) {
		t.Errorf("没有策略状态时 JSON 里不得出现 policy_on（omitempty）：%s", trunc(rawPlain, 400))
	}

	// ④ 编解码往返不丢（记录是证据；丢了就等于没记）。
	rawOn, err := json.Marshal(recOn)
	if err != nil {
		t.Fatalf("json.Marshal(policy_on=1): %v", err)
	}
	if !strings.Contains(string(rawOn), `"policy_on":"1"`) {
		t.Fatalf("序列化后看不到 meta.policy_on=\"1\"：%s", trunc(rawOn, 600))
	}
}

// TestRepeatAxisIsRecordedAdditively 是 Task 11 的用例：**重复轴必须在记录里可查**
// （`meta.repeat`，additive）。
//
// 为什么必须有它：全量扫描 = `--run 1|2|3` × 2 个臂 ⇒ 每个 targeted 场景 6 条记录。
// 三个维度必须**只靠记录本身**查得出来 —— 场景（`scenario_id` 的名字部分）、臂（`meta.policy_on`）、
// **重复（`meta.repeat`）**。`scenario_id` 的尾号是**实例号** `NN=(REPEAT-1)*NARMS+臂+1`
// （它保证三元组唯一，但**不能**直接当重复号读）。
//
// 判据四条：
//  1. 产物写了重复号 ⇒ `meta.repeat` 在场且归一（`"2"`）；
//  2. **不动评分**：总分 / 阈值 / 链与不写时逐位相同（它是证据不是输入）；
//  3. 产物没写 ⇒ 键**缺席**（`omitempty`）⇒ 单 run 的记录与 Task 9/10 逐字节不变；
//  4. **同一条记录里三个维度互不混同**：`meta.policy_on` 与 `meta.repeat` 是**两个字段**
//     （第 2 遍 + 策略在的臂 ⇒ `policy_on="1"` 且 `repeat="2"`），不是同一个数字。
func TestRepeatAxisIsRecordedAdditively(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	host := fixtureHostChecks()

	// 第 1 遍（不写重复号）作为对照
	gt1 := policyArmGroundTruth("0", true)
	rec1, err := assembleRecord(context.Background(), cfg, "S1-apparmor", gt1, 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(第 1 遍): %v", err)
	}
	// 第 2 遍 + 策略在的臂：实例号 NN=4（(2-1)*2+1+1），run=4；重复号写 2
	gt2 := policyArmGroundTruth("1", false)
	gt2.RepeatIndex = "2"
	rec2, err := assembleRecord(context.Background(), cfg, "S1-apparmor", gt2, 4, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(第 2 遍·策略在): %v", err)
	}

	// ① 在场且取值正确。
	if rec2.Meta.Repeat != "2" {
		t.Errorf("meta.repeat = %q, want \"2\"（重复轴）", rec2.Meta.Repeat)
	}
	if rec2.Meta.PolicyOn != "1" {
		t.Errorf("meta.policy_on = %q, want \"1\"（臂）—— 两个维度**必须是两个字段**", rec2.Meta.PolicyOn)
	}
	if rec2.ScenarioID != "S1-apparmor-04" {
		t.Errorf("scenario_id = %q, want S1-apparmor-04（实例号 NN=(REPEAT-1)*NARMS+臂+1）", rec2.ScenarioID)
	}

	// ② 不动评分。
	if rec2.Observed.FinalScore != rec1.Observed.FinalScore {
		t.Errorf("重复号不得影响总分：%v vs %v", rec2.Observed.FinalScore, rec1.Observed.FinalScore)
	}
	if rec2.Observed.Threshold != rec1.Observed.Threshold {
		t.Errorf("重复号不得影响阈值：%v vs %v", rec2.Observed.Threshold, rec1.Observed.Threshold)
	}

	// ③ 第 1 遍的记录里**不得**出现 repeat / policy_on 之外的重复轴痕迹：repeat 缺席。
	raw1, err := json.Marshal(rec1)
	if err != nil {
		t.Fatalf("json.Marshal(第 1 遍): %v", err)
	}
	if strings.Contains(string(raw1), `"repeat"`) {
		t.Errorf("第 1 遍的记录里不得出现 meta.repeat（omitempty ⇒ 与 Task 9/10 逐字节不变）：%s", trunc(raw1, 400))
	}

	// ④ 第 2 遍：两个维度都在场且**各自独立**（policy_on="1" + repeat="2"）。
	raw2, err := json.Marshal(rec2)
	if err != nil {
		t.Fatalf("json.Marshal(第 2 遍): %v", err)
	}
	for _, want := range []string{`"policy_on":"1"`, `"repeat":"2"`} {
		if !strings.Contains(string(raw2), want) {
			t.Fatalf("第 2 遍的记录里看不到 %s：%s", want, trunc(raw2, 600))
		}
	}
}

// TestRepeatIndexOfNormalizes 归一与"不猜"（与 `substratePolicyOn` 同款纪律）。
func TestRepeatIndexOfNormalizes(t *testing.T) {
	sp := func(s string) *string { return &s }
	cases := []struct {
		in   *string
		want string
		why  string
	}{
		{sp("1"), "1", "第 1 遍（矩阵只在 >1 时才写，这里仍接受）"},
		{sp("2"), "2", "第 2 遍"},
		{sp(" 3 "), "3", "环境变量带空白"},
		{sp("02"), "2", "前导零归一（避免 `02` 与 `2` 在数据集里被当成两个值）"},
		{sp(""), "", "空 ⇒ 缺席（产物没写）"},
		{sp("0"), "", "0 不合法 ⇒ 缺席（重复号从 1 起），**不猜**"},
		{sp("-1"), "", "负数 ⇒ 缺席"},
		{sp("abc"), "", "非法 ⇒ 缺席"},
		{nil, "", "键不在产物里 ⇒ 缺席"},
	}
	for _, c := range cases {
		if got := repeatIndexOf(c.in); got != c.want {
			label := "<nil>"
			if c.in != nil {
				label = *c.in
			}
			t.Errorf("repeatIndexOf(%s) = %q, want %q（%s）", label, got, c.want, c.why)
		}
	}
}

// TestSubstratePolicyOnNormalizes 判据 4/5：归一与"不猜"。
func TestSubstratePolicyOnNormalizes(t *testing.T) {
	cases := []struct {
		in   string
		want string
		why  string
	}{
		{"1", "1", "矩阵导出的常态"},
		{"0", "0", "同上"},
		{" 1 ", "1", "环境变量带空白"},
		{"TRUE", "1", "大小写/布尔写法"},
		{"false", "0", "布尔写法"},
		{"on", "1", "开关写法"},
		{"off", "0", "开关写法"},
		{"", "", "空 ⇒ 缺席（产物没写）"},
		{"maybe", "", "非法值 ⇒ 缺席，**不猜**成 0"},
	}
	for _, c := range cases {
		got := substratePolicyOn(&harnessSubstrateIdentity{PolicyOn: c.in})
		if got != c.want {
			t.Errorf("substratePolicyOn(%q) = %q, want %q（%s）", c.in, got, c.want, c.why)
		}
	}
	if got := substratePolicyOn(nil); got != "" {
		t.Errorf("substratePolicyOn(nil) = %q, want \"\"（老产物没有这一段）", got)
	}
}
