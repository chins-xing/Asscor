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
