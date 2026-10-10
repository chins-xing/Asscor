//go:build expr && engine && checks

// 本文件是 Task 8 Step ④ 的用例：**声明面必须进数据集本体**
// （`meta.expected_chain_factors` / `meta.expected_baseline_factors` /
// `meta.expected_baseline_factors_source`，三个都是 additive）。
//
// 为什么必须有它：采集侧的**因子集相等断言**是"这条记录合法"的前提，而它比的是
// `observed` 的链上因子集 == 声明面（基线活跃集 ∪ 注入集）。其中**基线活跃集**是**按基质**
// 声明出来的人为选择（dl360gen9 的 PVE CT 基质恒为 `{EF-SELINUX, EF-APPARMOR}`，见 spec §10.4），
// 而它此前只写在 harness 产物与 `collect-*.json` 里 ⇒ **只看 `records-*.jsonl` 的人看不出
// 这批数据做过基线声明**。同一批记录在"声明过"与"没声明"两种口径下**含义不同**。
//
// 判据四条（与 `skipped_checks_test.go` 同款，因为它们是同一路数的新增证据字段）：
//  1. 声明面**进** `meta`（三个字段的内容逐项正确）；
//  2. **不动评分**：总分 / 阈值 / 链上因子集与不声明时**逐位相同**（声明只影响采集侧的核对口径，
//     不是评分输入）；
//  3. **没声明时字段缺席**（`omitempty` ⇒ 既有夹具与既有记录的 JSON **逐字节不变**）；
//  4. 编解码往返不丢字段（记录是证据；丢了就等于没记）。
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// fixtureBaselineDecl 是夹具用的基线声明（形态与 dl360gen9 PVE CT 基质那一份一致）。
func fixtureBaselineDecl() ([]string, []string, string) {
	return []string{"EF-APPARMOR", "EF-SELINUX"},
		[]string{"EF-APPARMOR", "EF-SELINUX"},
		"PVE CT 基质：OT-005 结构性不可观测 ⇒ trigger.EF-SELINUX 与 trigger.EF-APPARMOR 恒在链上"
}

// TestBaselineDeclarationIsRecordedAdditively 判据四条（见文件头）。
func TestBaselineDeclarationIsRecordedAdditively(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	host := fixtureHostChecks()

	// 不声明（老路径：三个字段都缺席）
	gtPlain := newGroundTruth(true, 100, 2, 1, false)
	recPlain, err := assembleRecord(context.Background(), cfg, "S1-selinux", gtPlain, 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(不声明): %v", err)
	}

	// 声明（基线集 + 注入集 + 来源）
	chain, baseline, source := fixtureBaselineDecl()
	gtDecl := newGroundTruth(true, 100, 2, 1, false)
	gtDecl.ExpectedChainFactors = chain
	gtDecl.ExpectedBaselineFactors = baseline
	gtDecl.ExpectedBaselineFactorsSource = source
	recDecl, err := assembleRecord(context.Background(), cfg, "S1-selinux", gtDecl, 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord(声明): %v", err)
	}

	// ① 字段在场且内容正确。
	if got := recDecl.Meta.ExpectedBaselineFactors; len(got) != 2 || got[0] != "EF-APPARMOR" || got[1] != "EF-SELINUX" {
		t.Errorf("meta.expected_baseline_factors = %v, want [EF-APPARMOR EF-SELINUX]", got)
	}
	if got := recDecl.Meta.ExpectedChainFactors; len(got) != 2 || got[0] != "EF-APPARMOR" {
		t.Errorf("meta.expected_chain_factors = %v, want 注入集", got)
	}
	if !strings.Contains(recDecl.Meta.ExpectedBaselineFactorsSource, "OT-005 结构性不可观测") {
		t.Errorf("meta.expected_baseline_factors_source = %q，必须带上**为什么**（空基线集也要能把『没声明』与『声明为空』分开读）",
			recDecl.Meta.ExpectedBaselineFactorsSource)
	}

	// ② 不动评分：声明**不是**评分输入。
	if recDecl.Observed.FinalScore != recPlain.Observed.FinalScore {
		t.Errorf("声明不得影响总分：%v vs %v", recDecl.Observed.FinalScore, recPlain.Observed.FinalScore)
	}
	if recDecl.Observed.Threshold != recPlain.Observed.Threshold {
		t.Errorf("声明不得影响阈值：%v vs %v", recDecl.Observed.Threshold, recPlain.Observed.Threshold)
	}
	if len(recDecl.Observed.EdgeFactorChain) != len(recPlain.Observed.EdgeFactorChain) {
		t.Errorf("声明不得改变链：%d vs %d", len(recDecl.Observed.EdgeFactorChain), len(recPlain.Observed.EdgeFactorChain))
	}

	// ③ 不声明 ⇒ 三个键都**缺席**（否则既有夹具的 JSON 会多三个键，"逐字节不变"一起破）。
	rawPlain, err := json.Marshal(recPlain)
	if err != nil {
		t.Fatalf("json.Marshal(不声明): %v", err)
	}
	for _, key := range []string{"expected_chain_factors", "expected_baseline_factors", "expected_baseline_factors_source"} {
		if strings.Contains(string(rawPlain), key) {
			t.Errorf("没有声明时 JSON 里不得出现 %s（omitempty）：%s", key, trunc(rawPlain, 400))
		}
	}

	// ④ 编解码往返不丢字段（`MarshalRecord` → 读取层是采集器与数据集之间那条真实路径）。
	raw, err := edgeexp.MarshalRecord(recDecl)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	for _, want := range []string{`"expected_baseline_factors":["EF-APPARMOR","EF-SELINUX"]`,
		`"expected_chain_factors":["EF-APPARMOR","EF-SELINUX"]`, `"expected_baseline_factors_source":"PVE CT 基质`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("序列化后看不到 %s：%s", want, trunc(raw, 600))
		}
	}
	var round edgeexp.Record
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("反序列化: %v", err)
	}
	if len(round.Meta.ExpectedBaselineFactors) != 2 || round.Meta.ExpectedBaselineFactorsSource == "" {
		t.Errorf("往返后声明面丢了：%+v", round.Meta)
	}
}

// TestBaselineDeclarationIsSelfVerifying 是这条字段**存在的理由**的机器版本：
// 记录在声明面三件套在场时，读者用**数据集本体 alone** 就能复核采集侧比过的那条等式
//
//	observed 的链上因子集  ==  expected_baseline_factors ∪ expected_chain_factors
//
// 本用例不碰 `edge_collect.sh`（那是 shell 侧的相等断言，有自己的夹具）；它证明的是
// "把这三样写进记录**足够**让那条等式在离线被重算" —— 少了任何一个都做不到。
func TestBaselineDeclarationIsSelfVerifying(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	host := fixtureHostChecks()

	gt := newGroundTruth(true, 100, 2, 1, false)
	gt.ExpectedChainFactors = []string{"EF-APPARMOR"}
	gt.ExpectedBaselineFactors = []string{"EF-SELINUX"}
	gt.ExpectedBaselineFactorsSource = "夹具"
	rec, err := assembleRecord(context.Background(), cfg, "S1-selinux", gt, 1, host, "")
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}

	// 声明面 = 基线 ∪ 注入（与 edge_collect.sh 的 `expected = injected | baseline` 同一口径）。
	face := map[string]bool{}
	for _, f := range rec.Meta.ExpectedBaselineFactors {
		face[f] = true
	}
	for _, f := range rec.Meta.ExpectedChainFactors {
		face[f] = true
	}
	// 链上实际（`rec.Factors` 是链上出现的因子 ID，去重）。
	observed := map[string]bool{}
	for _, f := range rec.Factors {
		observed[f] = true
	}
	if len(face) == 0 || len(observed) == 0 {
		t.Fatalf("夹具太空：face=%v observed=%v（这条用例要真的比出东西来）", face, observed)
	}
	for f := range observed {
		if !face[f] {
			t.Errorf("链上因子 %s 不在声明面里 —— 说明这三个字段**不足以**离线重算那条等式", f)
		}
	}
	for f := range face {
		if !observed[f] {
			t.Errorf("声明面里的 %s 不在链上 —— 采集侧会判‘声明与现实不符’，而记录里看不出这一点", f)
		}
	}
}
