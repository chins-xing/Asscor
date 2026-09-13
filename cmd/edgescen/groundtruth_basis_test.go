//go:build expr && engine && checks

// 本文件是 Task 4D Step 3B 的用例：`ground_truth.basis`（标签依据，用户 2026-09-12 的 L2 裁定）
// 在**采集器**侧的通路 —— harness 产物 → `groundTruth` → 记录里的 `ground_truth.basis`。
//
// 为什么这条通路要单独钉住：`basis` 的语义是"这条 `compromised` 标签从哪来"，而它有两个可能的
// 出口被静默丢掉 —— ①harness 产物没写它（必须**在记录里也缺席**，不得猜一个默认值）；
// ②写了但采集中间被丢（记录里缺席），于是"这批数据用的是目标 TTP 还是侦察剧本"无从判定。
// 两条都必须有判据，否则 L2 语义在数据上不可核。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// harnessBasisFixture 造一份 harness 产物（其余必填字段齐全），basis 行按参数决定写不写。
func harnessBasisFixture(t *testing.T, scenario, basisLine string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "attack.json")
	body := `{
  "scenario": "` + scenario + `",
  "compromised": false,
  "time_to_compromise_s": 0,
  "ttps_achieved": 0,
  "nodes_affected": 0,
  "block_effective": true,
  ` + basisLine + `
  "injections": []
}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	return p
}

// TestHarnessBasisFlowsIntoTheRecord：写了 `basis` 就必须进记录（不能在中途被丢）。
func TestHarnessBasisFlowsIntoTheRecord(t *testing.T) {
	for _, want := range []string{edgeexp.BasisTargetedTTP, edgeexp.BasisReconPlaybook} {
		p := harnessBasisFixture(t, "S0-baseline", `"basis": "`+want+`",`)
		gt, err := loadGroundTruth(p, "S0-baseline")
		if err != nil {
			t.Fatalf("loadGroundTruth: %v", err)
		}
		if gt.Basis != want {
			t.Fatalf("groundTruth.Basis = %q, want %q", gt.Basis, want)
		}
		rec, err := gt.recordGroundTruth()
		if err != nil {
			t.Fatalf("recordGroundTruth: %v", err)
		}
		if rec.Basis != want {
			t.Errorf("记录里的 ground_truth.basis = %q, want %q（中途被丢了）", rec.Basis, want)
		}
	}
}

// TestHarnessBasisAbsentStaysAbsentInTheRecord：**没说依据 ⇒ 记录里也缺席**。
//
// 这条是"不许猜默认值"的钉子：缺省填 `recon_playbook` 会把"这份产物没声明依据"伪装成
// "它是侦察剧本" —— 而记录一旦落盘就再也分不清（依据是标签的语义，不是可以补的默认值）。
func TestHarnessBasisAbsentStaysAbsentInTheRecord(t *testing.T) {
	p := harnessBasisFixture(t, "S0-baseline", `"playbook_hash": "sha256:x",`)
	gt, err := loadGroundTruth(p, "S0-baseline")
	if err != nil {
		t.Fatalf("loadGroundTruth: %v", err)
	}
	if gt.Basis != "" {
		t.Errorf("harness 没写 basis 时 groundTruth.Basis 必须是空串（不得猜默认值），实际 %q", gt.Basis)
	}
	rec, err := gt.recordGroundTruth()
	if err != nil {
		t.Fatalf("recordGroundTruth: %v", err)
	}
	if rec.Basis != "" {
		t.Errorf("记录里的 basis 必须缺席，实际 %q", rec.Basis)
	}
	// 缺席在字节上也必须缺席（`omitempty`）：既有记录（里程碑 B 之前）不得因新增字段改变字节。
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "basis") {
		t.Errorf("未声明的 basis 不得出现在落盘字节里: %s", raw)
	}
}

// TestHarnessBasisValueIsValidated：写错的值必须被拒，且错误指向合法取值。
//
// 为什么不是"宽容忽略"：一个拼错的 basis 会让该记录**静默退出决策层样本**（或混进另一类），
// 而它与合法值在数据上完全同形（都是非空字符串）。校验点在**记录层**（`edgeexp.Validate`，
// 由 `MarshalRecord` 经 `ValidateConstruction` 覆盖到写出路径）：解析层刻意把值原样带过来，
// 于是"这条产物写错了"暴露在写出那一刻，那时错误信息里带着记录本身，比在读 JSON 时拒绝更容易归因。
func TestHarnessBasisValueIsValidated(t *testing.T) {
	for _, bad := range []string{"targeted-ttp", "recon", "TargetedTTP"} {
		p := harnessBasisFixture(t, "S0-baseline", `"basis": "`+bad+`",`)
		gt, err := loadGroundTruth(p, "S0-baseline")
		if err != nil {
			t.Fatalf("loadGroundTruth 不该在这一层判值域: %v", err)
		}
		if gt.Basis != bad {
			t.Fatalf("解析层必须原样保留值（否则值域校验无从谈起）: %q", gt.Basis)
		}
		gtJSON, err := gt.recordGroundTruth()
		if err != nil {
			t.Fatalf("recordGroundTruth（只做 JSON 往返，不做值域校验）: %v", err)
		}
		if gtJSON.Basis != bad {
			t.Fatalf("回读后 basis = %q, want %q", gtJSON.Basis, bad)
		}
		// 读取层与写出层共用同一个 `Validate`（`MarshalRecord` 经 `ValidateConstruction` 转调它）。
		// 这里刻意用一个**只有 GroundTruth** 的记录：值域校验必须先于其它构造要求触发，
		// 否则"写错的值"会被别的错误信息盖住，操作者永远看不到它。
		rec := edgeexp.Record{GroundTruth: gtJSON}
		if err := rec.Validate(); err == nil {
			t.Fatalf("basis=%q 必须被 Validate 拒掉", bad)
		} else if !strings.Contains(err.Error(), "basis") {
			t.Errorf("拒绝理由必须指向 basis: %v", err)
		}
		// 写出层：`MarshalRecord` 也必须拒（不写半条记录是既有纪律）。
		if _, err := edgeexp.MarshalRecord(rec); err == nil {
			t.Errorf("basis=%q 的记录不得被写出", bad)
		} else if !strings.Contains(err.Error(), "basis") {
			t.Errorf("写出层的拒绝理由也必须指向 basis: %v", err)
		}
	}
}
