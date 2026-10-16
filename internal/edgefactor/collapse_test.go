package edgefactor

import "testing"

// TestCollapseToFactorsIsIdentityForSingleEntry 钉住折叠的**最小性**：每个因子只出现一次时
// （无重复的历史数据集、手写夹具、既有一切夹具），折叠必须**逐位不动**。
//
// 为什么单独钉：折叠若"顺手再算一遍"（例如把重复条目相乘、或对单条目也做一次换算），
// 就会在所有没有重复的历史数据上静默改分 —— 那比原缺陷更难发现。
func TestCollapseToFactorsIsIdentityForSingleEntry(t *testing.T) {
	in := []FactorActivation{
		{FactorID: "EF-NO-IDS", TriggerCheck: "RS-006", EffectiveFactor: 0.88, CTrigger: 1},
		{FactorID: "EF-APPARMOR", TriggerCheck: "OT-005", EffectiveFactor: 0.82, CTrigger: 0.9},
	}
	out := CollapseToFactors(in)
	if len(out) != len(in) {
		t.Fatalf("条目数 = %d, want %d: %+v", len(out), len(in), out)
	}
	byID := map[string]FactorActivation{}
	for _, a := range out {
		byID[a.FactorID] = a
	}
	for _, want := range in {
		got, ok := byID[want.FactorID]
		if !ok {
			t.Fatalf("%s 在折叠后丢失", want.FactorID)
		}
		if got != want {
			t.Errorf("%s：折叠改变了单条目输入 %+v → %+v", want.FactorID, want, got)
		}
	}
}

// TestCollapseToFactorsKeepsStrongestObservation：同名两条时保留**最强观测惩罚**
// （`EffectiveFactor` 最小）的那一条，其余字段原样带走、不做任何算术合成。
func TestCollapseToFactorsKeepsStrongestObservation(t *testing.T) {
	// 真机形态：内置 EF-002FA = 0.70（level4_override）与 custom ef-002fa = 0.85
	// 分别被归一成同一个 ID，且**第二条更弱**。
	in := []FactorActivation{
		{FactorID: "EF-002FA", TriggerCheck: "EF-001", EffectiveFactor: 0.70, CTrigger: 1},
		{FactorID: "ef-002fa", TriggerCheck: "EF-001", EffectiveFactor: 0.85, CTrigger: 1},
	}
	out := CollapseToFactors(in)
	if len(out) != 1 {
		t.Fatalf("条目数 = %d, want 1（大小写不同但归一后是同一个因子）: %+v", len(out), out)
	}
	if out[0].EffectiveFactor != 0.70 {
		t.Errorf("保留的 EffectiveFactor = %v, want 0.70（最强观测惩罚；带 0.85 的那条必须被丢弃，"+
			"且不得与 0.70 做任何算术合成）", out[0].EffectiveFactor)
	}
	if out[0].FactorID != "EF-002FA" {
		t.Errorf("FactorID = %q, want 规范形 EF-002FA", out[0].FactorID)
	}
}

// TestCollapseToFactorsBreaksTiesByFirstOccurrence：并列（`EffectiveFactor` 相等）时保留
// **先出现**的那一条 —— 判据必须确定，不能取决于输入顺序的偶然。
func TestCollapseToFactorsBreaksTiesByFirstOccurrence(t *testing.T) {
	in := []FactorActivation{
		{FactorID: "EF-SELINUX", EffectiveFactor: 0.80, CTrigger: 1, TriggerCheck: "OT-005"},
		{FactorID: "EF-SELINUX", EffectiveFactor: 0.80, CTrigger: 0.5, TriggerCheck: "OTHER"},
	}
	out := CollapseToFactors(in)
	if len(out) != 1 {
		t.Fatalf("条目数 = %d, want 1", len(out))
	}
	if got := out[0].TriggerCheck; got != "OT-005" {
		t.Errorf("并列时保留的条目 TriggerCheck = %q, want 先出现的 OT-005", got)
	}
}

// TestCollapseToFactorsIsDeterministicAndSorted：输出按因子 ID 升序（同输入同输出）。
//
// `Synthesize` 内部用 `sort.Slice`（不稳定）按 ID 排序，重复 ID 的先后此前是未定义的；
// 折叠之后每个 ID 只出现一次，这条不确定性一并消失。
func TestCollapseToFactorsIsDeterministicAndSorted(t *testing.T) {
	in := []FactorActivation{
		{FactorID: "EF-SELINUX", EffectiveFactor: 0.80},
		{FactorID: "EF-APPARMOR", EffectiveFactor: 0.82},
		{FactorID: "EF-APPARMOR", EffectiveFactor: 0.90},
		{FactorID: "EF-NO-IDS", EffectiveFactor: 0.88},
	}
	out := CollapseToFactors(in)
	want := []string{"EF-APPARMOR", "EF-NO-IDS", "EF-SELINUX"}
	if len(out) != len(want) {
		t.Fatalf("条目数 = %d, want %d: %+v", len(out), len(want), out)
	}
	for i, id := range want {
		if out[i].FactorID != id {
			t.Fatalf("顺序 = %+v, want %v", out, want)
		}
	}
	if out[0].EffectiveFactor != 0.82 {
		t.Errorf("EF-APPARMOR 保留的 = %v, want 0.82（最强的观测）", out[0].EffectiveFactor)
	}
}

// TestCollapseToFactorsEmpty：空输入返回空（不 panic、不造出元素）。
func TestCollapseToFactorsEmpty(t *testing.T) {
	if got := CollapseToFactors(nil); len(got) != 0 {
		t.Errorf("nil 输入返回 %+v, want 空", got)
	}
	if got := CollapseToFactors([]FactorActivation{}); len(got) != 0 {
		t.Errorf("空切片输入返回 %+v, want 空", got)
	}
}
