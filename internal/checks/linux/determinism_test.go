//go:build checks

package linux

import (
	"strings"
	"testing"
)

// ============================================================================
// OT-001 的**确定性**钉子（Task 14 W2）
// ============================================================================
//
// 钉住的缺陷：`ot001()` 原来用 `map[string]string` 装"关键文件 → 期望权限"，然后
// `for path, expected := range correctFiles` 往 `issues` 里追加、最后 `strings.Join(issues, "; ")`
// 作为 `Detail`。而 **Go 的 map 迭代顺序是随机的** ⇒ 同一台机器、同一份文件状态下，同一个
// 检查项的 `Detail` 会在多次调用之间**变来变去**。两个后果（第二个才是要害）：
//
//	① `cmd/edgescen` 的 `TestCollectChecksForTargetDefaultsToLocalHostChecks` 判据是
//	   "默认路径的结果与 `runHostChecks()` 逐要素相等"，而两侧各调一次 `Check()`
//	   ⇒ 约 2/3 概率报红（`4fc5859` 干净树上实测 3/4 红）。那是**假红**，会让人去查错误的
//	   地方（历史上有过一整轮被这条带偏）。
//	② **与"数据可复现"直接冲突**：检查明细属于落盘记录的一部分（`checks[].detail`），
//	   同一状态两次采集写出的字节不同 ⇒ 记录无法逐字节比对，"同源则同"的判据失效。
//
// 本用例的两条判据（都**不依赖机器状态**，除了下面那条显式的 skip）：
//  1. **声明次序**：`ot001CriticalFiles` 的路径序列逐字等于
//     `/etc/shadow,/etc/gshadow,/etc/sudoers,/etc/passwd`（顺序是代码里的声明，改它必须
//     同时改这条断言 —— 这是"顺序不再随机"的正面证据）；
//  2. **逐字稳定**：连调 50 次，`Detail` 与 `ok` **逐字相同**，且（当确实有问题项时）
//     问题项在 `Detail` 里出现的先后与声明次序一致。
//
// 为什么要连调 50 次：旧实现的失败概率是"每对调用有 1/k! 的概率碰巧同序"（k = 问题项数）。
// 实测机器上 k≥2 ⇒ 单对已经有一半概率不同；50 次全同的概率在旧实现下 ≤ 2^-49 ⇒ 这条
// 用例在缺陷版上**几乎必然红**（Task 14 的执行记录里给了"改之前红、改之后绿"的原始输出）。
//
// 显式 skip：若这台机器上四个文件全都"没问题"（`Detail` 是成功文案），那就没有顺序可判 ——
// 这时用例**不假装通过**，而是 skip 并把原因打出来（判据 1 仍然照跑）。
func TestOT001DetailIsDeterministic(t *testing.T) {
	const wantOrder = "/etc/shadow,/etc/gshadow,/etc/sudoers,/etc/passwd"
	paths := make([]string, 0, len(ot001CriticalFiles))
	for _, f := range ot001CriticalFiles {
		paths = append(paths, f.Path)
	}
	if got := strings.Join(paths, ","); got != wantOrder {
		t.Fatalf("关键文件表的声明次序变了：\n got %s\nwant %s\n"+
			"（次序会进 `Detail` 的字节 ⇒ 改它必须同时改这条断言与 ot001CriticalFiles 的注释）",
			got, wantOrder)
	}
	if len(ot001CriticalFiles) < 2 {
		t.Fatalf("关键文件表只有 %d 项 ⇒ 下面的顺序判据失去意义", len(ot001CriticalFiles))
	}

	const rounds = 50
	ok0, detail0 := ot001().Check()
	for i := 1; i < rounds; i++ {
		okI, detailI := ot001().Check()
		if okI != ok0 || detailI != detail0 {
			t.Fatalf("第 %d 次调用与第 1 次**不同** —— 同一个检查项的明细必须逐字可复现"+
				"（map 迭代顺序是随机的；见本文件头）:\n 1) ok=%v detail=%q\n%2d) ok=%v detail=%q",
				i+1, ok0, detail0, i+1, okI, detailI)
		}
	}

	if detail0 == "关键文件权限配置正确" {
		t.Skipf("本机四个关键文件都对得上期望权限（`Detail` = %q）⇒ 没有问题项、也就没有次序可判；"+
			"判据 1（声明次序）已经跑过了", detail0)
	}

	// 问题项在 `Detail` 里按**声明次序**出现（而不是任意次序）。
	prev := -1
	for _, f := range ot001CriticalFiles {
		at := strings.Index(detail0, f.Path+" ") // 两种消息形态都是 "<路径> " 开头
		if at < 0 {
			continue
		}
		if at < prev {
			t.Fatalf("`Detail` 里问题项的次序与声明次序不符：%q 在 %d 处，而它前面那一项的偏移是 %d\n"+
				"detail=%q", f.Path, at, prev, detail0)
		}
		prev = at
	}
	t.Logf("OT-001 明细在 %d 次调用中逐字稳定：%q", rounds, detail0)
}

// TestOT001DetailFormatUnchanged 把**输出格式**钉成字节级契约（Task 14 修 W2 的前提）：
// 修"顺序"不许顺手改格式 —— `名称 权限=X (期望=Y)`、问题项之间 `; ` 连接、一个都不能变。
// 做法：拿真实文件系统造不出来的两件事分开验 ——
//
//	· 成功文案与"存在"分支的措辞在这里按字面锁定（改文案会让这条红）；
//	· 真正的格式化分支（`mode != expected`）在真实机器上依赖 `/etc/*` 的实际权限，
//	  本用例不复制实现，只断言"若出现权限问题，它恰好是这个形状"。
func TestOT001DetailFormatUnchanged(t *testing.T) {
	ok, detail := ot001().Check()
	if ok && detail != "关键文件权限配置正确" {
		t.Fatalf("全部通过时的文案变了：%q", detail)
	}
	if detail == "" {
		t.Fatalf("`Detail` 不得为空串（记录里的 detail 字段不允许空）")
	}
	for _, seg := range strings.Split(detail, "; ") {
		if seg == "关键文件权限配置正确" {
			continue
		}
		// 只允许两种形状：`<路径> 不存在` 或 `<路径> 权限=<4 位八进制> (期望=<期望>)`
		if strings.HasSuffix(seg, " 不存在") {
			continue
		}
		if !strings.Contains(seg, " 权限=") || !strings.HasSuffix(seg, ")") ||
			!strings.Contains(seg, "(期望=") {
			t.Fatalf("问题项的措辞变了（格式是记录的一部分，不许改）：%q（整串 %q）", seg, detail)
		}
	}
}
