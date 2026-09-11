//go:build engine

package engine

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// allFactorsOn 是「所有边缘因子都未激活」的期望值：六个因子字段全为 1.0。
func allFactorsOn() model.EdgeFactors {
	return model.EdgeFactors{
		TwoFactorFailure:  1.0,
		SYNCookieDisabled: 1.0,
		SELinuxDisabled:   1.0,
		AppArmorDisabled:  1.0,
		NoSIEM:            1.0,
		NoIDS:             1.0,
	}
}

// assertEdgeFactors 逐字段比较（浮点用 1e-9 容差，避免 attenuate 的减法引入的尾数噪声）。
func assertEdgeFactors(t *testing.T, ctx string, got, want model.EdgeFactors) {
	t.Helper()
	fields := []struct {
		name     string
		got, exp float64
	}{
		{"TwoFactorFailure", got.TwoFactorFailure, want.TwoFactorFailure},
		{"SYNCookieDisabled", got.SYNCookieDisabled, want.SYNCookieDisabled},
		{"SELinuxDisabled", got.SELinuxDisabled, want.SELinuxDisabled},
		{"AppArmorDisabled", got.AppArmorDisabled, want.AppArmorDisabled},
		{"NoSIEM", got.NoSIEM, want.NoSIEM},
		{"NoIDS", got.NoIDS, want.NoIDS},
	}
	for _, f := range fields {
		if math.Abs(f.got-f.exp) > 1e-9 {
			t.Errorf("%s: EdgeFactors.%s = %.6f, want %.6f", ctx, f.name, f.got, f.exp)
		}
	}
}

// evalTriggers 用给定配置跑一遍 legacy 边缘因子链，返回结果。
func evalTriggers(cfg *config.Config, checks ...model.CheckResult) model.EdgeFactors {
	a := NewAssessor(cfg)
	result := &model.AssessmentResult{Checks: checks}
	a.evaluateEdgeFactorChain(result)
	return result.EdgeFactors
}

// TestEvaluateEdgeFactorChainAppliesTriggerOverride 是「触发映射单一来源」改造的红测试。
//
// 改造前：`[edge_factors.model] trigger.<factor>` 只被 ssam 路径消费（adapter.go 查默认表 + 覆盖），
// legacy 路径（本函数）只有 EF-001/EF-002 两处内联字面量，配置覆盖在它上面完全失效 ——
// 而 cmd/kernel/engine_on.go 同时装配两条路径，于是同一个配置只对一半生效。
//
// 本测试断言 legacy 路径也按覆盖后的检查 ID 激活因子。
func TestEvaluateEdgeFactorChainAppliesTriggerOverride(t *testing.T) {
	t.Run("覆盖内置因子的触发检查", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}

		got := evalTriggers(cfg, model.CheckResult{
			CheckID: "RS-999", Domain: model.DomainResilience, Passed: false,
		})

		want := allFactorsOn()
		want.NoIDS = 0.88 // 默认表里 EF-NO-IDS 的 Factor
		assertEdgeFactors(t, "trigger.EF-NO-IDS = RS-999", got, want)
	})

	t.Run("覆盖 EF-002FA 的触发检查是替换而非追加", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactors.TwoFactorFailure = 0.85
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-002FA": "EF-100"}

		moved := evalTriggers(cfg, model.CheckResult{
			CheckID: "EF-100", Domain: model.DomainAttackSurface, Passed: false,
		})
		wantMoved := allFactorsOn()
		wantMoved.TwoFactorFailure = 0.85
		assertEdgeFactors(t, "覆盖后的触发检查 EF-100 失败", moved, wantMoved)

		// 与 ssam 路径同一套语义：覆盖是替换 —— 原触发检查 EF-001 不再激活该因子。
		old := evalTriggers(cfg, model.CheckResult{
			CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false,
		})
		assertEdgeFactors(t, "被替换掉的 EF-001 失败", old, allFactorsOn())
	})

	t.Run("空值覆盖不生效（不静默清空触发）", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactors.TwoFactorFailure = 0.85
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-002FA": "   "}

		got := evalTriggers(cfg, model.CheckResult{
			CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false,
		})

		want := allFactorsOn()
		want.TwoFactorFailure = 0.85
		assertEdgeFactors(t, "空白覆盖", got, want)
	})

	t.Run("未覆盖的因子仍按默认表之外的内置分支处理", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}

		got := evalTriggers(cfg, model.CheckResult{
			CheckID: "EF-002", Domain: model.DomainAttackSurface, Passed: false,
		})

		want := allFactorsOn()
		want.TwoFactorFailure = 0.82 // EF-3FA 级联
		assertEdgeFactors(t, "EF-002 级联", got, want)
	})
}

// TestEvaluateEdgeFactorChainDefaultTriggerBehaviorPinned 固化 legacy 路径的默认行为
// （不提供任何 trigger.* 配置时），它是「默认零行为变化」的执行期守卫。
//
// 两个要点：
//   - 改造前 legacy 只按 EF-001 / EF-002 两个检查激活因子（对应默认表 EF-002FA / EF-3FA 两项）；
//   - 默认表里另外五项（RS-005 / OT-005 / RS-007 / RS-006）的触发检查在 legacy 路径上**不生效** ——
//     legacy 的 default 分支是把 check ID 当因子 ID 查表，与触发映射无关。因此把这些默认条目
//     接进 legacy 会**新增**默认激活、改变既有评分；本改造刻意不这么做（详见 assessor.go 注释）。
//     若后续有人把默认表整体接入，本测试会红，迫使那次改动作为独立决策提交。
func TestEvaluateEdgeFactorChainDefaultTriggerBehaviorPinned(t *testing.T) {
	t.Run("EF-001 触发 EF-002FA", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactors.TwoFactorFailure = 0.85
		got := evalTriggers(cfg, model.CheckResult{CheckID: "EF-001", Passed: false})
		want := allFactorsOn()
		want.TwoFactorFailure = 0.85
		assertEdgeFactors(t, "EF-001", got, want)
	})

	t.Run("EF-002 触发 EF-3FA 并把 EF-002FA 级联到 0.82", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactors.TwoFactorFailure = 0.85
		got := evalTriggers(cfg, model.CheckResult{CheckID: "EF-002", Passed: false})
		want := allFactorsOn()
		want.TwoFactorFailure = 0.82
		assertEdgeFactors(t, "EF-002", got, want)
	})

	t.Run("EF-001 与 EF-002 同时失败时级联取 0.82", func(t *testing.T) {
		cfg := config.Default()
		cfg.EdgeFactors.TwoFactorFailure = 0.85
		got := evalTriggers(cfg,
			model.CheckResult{CheckID: "EF-001", Passed: false},
			model.CheckResult{CheckID: "EF-002", Passed: false},
		)
		want := allFactorsOn()
		want.TwoFactorFailure = 0.82
		assertEdgeFactors(t, "EF-001 + EF-002", got, want)
	})

	// 默认表其余五项：legacy 路径上它们**不**激活任何因子（改造前后一致）。
	for _, checkID := range []string{"RS-005", "OT-005", "RS-007", "RS-006"} {
		t.Run("默认触发检查 "+checkID+" 在 legacy 路径上不激活因子", func(t *testing.T) {
			cfg := config.Default()
			cfg.EdgeFactors.TwoFactorFailure = 0.85
			got := evalTriggers(cfg, model.CheckResult{CheckID: checkID, Passed: false})
			assertEdgeFactors(t, checkID, got, allFactorsOn())
		})
	}

	// legacy 的既有 identity 分支：check ID 恰好等于因子 ID 时按该因子的权重激活。
	// 这是改造前就有的语义（default 分支 `customFactors[check.CheckID]`），本改造不得改变它。
	t.Run("check ID 等于因子 ID 时按 identity 分支激活", func(t *testing.T) {
		cfg := config.Default()
		got := evalTriggers(cfg, model.CheckResult{CheckID: "EF-SELINUX", Passed: false})
		want := allFactorsOn()
		want.SELinuxDisabled = 0.80
		assertEdgeFactors(t, "identity EF-SELINUX", got, want)
	})

	t.Run("全部通过时不激活任何因子", func(t *testing.T) {
		cfg := config.Default()
		got := evalTriggers(cfg, model.CheckResult{CheckID: "EF-001", Passed: true})
		assertEdgeFactors(t, "passed", got, allFactorsOn())
	})
}

// TestLegacyDefaultEdgeFactorTableUnchanged 是「默认零行为变化」的静态不变式：
// legacy 内置默认表的六个条目逐字段（Factor + TriggerCheck）等于改造前的硬编码字面量。
//
// 期望值**内联**在测试里（不引用实现中的同一份字面量，也不从 config 默认表推导），
// 否则测试只会证明「实现等于它自己」。同时断言这份默认表的 TriggerCheck 与 config 的
// 出厂默认表描述同一套映射 —— 否则「默认表下沉到 config」只是搬了个名字，两条路径
// 仍可能各说各话（EF-3FA 只存在于 config 表：legacy 用内置分支 + 级联常量表达它）。
func TestLegacyDefaultEdgeFactorTableUnchanged(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactors.TwoFactorFailure = 0.85

	got := legacyDefaultCustomFactors(cfg)
	want := map[string]config.CustomEdgeFactorConfig{
		"EF-002FA":     {Factor: 0.85, TriggerCheck: "EF-001"},
		"EF-SYNCOOKIE": {Factor: 0.75, TriggerCheck: "RS-005"},
		"EF-SELINUX":   {Factor: 0.80, TriggerCheck: "OT-005"},
		"EF-APPARMOR":  {Factor: 0.82, TriggerCheck: "OT-005"},
		"EF-NO-SIEM":   {Factor: 0.90, TriggerCheck: "RS-007"},
		"EF-NO-IDS":    {Factor: 0.88, TriggerCheck: "RS-006"},
	}
	if len(got) != len(want) {
		t.Fatalf("默认表条目数 = %d, want %d (%v)", len(got), len(want), got)
	}
	for id, wantEntry := range want {
		gotEntry, ok := got[id]
		if !ok {
			t.Errorf("默认表缺少条目 %s", id)
			continue
		}
		if gotEntry.Factor != wantEntry.Factor {
			t.Errorf("默认表[%s].Factor = %v, want %v", id, gotEntry.Factor, wantEntry.Factor)
		}
		if gotEntry.TriggerCheck != wantEntry.TriggerCheck {
			t.Errorf("默认表[%s].TriggerCheck = %q, want %q", id, gotEntry.TriggerCheck, wantEntry.TriggerCheck)
		}
	}

	// EF-002FA 的权重沿用既有约定取自 [edge_factors] two_factor_failure，不是常量。
	cfg.EdgeFactors.TwoFactorFailure = 0.42
	if v := legacyDefaultCustomFactors(cfg)["EF-002FA"].Factor; v != 0.42 {
		t.Errorf("EF-002FA 权重应取 [edge_factors] two_factor_failure，got %v", v)
	}

	// 两份表必须描述同一套映射（EF-002FA 的 TriggerCheck 与 config 表一致）。
	resolved := config.ResolveEdgeFactorTriggerMap(cfg)
	for id, entry := range legacyDefaultCustomFactors(cfg) {
		if resolved[id] != entry.TriggerCheck {
			t.Errorf("默认表内容与 config 来源不一致：%s trigger = %q（legacy 表）/ %q（config 表）",
				id, entry.TriggerCheck, resolved[id])
		}
	}
	if resolved["EF-3FA"] != "EF-002" {
		t.Errorf("config 默认表 EF-3FA 触发检查 = %q, want EF-002", resolved["EF-3FA"])
	}
}

// TestEvaluateEdgeFactorChainTriggerOverrideWithCustomFactors 覆盖「生产配置形状」下的
// 覆盖生效路径：出厂模板带 [edge_factors.custom]（键被 parseSections 小写化），
// 此时 legacy 走的是 customFactors 非空分支，覆盖必须同样命中默认表的权重。
func TestEvaluateEdgeFactorChainTriggerOverrideWithCustomFactors(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-002fa":     {Factor: 0.85, TriggerCheck: "EF-001"},
		"ef-syncookie": {Factor: 0.75, TriggerCheck: "RS-005"},
		"ef-selinux":   {Factor: 0.80, TriggerCheck: "OT-005"},
		"ef-apparmor":  {Factor: 0.82, TriggerCheck: "OT-005"},
		"ef-no-siem":   {Factor: 0.90, TriggerCheck: "RS-007"},
		"ef-no-ids":    {Factor: 0.88, TriggerCheck: "RS-006"},
		"ef-3fa":       {Factor: 0.82, TriggerCheck: "EF-002"},
	}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-NO-IDS": "RS-999"}

	got := evalTriggers(cfg, model.CheckResult{CheckID: "RS-999", Passed: false})

	want := allFactorsOn()
	want.NoIDS = 0.88 // legacy 为该因子使用的默认表权重（不因出现 custom 段而改变来源）
	assertEdgeFactors(t, "custom 段非空 + 覆盖", got, want)
}

// TestEvaluateEdgeFactorChainSharesOneCheckAcrossFactors 锁定覆盖映射是「检查 ID → 因子」
// 的一对多关系：默认表里 EF-SELINUX 与 EF-APPARMOR 本就共用 OT-005，操作员把两个因子的
// 触发检查都指向同一个 ID 是合法用法，两个因子都必须激活（用 map[string]string 实现会
// 静默丢掉其中一个 —— 正是本方向要消除的「配了但无效」）。
func TestEvaluateEdgeFactorChainSharesOneCheckAcrossFactors(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactorModel.TriggerMap = map[string]string{
		"EF-SELINUX":  "RS-999",
		"EF-APPARMOR": "RS-999",
	}

	got := evalTriggers(cfg, model.CheckResult{CheckID: "RS-999", Passed: false})

	want := allFactorsOn()
	want.SELinuxDisabled = 0.80
	want.AppArmorDisabled = 0.82
	assertEdgeFactors(t, "两个因子共用 RS-999", got, want)
}

// TestEvaluateEdgeFactorChainOverridesEF3FA 覆盖 EF-3FA：触发检查是替换语义，
// 级联（0.82 → EF-002FA）随因子而非随原检查 ID 走。
func TestEvaluateEdgeFactorChainOverridesEF3FA(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactors.TwoFactorFailure = 0.85
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-3FA": "EF-777"}

	moved := evalTriggers(cfg, model.CheckResult{CheckID: "EF-777", Passed: false})
	wantMoved := allFactorsOn()
	wantMoved.TwoFactorFailure = 0.82 // 级联
	assertEdgeFactors(t, "覆盖后的 EF-3FA 触发检查", moved, wantMoved)

	old := evalTriggers(cfg, model.CheckResult{CheckID: "EF-002", Passed: false})
	assertEdgeFactors(t, "被替换掉的 EF-002", old, allFactorsOn())
}

// TestEvaluateEdgeFactorChainCustomFactorOverrideIsNoOp legacy 输出层只有六个内置槽位
// （model.EdgeFactors 的六个字段），自定义因子即便被覆盖触发也没有承载它的字段 ⇒ 对评分
// 无影响。这条断言把该限制显式化：它不是「配了但静默失效」，而是 legacy 表达不了；
// 自定义因子由 ssam 路径（adapter.ConfigToEdgeFactors，支持自定义因子）承担。
func TestEvaluateEdgeFactorChainCustomFactorOverrideIsNoOp(t *testing.T) {
	cfg := config.Default()
	cfg.EdgeFactorsCustom = map[string]config.CustomEdgeFactorConfig{
		"ef-custom": {Factor: 0.5, TriggerCheck: "RS-001"},
	}
	cfg.EdgeFactorModel.TriggerMap = map[string]string{"EF-CUSTOM": "RS-999"}

	got := evalTriggers(cfg, model.CheckResult{CheckID: "RS-999", Passed: false})
	assertEdgeFactors(t, "自定义因子覆盖", got, allFactorsOn())
}
