//go:build expr && engine && checks

package main

import (
	"fmt"
	"sort"
	"strings"
)

// 场景表（spec §5 的实验矩阵：S0–S5 共 22 组 + R 组 3 个真实缺失对照）。
//
// 表的每一项都必须对应**可执行的注入规格**，不留占位：`Inject` 的每个元素是"同一时刻注入"
// 的因子组，组内因子在当前配置下解析出的触发检查被强制判为失败；组的先后即**注入顺序**。
//
// 三条设计纪律（改表前先读）：
//
//  1. **因子 ID 是规范形**（`EF-SELINUX`，不是展示名 `selinux_disabled`）：注入按因子解析
//     触发检查，写错 ID 会让 `ResolveEdgeFactorTriggerMap` 查空 ⇒ 该场景其实什么都没注入。
//     规范 ID 同时是 `edgeexp.ValidateConstruction` 的记录构造要求。
//  2. **顺序注入（`len(Inject) > 1`）是为了给 C 候选留可分辨的时间结构**：链模型的严格时间窗
//     （`from.ts.Before(to.ts)`）要求相邻观测真的有先后；全部同刻注入的场景在这条数据上
//     C ≡ V，那是**如实结果**（"无时间结构时 C 不该凭空变好"的反向证据），但 S5 级联组与
//     至少两组 S2/S3 子场景必须采到两个不同时刻（见 TestSequentialScenariosExistForTheChainModel）。
//  3. **不注入的场景**（S0 基线、R 组）：S0 什么都不激活；R 组靠在目标机上**真的停掉服务**
//     让真实检查自然失败（`RealMissing` 是对照的声明面，采集器不做任何注入）。
type scenarioSpec struct {
	// Factors 是本场景**声明激活**的因子（规范 ID，按 spec §5 的组定义）。
	Factors []string
	// Inject 是注入计划：每个元素是"同一时刻注入"的因子组，按顺序依次注入。
	// 注入 = 把该因子在当前配置下**实际解析出的触发检查**判为失败（不是硬编码检查 ID：
	// 触发映射的唯一来源是 `config.ResolveEdgeFactorTriggerMap`，运营者覆盖过的部署算后者）。
	Inject [][]string
	// CascadeTo 是级联场景的**观测目标**：EF-3FA 是 CascadeOnly（自身不上链），它的影响
	// 体现在被级联的因子上。只有 S5 级联组需要它。
	CascadeTo string
	// RealMissing 是 R 组的真实缺失项（停 IDS / 去 SIEM / 去 2FA）。它不驱动注入，
	// 只作为"这个场景靠真实缺失、不靠注入"的声明面，并写进 `injection = real_missing`。
	RealMissing []string
}

// cascadeFactorID 是唯一带级联的因子（spec §5 / 附录 B：EF-3FA → EF-002FA，CascadeOnly）。
// 采它的唯一用途是"期望链上出现的因子"推导：EF-3FA 自己不上链，上链的是它的级联目标。
const cascadeFactorID = "EF-3FA"

var scenarios = map[string]scenarioSpec{
	// ---- S0：基线（无因子）----------------------------------------------------
	"S0-baseline": {},

	// ---- S1：单因子各自激活（主效应 β_i）-------------------------------------
	"S1-selinux":    {Factors: []string{"EF-SELINUX"}, Inject: [][]string{{"EF-SELINUX"}}},
	"S1-apparmor":   {Factors: []string{"EF-APPARMOR"}, Inject: [][]string{{"EF-APPARMOR"}}},
	"S1-syn-cookie": {Factors: []string{"EF-SYNCOOKIE"}, Inject: [][]string{{"EF-SYNCOOKIE"}}},
	"S1-no-siem":    {Factors: []string{"EF-NO-SIEM"}, Inject: [][]string{{"EF-NO-SIEM"}}},
	"S1-no-ids":     {Factors: []string{"EF-NO-IDS"}, Inject: [][]string{{"EF-NO-IDS"}}},
	"S1-2fa":        {Factors: []string{"EF-002FA"}, Inject: [][]string{{"EF-002FA"}}},

	// ---- S2：两两共存（对称交互 c_ij）----------------------------------------
	// 前四组是 brief 指定的"同源/可疑耦合"优先组：
	//   * selinux+apparmor  **共用触发检查 OT-005**（耦合先验的实证）；
	//   * selinux+no-ids / no-siem+no-ids / syn-cookie+no-siem 覆盖跨域组合。
	"S2-selinux-apparmor":   {Factors: []string{"EF-SELINUX", "EF-APPARMOR"}, Inject: [][]string{{"EF-SELINUX", "EF-APPARMOR"}}},
	"S2-selinux-no-ids":     {Factors: []string{"EF-SELINUX", "EF-NO-IDS"}, Inject: [][]string{{"EF-SELINUX", "EF-NO-IDS"}}},
	"S2-no-siem-no-ids":     {Factors: []string{"EF-NO-SIEM", "EF-NO-IDS"}, Inject: [][]string{{"EF-NO-SIEM"}, {"EF-NO-IDS"}}},     // 顺序：同域（监测缺失）、不同触发检查
	"S2-syn-cookie-no-siem": {Factors: []string{"EF-SYNCOOKIE", "EF-NO-SIEM"}, Inject: [][]string{{"EF-SYNCOOKIE", "EF-NO-SIEM"}}}, // 同域（resilience）
	// 另四组按"同域/共触发/级联相关"补齐到 spec §5 的 8 组：
	"S2-apparmor-no-ids":   {Factors: []string{"EF-APPARMOR", "EF-NO-IDS"}, Inject: [][]string{{"EF-APPARMOR", "EF-NO-IDS"}}},     // 共触发 OT-005 的另一半 + 监测缺失
	"S2-selinux-no-siem":   {Factors: []string{"EF-SELINUX", "EF-NO-SIEM"}, Inject: [][]string{{"EF-SELINUX"}, {"EF-NO-SIEM"}}},   // 顺序：执行强制 + 监测缺失
	"S2-2fa-selinux":       {Factors: []string{"EF-002FA", "EF-SELINUX"}, Inject: [][]string{{"EF-002FA", "EF-SELINUX"}}},         // 级联目标 + 共触发因子
	"S2-syn-cookie-no-ids": {Factors: []string{"EF-SYNCOOKIE", "EF-NO-IDS"}, Inject: [][]string{{"EF-SYNCOOKIE"}, {"EF-NO-IDS"}}}, // 顺序：同域（resilience）

	// ---- S3：三因子共存（高阶与饱和行为）-------------------------------------
	"S3-selinux-apparmor-2fa": {Factors: []string{"EF-SELINUX", "EF-APPARMOR", "EF-002FA"},
		Inject: [][]string{{"EF-SELINUX", "EF-APPARMOR"}, {"EF-002FA"}}}, // 顺序：先同源对（OT-005），再 2FA
	"S3-selinux-no-siem-no-ids": {Factors: []string{"EF-SELINUX", "EF-NO-SIEM", "EF-NO-IDS"},
		Inject: [][]string{{"EF-SELINUX"}, {"EF-NO-SIEM", "EF-NO-IDS"}}},
	"S3-syn-cookie-no-siem-no-ids": {Factors: []string{"EF-SYNCOOKIE", "EF-NO-SIEM", "EF-NO-IDS"},
		Inject: [][]string{{"EF-SYNCOOKIE"}, {"EF-NO-SIEM"}, {"EF-NO-IDS"}}},
	// 含 EF-3FA 的三方组：级联因子 + 共用 OT-005 的同源对（最高耦合先验的一组）
	"S3-3fa-selinux-apparmor": {Factors: []string{cascadeFactorID, "EF-SELINUX", "EF-APPARMOR"},
		Inject:    [][]string{{cascadeFactorID}, {"EF-SELINUX", "EF-APPARMOR"}},
		CascadeTo: "EF-002FA"},

	// ---- S4：全因子共存（上限与 P_floor 验证）--------------------------------
	"S4-all": {Factors: []string{"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR", "EF-NO-SIEM", "EF-NO-IDS"},
		Inject: [][]string{{"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR", "EF-NO-SIEM", "EF-NO-IDS"}}},

	// ---- S5：级联 vs 独立（C 模型核心）---------------------------------------
	// 级联组天然是顺序注入：先让 EF-002 失败触发 EF-3FA（它本身 CascadeOnly 不上链），
	// 级联把 EF-002FA 压到 0.82；再让 EF-001 失败直接触发 EF-002FA —— 两条观测时刻不同，
	// 这正是 C 与 V 可分辨的那条数据。
	"S5-cascade-3fa": {Factors: []string{cascadeFactorID},
		Inject:    [][]string{{cascadeFactorID}, {"EF-002FA"}},
		CascadeTo: "EF-002FA"},
	"S5-2fa-only": {Factors: []string{"EF-002FA"}, Inject: [][]string{{"EF-002FA"}}},

	// ---- R：真实缺失对照（不注入，靠目标机上真的停掉服务）--------------------
	"R-no-ids":  {Factors: []string{"EF-NO-IDS"}, RealMissing: []string{"ids"}},
	"R-no-siem": {Factors: []string{"EF-NO-SIEM"}, RealMissing: []string{"siem"}},
	"R-no-2fa":  {Factors: []string{"EF-002FA"}, RealMissing: []string{"2fa"}},
}

// injectionKind 是记录里 `injection` 字段的取值。
//
// spec §5.1 的示例用 `check_fail`；本工具在此之上只有两个取值：
// `none`（S0 基线：什么都没注入）与 `real_missing`（R 组：靠目标机上真实的缺失）。
// 三者的区别是**实验方法**的区别，必须落进记录本体，否则"这条记录的因子为什么激活"
// 在事后无从判断（注入失败与自然失败的操作含义完全不同）。
func (s scenarioSpec) injectionKind() string {
	switch {
	case len(s.RealMissing) > 0:
		return "real_missing"
	case len(s.Inject) == 0:
		return "none"
	default:
		return "check_fail"
	}
}

// sequential 报告本场景是否按"分先后注入"设计（两个以上注入阶段）。
//
// 判据只看注入计划的阶段数，不看注入时刻 —— 时刻由 harness 提供，采集器不参与决定顺序。
func (s scenarioSpec) sequential() bool { return len(s.Inject) > 1 }

// injectedFactors 返回注入计划里出现的因子（按阶段顺序，保留重复）。
func (s scenarioSpec) injectedFactors() []string {
	var out []string
	for _, phase := range s.Inject {
		out = append(out, phase...)
	}
	return out
}

// expectedChainFactors 返回"这条记录的观测链上**必须**出现的因子"。
//
// 与 `Factors` 的区别：`Factors` 是**注入声明**（要注入什么），这里是**观测断言**（必须观察到什么）。
// 两者在级联场景上分叉 —— EF-3FA 是 CascadeOnly，注入它不会让它自己上链，上链的是级联目标
// （`CascadeTo`）；把期望写成 `Factors` 会让 S5 级联组永远判失败。
//
// R 组不注入：期望就是声明的因子本身（真实缺失必须让对应检查真的失败，否则这次对照没跑对）。
func (s scenarioSpec) expectedChainFactors() []string {
	injected := s.injectedFactors()
	if len(injected) == 0 {
		return append([]string(nil), s.Factors...)
	}
	var out []string
	for _, f := range injected {
		if f == cascadeFactorID && s.CascadeTo != "" {
			out = append(out, s.CascadeTo)
			continue
		}
		out = append(out, f)
	}
	return out
}

// scenarioNames 返回按字典序排序的全部场景名（矩阵脚本按它迭代，顺序必须可复现）。
func scenarioNames() []string {
	names := make([]string, 0, len(scenarios))
	for name := range scenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// lookupScenario 按名字取场景定义，错误信息里带上全部可用名字。
func lookupScenario(name string) (scenarioSpec, error) {
	spec, ok := scenarios[name]
	if !ok {
		return scenarioSpec{}, fmt.Errorf("未知场景 %q —— 可用场景（%d 组）：%s",
			name, len(scenarios), strings.Join(scenarioNames(), " "))
	}
	return spec, nil
}
