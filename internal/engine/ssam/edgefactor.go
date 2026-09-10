//go:build engine

package ssam

import (
	"fmt"
	"strings"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// DefaultTriggerMap 是现有硬编码触发映射的默认表（adapter.go 原值）。
func DefaultTriggerMap() map[string]string {
	return map[string]string{
		"EF-002FA":     "EF-001",
		"EF-SYNCOOKIE": "RS-005",
		"EF-SELINUX":   "OT-005",
		"EF-APPARMOR":  "OT-005",
		"EF-NO-SIEM":   "RS-007",
		"EF-NO-IDS":    "RS-006",
	}
}

// ParamsFromConfig 把 config 解析结果装配成 edgefactor.Params。
// enabled=false 表示未配置 [edge_factors.model]，调用方必须走 legacy 路径。
//
// 装配层在 brief 之外承担主控裁决的三条额外校验，因为三者都落在
// edgefactor.Validate 的盲区里 —— Validate 只看得到「已声明的键」，发现不了
// 拼错的因子 ID（它在 Validate 眼里根本不存在，会被静默忽略）：
//   - 裁定 #1：Vectors/Coupling 的键必须 ⊆ Factors 的键；
//   - 裁定 #2：graph 是耦合语义，同一对因子双向配了不同值即歧义，必须报错；
//   - 裁定 #5：空 trigger 值不得覆盖默认表（第二道防线，Task 3 已在解析层拒绝）。
func ParamsFromConfig(cfg *config.Config) (edgefactor.Params, bool, error) {
	if cfg == nil {
		return edgefactor.Params{}, false, fmt.Errorf("ssam: ParamsFromConfig requires a config, got nil")
	}
	factors := map[string]float64{
		"EF-002FA":     cfg.EdgeFactors.TwoFactorFailure,
		"EF-SYNCOOKIE": cfg.EdgeFactors.SYNCookieDisabled,
		"EF-SELINUX":   cfg.EdgeFactors.SELinuxDisabled,
		"EF-APPARMOR":  cfg.EdgeFactors.AppArmorDisabled,
		"EF-NO-SIEM":   cfg.EdgeFactors.NoSIEM,
		"EF-NO-IDS":    cfg.EdgeFactors.NoIDS,
	}
	m := cfg.EdgeFactorModel
	// 触发映射与模型无关：ConfigToEdgeFactors 无论走 legacy 还是新模型都消费它，
	// 故空值校验不放进启用分支（裁定 #5）。
	if err := validateTriggerOverrides(m.TriggerMap); err != nil {
		return edgefactor.Params{}, false, err
	}
	p := edgefactor.Params{
		Model: edgefactor.ModelLegacy, PFloor: m.PFloor, Lambda: m.Lambda,
		Vectors: m.Vectors, Coupling: m.Coupling, ChainWindowSeconds: m.ChainWindowSeconds,
		Factors: factors,
	}
	if m.Model == "" {
		// 未配置：返回 legacy 参数但标记未启用，调用方保持既有路径。
		// 这里只补一个占位 p_floor，不做任何校验、不注册任何策略（裁定 #4）：
		// 未启用路径不得构造出一个「看起来可用」的新模型参数集。
		if p.PFloor == 0 {
			p.PFloor = 0.5
		}
		return p, false, nil
	}
	p.Model = edgefactor.ModelID(m.Model)
	if err := validateAssembly(p); err != nil {
		return edgefactor.Params{}, false, err
	}
	// 结构规则（Σ_d v_i[d] ≤ 1、已声明 vector 覆盖全部域、p_floor ∈ (0,1) 等）只在
	// edgefactor.Validate 里实现一次；启用路径必须走它，让 p_floor 缺失这类错误
	// 在装配处暴露，而不是拖到运行时变成「域分被惩罚下限清零」（裁定 #4）。
	if err := p.Validate(edgefactor.DefaultDomains()); err != nil {
		return edgefactor.Params{}, false, err
	}
	return p, true, nil
}

// validateAssembly 做键面（裁定 #1）与 graph 对称性（裁定 #2）校验。
func validateAssembly(p edgefactor.Params) error {
	for id := range p.Vectors {
		if _, ok := p.Factors[id]; !ok {
			return fmt.Errorf("ssam: vector for unknown factor id %q — not a factor of [edge_factors]", id)
		}
	}
	for from, tos := range p.Coupling {
		if _, ok := p.Factors[from]; !ok {
			return fmt.Errorf("ssam: coupling from unknown factor id %q — not a factor of [edge_factors]", from)
		}
		for to := range tos {
			if _, ok := p.Factors[to]; !ok {
				return fmt.Errorf("ssam: coupling to unknown factor id %q — not a factor of [edge_factors]", to)
			}
		}
	}
	if p.Model != edgefactor.ModelGraph {
		// chain 是有向时序语义，双向不同值合法；vector/legacy 不消费耦合项。
		return nil
	}
	for from, tos := range p.Coupling {
		for to, c := range tos {
			if from > to {
				continue // 每对只报一次，固定从字典序小的一侧检查
			}
			other, ok := p.Coupling[to][from]
			if !ok || other == c {
				continue
			}
			return fmt.Errorf("ssam: graph coupling %s→%s = %v conflicts with %s→%s = %v — graph is symmetric, pick one value", from, to, c, to, from, other)
		}
	}
	return nil
}

// validateTriggerOverrides 拒绝空的 trigger 覆盖值（裁定 #5）。空值本身不是「无覆盖」：
// 它会让该因子失去触发检查 ⇒ 永不激活，属于静默失效，必须报错而非静默套用。
func validateTriggerOverrides(overrides map[string]string) error {
	for id, check := range overrides {
		if strings.TrimSpace(check) == "" {
			return fmt.Errorf("ssam: trigger override for %q is empty — it would leave the factor without a trigger check", id)
		}
	}
	return nil
}

// ActivationFromResult 把引擎侧的一个边缘因子结果换算成合成层的输入项（裁定 #3）。
//
// CTrigger 不进 Synthesize：合成层只读 EffectiveFactor，因此这里必须用
// edgefactor.EffectiveFactor(f, c) 把（配置权重, 触发可信度）换算后再填入。
// 直接塞原始 c 是错的：c > 1 会被合成层的 (0,1] 校验拒掉，而 c ≤ 1 时它还会
// 悄悄丢掉方向① 的可信度衰减语义（c=0.5、f=0.8 → 0.9，不是 0.5）。
//
// triggerCheck 仅用于溯源（Synthesize 不消费该字段），无来源时传 ""。
// 调用方必须先滤掉未激活的因子：Factor == 0 会让 effective 也等于 0，而 0 在
// Synthesize 里是「未提供，回落到配置权重」的哨兵，语义与「无惩罚」不同。
func ActivationFromResult(r EdgeFactorResult, triggerCheck string) edgefactor.FactorActivation {
	return edgefactor.FactorActivation{
		FactorID:        r.ID,
		TriggerCheck:    triggerCheck,
		CTrigger:        r.TriggerConfidence,
		EffectiveFactor: edgefactor.EffectiveFactor(r.Factor, r.TriggerConfidence),
	}
}
