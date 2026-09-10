//go:build engine

package ssam

import (
	"fmt"
	"strings"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ef3FAFactorID 是级联因子 EF-3FA 的 ID。它由 ConfigToEdgeFactors 产出，但既不在
// [edge_factors] 也不在 [edge_factors.custom] 里 —— 它没有权重，却必须能配置触发检查
// （主控裁定 A：此前 trigger.EF-3FA 是静默 no-op）。
const ef3FAFactorID = "EF-3FA"

// DefaultTriggerMap 是现有硬编码触发映射的默认表（adapter.go 原值，含 EF-3FA 的级联入口）。
func DefaultTriggerMap() map[string]string {
	return map[string]string{
		"EF-002FA":     "EF-001",
		"EF-SYNCOOKIE": "RS-005",
		"EF-SELINUX":   "OT-005",
		"EF-APPARMOR":  "OT-005",
		"EF-NO-SIEM":   "RS-007",
		"EF-NO-IDS":    "RS-006",
		ef3FAFactorID:  "EF-002",
	}
}

// legacyOnlyParams 是「未启用」与「出错」两类返回共用的参数集：模型字段全为零值，
// 只把 Model 固定成 legacy。这样「未启用或出错 ⇒ Model == ModelLegacy」这条不变式在
// **每一条**返回路径上都成立，调用方不必区分「零值」与「legacy」两种失败形态
// （Fix round 1 Minor#6）。零值的 p_floor 是刻意的：一旦被误用，edgefactor.Validate
// 会立刻拒绝，而不是带着一个捏造的下限静默算出分数。
func legacyOnlyParams() edgefactor.Params {
	return edgefactor.Params{Model: edgefactor.ModelLegacy}
}

// ParamsFromConfig 把 config 解析结果装配成 edgefactor.Params。
// enabled=false 表示未配置 [edge_factors.model]，调用方必须走 legacy 路径。
//
// 装配层承担 edgefactor.Validate 盲区里的校验 —— Validate 只看得到「已声明的键」，
// 发现不了拼错的因子 ID（它在 Validate 眼里根本不存在，会被静默忽略）：
//   - 裁定 #1：Vectors/Coupling 的键必须 ⊆ Factors 的键；
//   - 裁定 #2：graph 是耦合语义，同一对因子双向配了不同值即歧义，必须报错；
//   - 裁定 #5：空 trigger 值不得覆盖默认表（第二道防线，Task 3 已在解析层拒绝）；
//   - 裁定 A：trigger.<id> 的键必须指向真实存在的因子，否则拼错的键会被静默丢弃。
func ParamsFromConfig(cfg *config.Config) (edgefactor.Params, bool, error) {
	if cfg == nil {
		return legacyOnlyParams(), false, fmt.Errorf("ssam: ParamsFromConfig requires a config, got nil")
	}
	factors := factorWeights(cfg)
	m := cfg.EdgeFactorModel
	// 触发映射与模型无关：ConfigToEdgeFactors 无论走 legacy 还是新模型都消费它，
	// 故键面与空值校验都不放进启用分支（裁定 #5 / 裁定 A）。
	if err := validateTriggerOverrides(m.TriggerMap, knownTriggerFactorIDs(factors)); err != nil {
		return legacyOnlyParams(), false, err
	}
	p := edgefactor.Params{
		Model: edgefactor.ModelLegacy, PFloor: m.PFloor, Lambda: m.Lambda,
		Vectors: m.Vectors, Coupling: m.Coupling, ChainWindowSeconds: m.ChainWindowSeconds,
		Factors: factors,
	}
	if m.Model == "" {
		// 未配置：返回 legacy 参数但标记未启用，调用方保持既有路径。
		// 模型字段一律保持零值（裁定 4 / Fix round 1 Important#1）：不补 p_floor 之类的
		// 占位默认值 —— 未启用路径不得构造出一个「看起来可用」的新模型参数集。
		return p, false, nil
	}
	p.Model = edgefactor.ModelID(m.Model)
	if err := validateAssembly(p); err != nil {
		return legacyOnlyParams(), false, err
	}
	// 结构规则（Σ_d v_i[d] ≤ 1、已声明 vector 覆盖全部域、p_floor ∈ (0,1) 等）只在
	// edgefactor.Validate 里实现一次；启用路径必须走它，让 p_floor 缺失这类错误
	// 在装配处暴露，而不是拖到运行时变成「域分被惩罚下限清零」（裁定 #4）。
	if err := p.Validate(edgefactor.DefaultDomains()); err != nil {
		return legacyOnlyParams(), false, err
	}
	return p, true, nil
}

// NormalizeFactorID 把因子 ID 归一为规范拼写（引擎的 FactorID 约定：全大写），并在
// 查表前使用 —— **产出侧不改 ID，只在消费侧归一**（Fix round 3）。
//
// 语义必须与 internal/config 的 canonicalFactorID 保持一致（定义见
// internal/config/edgefactor.go:218；该函数未导出，无法直接复用，**两处修改务必同步**）。
//
// 为什么需要它：parseSections 会把配置键小写化，于是 [edge_factors.custom] 的条目在
// ConfigToEdgeFactors 里以**小写 ID** 产出（这是改造前就有的既有语义，出厂模板正是靠
// 「大写内置项 + 小写定制副本」两个不同的 map 键让定制值各自计入 —— 见 ssam.go 的 efMap），
// 而 Params.Factors/Vectors 的键面是规范大写（Task 3 已把模型段的 vector./coupling./trigger.
// 键归一为大写）。Task 7 若直接拿 EdgeFactorResult.ID 去查 Params.Vectors，自定义因子会查不中
// 并静默回落成全强度默认向量 —— 用本函数把 ID 归一后再查，即可消除该回落，同时保持产出侧
// 与历史评分逐位一致。
func NormalizeFactorID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// factorWeights 汇总合成层可见的因子权重：内置六因子取自 [edge_factors]（单一事实来源），
// 外加 [edge_factors.custom] 里的自定义因子（Fix round 1 裁定 B：变量化必须覆盖自定义
// 因子，否则 vector.<custom> 会被裁定 1 的「键 ⊆ Factors」直接拒绝）。
//
// 键一律归一为规范大写：parseSections 会把配置键小写化，而 Task 3 已把模型段的因子键
// （vector./coupling./trigger.）归一为大写 —— 不归一的话自定义因子的向量永远匹配不上，
// 裁定 B 想解决的问题只是换了个地方静默发生。
//
// 与内置六因子同名的自定义项（工厂模板把同样 6 个 ID 重复写进 [edge_factors.custom]）
// 不覆盖内置权重：[edge_factors] 是内置因子的单一事实来源，而 legacy 路径的实际行为也是
// 「大写查表查不到小写键 ⇒ 该覆盖从未生效」，此处保持一致而不是悄悄改写内置权重。
func factorWeights(cfg *config.Config) map[string]float64 {
	factors := map[string]float64{
		"EF-002FA":     cfg.EdgeFactors.TwoFactorFailure,
		"EF-SYNCOOKIE": cfg.EdgeFactors.SYNCookieDisabled,
		"EF-SELINUX":   cfg.EdgeFactors.SELinuxDisabled,
		"EF-APPARMOR":  cfg.EdgeFactors.AppArmorDisabled,
		"EF-NO-SIEM":   cfg.EdgeFactors.NoSIEM,
		"EF-NO-IDS":    cfg.EdgeFactors.NoIDS,
	}
	for id, c := range cfg.EdgeFactorsCustom {
		key := NormalizeFactorID(id)
		if key == "" {
			// 畸形配置（`= 0.7` 这类无键行）会产出空键；空因子 ID 不可能被任何
			// vector./coupling./trigger. 键指向，跳过即可（不存在与之配对的配置项，
			// 因此不是静默失配）。
			continue
		}
		if _, ok := factors[key]; ok {
			continue
		}
		factors[key] = c.Factor
	}
	return factors
}

// knownTriggerFactorIDs 返回 trigger.<id> 允许出现的因子 ID 集合（裁定 A）：
// Factors 的全部键（内置六因子 + 自定义因子）再加上 EF-3FA —— 后者是
// ConfigToEdgeFactors 的产出项，也是唯一「存在但不携带权重」的因子。
func knownTriggerFactorIDs(factors map[string]float64) map[string]bool {
	known := make(map[string]bool, len(factors)+1)
	for id := range factors {
		known[id] = true
	}
	known[ef3FAFactorID] = true
	return known
}

// validateAssembly 做键面（裁定 #1）与 graph 对称性（裁定 #2）校验。
func validateAssembly(p edgefactor.Params) error {
	for id := range p.Vectors {
		if _, ok := p.Factors[id]; !ok {
			return fmt.Errorf("ssam: vector for unknown factor id %q — not a factor of [edge_factors] or [edge_factors.custom]", id)
		}
	}
	for from, tos := range p.Coupling {
		if _, ok := p.Factors[from]; !ok {
			return fmt.Errorf("ssam: coupling from unknown factor id %q — not a factor of [edge_factors] or [edge_factors.custom]", from)
		}
		for to := range tos {
			if _, ok := p.Factors[to]; !ok {
				return fmt.Errorf("ssam: coupling to unknown factor id %q — not a factor of [edge_factors] or [edge_factors.custom]", to)
			}
			// 自耦合没有任何语义：Synthesize 在累加耦合项时显式跳过 from.id == to.id
			// （synthesize.go:153-156），所以 coupling.<X>.<X> 只会静默失效。拒绝它，
			// 而不是让操作员以为自己配了一条耦合边（Fix round 2 第 2 项）。
			if from == to {
				return fmt.Errorf("ssam: coupling %s→%s is self-coupling — Synthesize skips i == j, so it would be silently ignored; remove the entry", from, to)
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

// validateTriggerOverrides 校验 trigger.<factor> 的键面与取值（裁定 5 + 裁定 A）。
//
// 键必须指向真实存在的因子（内置六因子、自定义因子或 EF-3FA）：否则一个拼错的键
// （trigger.EF-SELNUX）会连同它本想表达的覆盖一起被静默丢弃。
// 值不得为空或纯空白：空值本身不是「无覆盖」，它会让该因子失去触发检查 ⇒ 永不激活，
// 属于静默失效，必须报错而非静默套用。
func validateTriggerOverrides(overrides map[string]string, known map[string]bool) error {
	for id, check := range overrides {
		if !known[id] {
			return fmt.Errorf("ssam: trigger override for unknown factor id %q — not a factor of [edge_factors] or [edge_factors.custom]", id)
		}
		if strings.TrimSpace(check) == "" {
			return fmt.Errorf("ssam: trigger override for %q is empty — it would leave the factor without a trigger check", id)
		}
	}
	return nil
}

// ActivationFromResult 把引擎侧的一个边缘因子结果换算成合成层的输入项（裁定 3）。
// ok=false 表示该结果未激活，调用方不得把它放进 Input.Factors。
//
// 未激活因子必须在这里被滤掉（Fix round 1 Important#2）：未激活的因子 Factor 为 0，
// 而 EffectiveFactor(0, c) 在 c >= 1 时恰好等于 0，0 又是 Synthesize 里「未提供，
// 回落到配置权重」的哨兵 —— 于是一个根本没触发的因子会按配置权重计入惩罚（静默误评分）。
//
// EffectiveFactor 的精确语义（与合成层实现一致，不要凭直觉改写本注释）：
// c <= 0 → 1（无可信度即不做可信度衰减）；c >= 1 → f；其余 1 − (1−f)·c。
// 因此只有「c >= 1 且 f == 0」时结果才是 0。对于已激活的因子，f == 0 会命中同一个哨兵，
// 其语义是「该因子沿用配置权重」，这是 Synthesize 的既有约定而非缺陷。
//
// triggerCheck 仅用于溯源（Synthesize 不消费该字段），无来源时传 ""。
//
// FactorID 会经 NormalizeFactorID 归一后再填入：合成层的 Vectors / Factors / Coupling
// 三处查表都以规范大写键进行，而未归一的 ID（parseSections 小写化的自定义因子）会让
// Vectors 查表落空、静默回落到「全强度」默认向量 —— 实测 L 由 0.15 变成 0.3。
// 归一写在这里而不是留给调用方，是为了让「激活项的 ID 恒为规范键」成为构造性保证；
// 调用方若还要自己查 Params，同样使用 NormalizeFactorID。
func ActivationFromResult(r EdgeFactorResult, triggerCheck string) (edgefactor.FactorActivation, bool) {
	if !r.Active {
		return edgefactor.FactorActivation{}, false
	}
	return edgefactor.FactorActivation{
		FactorID:        NormalizeFactorID(r.ID),
		TriggerCheck:    triggerCheck,
		CTrigger:        r.TriggerConfidence,
		EffectiveFactor: edgefactor.EffectiveFactor(r.Factor, r.TriggerConfidence),
	}, true
}
