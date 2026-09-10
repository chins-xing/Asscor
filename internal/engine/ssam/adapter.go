//go:build engine

package ssam

import (
	"strings"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

func ConfigToWeights(cfg *config.Config) []WeightConfig {
	if cfg == nil {
		return nil
	}
	w := cfg.Weights
	result := []WeightConfig{
		{Domain: model.DomainAttackSurface, Weight: w.AttackSurface},
		{Domain: model.DomainBusinessContinuity, Weight: w.BusinessContinuity},
		{Domain: model.DomainOperationTrust, Weight: w.OperationTrust},
		{Domain: model.DomainResilience, Weight: w.Resilience},
	}
	if w.KernelSecurity != 0 {
		result = append(result, WeightConfig{Domain: model.DomainKernelSecurity, Weight: w.KernelSecurity})
	}
	for domain, weight := range cfg.ExtensionWeights {
		result = append(result, WeightConfig{Domain: domain, Weight: weight})
	}
	return result
}

func ConfigToEdgeFactors(cfg *config.Config) []EdgeFactorConfig {
	if cfg == nil {
		return nil
	}
	triggers := DefaultTriggerMap()
	// 显式覆盖表：自定义因子只认它，不认合并后的默认表（见下方循环内的说明）。
	modelTriggers := cfg.EdgeFactorModel.TriggerMap
	for id, check := range cfg.EdgeFactorModel.TriggerMap {
		// 主控裁定 #5 的第二道防线：空值绝不允许覆盖默认表。写进去等于让该因子
		// 静默失去触发检查（永不激活）。本函数没有 error 通道，报错由同一装配流程里的
		// ParamsFromConfig 承担（见 edgefactor.go validateTriggerOverrides）。
		if strings.TrimSpace(check) == "" {
			continue
		}
		triggers[id] = check
	}
	result := make([]EdgeFactorConfig, 0)
	result = append(result, EdgeFactorConfig{
		ID: "EF-002FA", Name: "2FA Missing",
		Factor: cfg.EdgeFactors.TwoFactorFailure, TriggerCheck: triggers["EF-002FA"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled",
		Factor: cfg.EdgeFactors.SYNCookieDisabled, TriggerCheck: triggers["EF-SYNCOOKIE"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SELINUX", Name: "SELinux Disabled",
		Factor: cfg.EdgeFactors.SELinuxDisabled, TriggerCheck: triggers["EF-SELINUX"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-APPARMOR", Name: "AppArmor Disabled",
		Factor: cfg.EdgeFactors.AppArmorDisabled, TriggerCheck: triggers["EF-APPARMOR"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-SIEM", Name: "SIEM Integration Missing",
		Factor: cfg.EdgeFactors.NoSIEM, TriggerCheck: triggers["EF-NO-SIEM"],
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-IDS", Name: "IDS/IPS Missing",
		Factor: cfg.EdgeFactors.NoIDS, TriggerCheck: triggers["EF-NO-IDS"],
	})
	result = append(result, EdgeFactorConfig{
		ID: ef3FAFactorID, Name: "3FA Not Met",
		Factor: 0.82, TriggerCheck: triggers[ef3FAFactorID], CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true,
	})
	// 已产出的因子 ID（内置六因子 + EF-3FA）。[edge_factors.custom] 里与它们同名的条目一律
	// 忽略：工厂模板会把同样 6 个内置 ID 连同 EF-3FA 重复写进 custom 段，而 ssam-lib 以 ID
	// 为 map 键（ssam.go 的 efMap），ID 归一为大写后同名条目会互相覆盖 —— 实测会让 EF-3FA
	// 的级联字段被「无触发检查」的 custom 副本抹掉，EF-002 失败后不再级联 0.82。
	// 内置因子的权重/触发/级联一律以 [edge_factors] + 模型段触发表为准，与 Params.Factors
	// 的口径（内置优先）保持一致；custom 段只负责增添全新的自定义因子。
	emitted := make(map[string]bool, len(result))
	for _, f := range result {
		emitted[f.ID] = true
	}
	for id, cfg := range cfg.EdgeFactorsCustom {
		// 模型段的 trigger.<factor> 同样覆盖自定义因子（裁定 A）：该键已被装配层的
		// 键面校验列为合法，若在此不消费就又是一条「校验通过但静默无效」的路径。
		// 只认显式配置的覆盖（modelTriggers），不查合并后的默认表 —— 否则内置因子的
		// 默认值会反过来盖掉 [edge_factors.custom_triggers] 里操作员自己写的触发检查，
		// 破坏「未配置模型段时默认行为逐字等价」。
		// 注意 id 来自 parseSections（键被小写化），而 trigger 键在 Task 3 已归一为大写。
		// ID 一律归一为规范大写，与 Params.Factors/Vectors 的键面口径统一（Fix round 2 第 1 项）：
		// 否则 Task 7 拿 EdgeFactorResult.ID 查 Params.Vectors 会查不中，回落成全强度默认向量。
		factorID := canonicalFactorID(id)
		if factorID == "" || emitted[factorID] {
			continue
		}
		emitted[factorID] = true
		triggerCheck := cfg.TriggerCheck
		if override, ok := modelTriggers[factorID]; ok && strings.TrimSpace(override) != "" {
			triggerCheck = override
		}
		result = append(result, EdgeFactorConfig{
			ID: factorID, Name: id, Factor: cfg.Factor, TriggerCheck: triggerCheck,
		})
	}
	return result
}

func CheckResultsToInputs(checks []model.CheckResult) []CheckInput {
	result := make([]CheckInput, len(checks))
	for i, c := range checks {
		result[i] = CheckInput{
			CheckID:    c.CheckID,
			Domain:     c.Domain,
			Name:       c.Name,
			Passed:     c.Passed,
			Delta:      c.Delta,
			Detail:     c.Detail,
			Confidence: c.Confidence,
		}
	}
	return result
}

func DomainScoresToOutput(scores []DomainScore) model.DomainScores {
	ds := model.DomainScores{}
	for _, s := range scores {
		ds.Set(s.Domain, s.Score)
	}
	return ds
}

func DomainScoresFromLegacy(legacy model.DomainScores) map[string]float64 {
	m := legacy.GetAllDomainScores()
	if len(m) == 0 {
		m = map[string]float64{
			model.DomainAttackSurface:      legacy.AttackSurface,
			model.DomainBusinessContinuity: legacy.BusinessContinuity,
			model.DomainOperationTrust:     legacy.OperationTrust,
			model.DomainResilience:         legacy.Resilience,
		}
	}
	return m
}

func EdgeFactorsToModel(factors []EdgeFactorResult) model.EdgeFactors {
	ef := model.EdgeFactors{}
	for _, f := range factors {
		if !f.Active || f.Factor >= 1.0 {
			continue
		}
		switch f.ID {
		case "EF-002FA":
			ef.TwoFactorFailure = f.Factor
		case "EF-SYNCOOKIE":
			ef.SYNCookieDisabled = f.Factor
		case "EF-SELINUX":
			ef.SELinuxDisabled = f.Factor
		case "EF-APPARMOR":
			ef.AppArmorDisabled = f.Factor
		case "EF-NO-SIEM":
			ef.NoSIEM = f.Factor
		case "EF-NO-IDS":
			ef.NoIDS = f.Factor
		}
	}
	return ef
}

func ModelToInput(result *model.AssessmentResult) *AssessmentInput {
	if result == nil {
		return nil
	}
	return &AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Threshold:   result.Threshold,
		Checks:      CheckResultsToInputs(result.Checks),
		ThreatCoeff: result.ThreatCoeff,
		SPCScore:    result.SPCScore,
	}
}

func OutputToModel(output *AssessmentOutput, result *model.AssessmentResult) {
	if output == nil || result == nil {
		return
	}
	result.FinalScore = output.FinalScore
	result.Acceptable = output.Acceptable
	result.DomainScores = DomainScoresToOutput(output.DomainScores)
	result.EdgeFactors = EdgeFactorsToModel(output.EdgeFactors)
	result.ThreatCoeff = output.ThreatCoeff
	result.SPCScore = output.SPCScore
	// Posterior statistics (model-native; zeros when confidence disabled).
	result.FinalSigma = output.FinalSigma
	result.ScoreLower95 = output.Lower95
	result.ScoreUpper95 = output.Upper95
	result.EvidenceConfidence = output.EvidenceConfidence
}

func OutputV2ToModel(output *AssessmentOutputV2, result *model.AssessmentResult) {
	if output == nil || result == nil {
		return
	}
	result.FinalScore = output.FinalScore.Total
	result.Acceptable = output.Acceptable
	result.DomainScores = DomainScoresToOutput(output.DomainScores)
	result.EdgeFactors = EdgeFactorsToModel(output.EdgeFactors)
	result.ThreatCoeff = output.FinalScore.Layers.Threat.Coeff
	result.SPCScore = output.FinalScore.Layers.Exposure.Coeff
}

// ConfigToConfidencePolicy converts the kernel's [confidence] configuration
// into the ssam-library policy. A disabled config yields the library's
// default (disabled) policy — identical legacy behavior.
func ConfigToConfidencePolicy(cfg *config.Config) ConfidencePolicy {
	if cfg == nil || !cfg.Confidence.Enabled {
		return DefaultConfidencePolicy()
	}
	cc := cfg.Confidence
	return ConfidencePolicy{
		Enabled:       true,
		Default:       cc.Default,
		Floor:         cc.Floor,
		PriorStrength: cc.PriorStrength,
	}
}

// ResolveCheckConfidence fills result.Checks[].Confidence from the kernel's
// confidence rule table (design §3). It is a thin wrapper over the shared
// resolver in internal/config so both the plugin (ssam) engine and the legacy
// DynamicScoringEngine consume the same rules. Results that already carry an
// explicit confidence (e.g. agent-set) are preserved.
func ResolveCheckConfidence(cfg *config.Config, result *model.AssessmentResult) {
	if cfg == nil || result == nil {
		return
	}
	cfg.ResolveChecks(result.Checks)
}
