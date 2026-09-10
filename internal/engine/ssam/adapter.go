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
	// [edge_factors.custom] 的条目**原样产出**（ID 大小写保持解析结果，不去重、不跳过）：
	// ssam-lib 以 ID 为 map 键（ssam.go 的 efMap），大写内置项与小写 custom 条目本是两个
	// 不同的键、各自计入 —— 这是出厂配置下既有的实际语义（custom 段是按行业定制的
	// **额外惩罚项**，不是覆盖项）。任何归一化或去重都会改变出厂配置的乘子，违反 P4
	// 「默认 legacy 与历史评分逐位一致」。大小写归一改在**消费侧**做（见 NormalizeFactorID）。
	for id, cfg := range cfg.EdgeFactorsCustom {
		// 模型段的 trigger.<factor> 覆盖自定义因子的触发检查（裁定 A）：该键已被装配层的
		// 键面校验列为合法，若在此不消费就又是一条「校验通过但静默无效」的路径。
		// 只认显式配置的覆盖（modelTriggers），不查合并后的默认表 —— 否则内置因子的
		// 默认值会反过来盖掉 [edge_factors.custom_triggers] 里操作员自己写的触发检查。
		// 查表前做大小写归一（id 来自 parseSections，键被小写化；trigger 键在 Task 3 已归一大写），
		// 但产出的 ID 本身保持原样，条目集合与改造前逐项一致。
		triggerCheck := cfg.TriggerCheck
		if override, ok := modelTriggers[NormalizeFactorID(id)]; ok && strings.TrimSpace(override) != "" {
			triggerCheck = override
		}
		result = append(result, EdgeFactorConfig{
			ID: id, Name: id, Factor: cfg.Factor, TriggerCheck: triggerCheck,
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
