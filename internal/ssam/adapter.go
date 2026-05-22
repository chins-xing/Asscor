package ssam

import (
	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/model"
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
	result := make([]EdgeFactorConfig, 0)
	result = append(result, EdgeFactorConfig{
		ID: "EF-002FA", Name: "2FA Missing",
		Factor: cfg.EdgeFactors.TwoFactorFailure, TriggerCheck: "EF-001",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled",
		Factor: cfg.EdgeFactors.SYNCookieDisabled, TriggerCheck: "EF-SYNCOOKIE",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-SELINUX", Name: "SELinux Disabled",
		Factor: cfg.EdgeFactors.SELinuxDisabled, TriggerCheck: "EF-SELINUX",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-APPARMOR", Name: "AppArmor Disabled",
		Factor: cfg.EdgeFactors.AppArmorDisabled, TriggerCheck: "EF-APPARMOR",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-SIEM", Name: "SIEM Integration Missing",
		Factor: cfg.EdgeFactors.NoSIEM, TriggerCheck: "EF-NO-SIEM",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-NO-IDS", Name: "IDS/IPS Missing",
		Factor: cfg.EdgeFactors.NoIDS, TriggerCheck: "EF-NO-IDS",
	})
	result = append(result, EdgeFactorConfig{
		ID: "EF-3FA", Name: "3FA Not Met",
		Factor: 0.82, TriggerCheck: "EF-002", CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true,
	})
	for id, factor := range cfg.EdgeFactorsCustom {
		result = append(result, EdgeFactorConfig{
			ID: id, Name: id, Factor: factor,
		})
	}
	return result
}

func CheckResultsToInputs(checks []model.CheckResult) []CheckInput {
	result := make([]CheckInput, len(checks))
	for i, c := range checks {
		result[i] = CheckInput{
			CheckID: c.CheckID,
			Domain:  c.Domain,
			Name:    c.Name,
			Passed:  c.Passed,
			Delta:   c.Delta,
			Detail:  c.Detail,
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
		Timestamp:   result.Timestamp,
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
}
