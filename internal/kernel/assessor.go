package kernel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/ssam"
)

type AssessorModule struct {
	kernel KernelContext
	cfg    *config.Config
	engine *engine.Assessor

	mu      sync.RWMutex
	results map[string]*model.AssessmentResult

	state PluginState
}

func (m *AssessorModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "assessor",
		Version:     "1.2.0",
		Description: "ASSCOR assessment engine — computes domain scores and final acceptability score",
		Author:      "ASSCOR Core Team",
	}
}

func (m *AssessorModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "config", Interface: (*config.Config)(nil)},
	}
}

func (m *AssessorModule) Priority() int {
	return 40
}

func (m *AssessorModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized
	m.results = make(map[string]*model.AssessmentResult)

	if impl, ok := kc.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	m.engine = engine.NewAssessor(m.cfg)

	kc.Container().Bind((*ssam.ScoringProvider)(nil), m.engine.SSAMEngine())

	warnings := m.engine.ValidateEdgeFactors(checks.GetAll())
	for _, w := range warnings {
		logger.WithComponent("assessor").Warn("edge factor warning", "warning", w)
	}

	kc.Container().Bind((*AssessorInterface)(nil), m)

	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "assessor.pre_evaluate",
		Description: "Called before each host assessment",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "assessor.post_evaluate",
		Description: "Called after each host assessment completes",
		Version:     "1.0",
	})

	return nil
}

func (m *AssessorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	logger.WithComponent("assessor").Info("started")
	return nil
}

func (m *AssessorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("assessor")
	m.state = PluginStopped
	logger.WithComponent("assessor").Info("stopped")
	return nil
}

func (m *AssessorModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *AssessorModule) HealthCheck(ctx context.Context) error {
	if m.state != PluginStarted {
		return fmt.Errorf("assessor not started (state=%s)", m.state)
	}
	if m.engine == nil {
		return fmt.Errorf("assessor engine is nil")
	}
	return nil
}

func (m *AssessorModule) Evaluate(hostID string) *model.AssessmentResult {
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)

	result := m.engine.Assess(hostID, hostID)

	m.applySPCAndCTI(hostID, result)
	m.applyATTACK(hostID, result)

	if result.SPCScore != 1.0 || result.ThreatCoeff != m.cfg.ThreatCoeff {
		result.FinalScore = m.recomputeFinalScore(result)
		result.Acceptable = result.FinalScore >= result.Threshold
	}

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", result)

	if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
		Topic:   TopicAssessorResult,
		Payload: result,
		Source:  "assessor",
	}); len(errs) > 0 {
		logger.WithComponent("assessor").Warn("sync publish errors", "count", len(errs))
	}

	return result
}

func (m *AssessorModule) EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult {
	logger.WithComponent("assessor").Info("EvaluateFromResults called", "host_id", hostID, "checks", len(checkResults))

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)

	result := &model.AssessmentResult{
		HostID:    hostID,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: m.cfg.Threshold,
		Checks:    checkResults,
	}

	if len(result.Checks) == 0 {
		result.Acceptable = true
		result.FinalScore = 100
		result.DomainScores = model.DomainScores{
			AttackSurface:      100,
			BusinessContinuity: 100,
			OperationTrust:     100,
			Resilience:         100,
		}
		result.ThreatCoeff = m.cfg.ThreatCoeff
		result.SPCScore = 1.0
	} else {
		m.applySPCAndCTI(hostID, result)
		m.applyATTACK(hostID, result)
		result.FinalScore = m.recomputeFinalScore(result)
	}

	logger.WithComponent("assessor").Info("assessment score computed", "host_id", hostID, "score", result.FinalScore, "spc_score", result.SPCScore, "threat_coeff", result.ThreatCoeff)

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", result)

	subCount := m.kernel.Bus().SubscriberCount(TopicAssessorResult)
	logger.WithComponent("assessor").Debug("publishing assessor.result", "subscribers", subCount)

	if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
		Topic:   TopicAssessorResult,
		Payload: result,
		Source:  "assessor",
	}); len(errs) > 0 {
		logger.WithComponent("assessor").Warn("sync publish errors", "count", len(errs))
	}

	return result
}

func (m *AssessorModule) applySPCAndCTI(hostID string, result *model.AssessmentResult) {
	spcScore := 1.0
	threatCoeff := m.cfg.ThreatCoeff

	if impl, ok := m.kernel.Container().Resolve((*SPCInterface)(nil)); ok {
		if spc, ok2 := impl.(SPCInterface); ok2 && spc.Enabled() {
			m.syncACIToAsset(spc, hostID, result)

			var packages []string
			if asset := spc.GetAsset(hostID); asset != nil {
				packages = asset.Packages
			}
			if len(packages) == 0 {
				packages = m.extractPackagesFromChecks(result.Checks)
			}
			correction := spc.Calculate(hostID, packages)
			spcScore = correction.Score

			if len(correction.AffectedCVE) > 0 {
				cveInfos := make([]model.SPCCVEInfo, 0, len(correction.PenaltyBreakdown))
				for _, p := range correction.PenaltyBreakdown {
					cveInfos = append(cveInfos, model.SPCCVEInfo{
						CVEID:   p.CVEID,
						CVSS:    p.CVSS,
						EPSS:    p.EPSS,
						InKEV:   p.InKEV,
						HasPoC:  p.HasPoC,
						Penalty: p.Penalty,
						Product: p.Products,
					})
				}
				result.SPCCVEs = cveInfos
			}

			if len(correction.Weights) > 0 {
				if result.DomainWeightShift == nil {
					result.DomainWeightShift = make(map[string]float64)
				}
				for k, v := range correction.Weights {
					result.DomainWeightShift[k] = v
				}
			}

			logger.WithComponent("assessor").Info("SPC correction applied",
				"host_id", hostID,
				"p_score", correction.Score,
				"action", correction.Action,
				"affected_cve", len(correction.AffectedCVE))
		}
	}

	if impl, ok := m.kernel.Container().Resolve((*CTIInterface)(nil)); ok {
		if cti, ok2 := impl.(CTIInterface); ok2 {
			threatCoeff = cti.GetCoefficient()
		}
	}

	result.SPCScore = spcScore
	result.ThreatCoeff = threatCoeff
}

func (m *AssessorModule) applyATTACK(hostID string, result *model.AssessmentResult) {
	impl, ok := m.kernel.Container().Resolve((*ATTACKInterface)(nil))
	if !ok {
		return
	}
	attck, ok := impl.(ATTACKInterface)
	if !ok {
		return
	}

	checkResults := make(map[string]bool)
	for _, c := range result.Checks {
		checkResults[c.CheckID] = c.Passed
	}

	coverages := attck.CalculateCoverage(checkResults)
	if len(coverages) > 0 {
		result.ATTACKCoverage = make([]model.ATTACKCoverageInfo, len(coverages))
		for i, cov := range coverages {
			result.ATTACKCoverage[i] = model.ATTACKCoverageInfo{
				TacticID:        cov.TacticID,
				TacticName:      cov.TacticName,
				TotalTechniques: cov.TotalTechniques,
				CoveredDet:      cov.CoveredDet,
				CoverageDet:     cov.CoverageDet,
				CoveragePrev:    cov.CoveragePrev,
				CoverageComp:    cov.CoverageComp,
				RiskLevel:       cov.RiskLevel,
			}
		}
	}

	killChain := attck.AssessKillChain(hostID, checkResults)
	if killChain.OverallScore > 0 || len(killChain.Stages) > 0 {
		kcInfo := &model.ATTACKKillChainInfo{
			OverallScore: killChain.OverallScore,
			WeakestStage: killChain.WeakestStage,
			Stages:       make([]model.ATTACKKillChainStage, len(killChain.Stages)),
		}
		for i, stage := range killChain.Stages {
			kcInfo.Stages[i] = model.ATTACKKillChainStage{
				Name:         stage.Name,
				Score:        stage.Score,
				Status:       stage.Status,
				ChecksPassed: stage.ChecksPassed,
				ChecksTotal:  stage.ChecksTotal,
			}
		}
		result.ATTACKKillChain = kcInfo
	}

	var weakTacticIDs []string
	for _, cov := range coverages {
		if cov.CoverageDet < 50 {
			weakTacticIDs = append(weakTacticIDs, cov.TacticID)
		}
	}

	var failedTechIDs []string
	for _, cov := range coverages {
		if cov.CoverageDet < 100 {
			for _, tactic := range attck.GetAllTactics() {
				if tactic.ID == cov.TacticID {
					for _, tech := range tactic.Techniques {
						if len(tech.AsscorChecks) > 0 {
							allFailed := false
							for _, check := range tech.AsscorChecks {
								if passed, ok := checkResults[check]; ok && !passed {
									allFailed = true
									break
								}
							}
							if allFailed {
								failedTechIDs = append(failedTechIDs, tech.ID)
							}
						}
					}
				}
			}
		}
	}

	if len(weakTacticIDs) > 0 && len(failedTechIDs) > 0 {
		aptMatches := attck.MatchAPTGroup(failedTechIDs)
		if len(aptMatches) > 0 {
			result.ATTACKAPTMatches = make([]model.ATTACKAPTMatchInfo, len(aptMatches))
			for i, match := range aptMatches {
				result.ATTACKAPTMatches[i] = model.ATTACKAPTMatchInfo{
					GroupID:     match.GroupID,
					GroupName:   match.GroupName,
					Similarity:  match.Similarity,
					Confidence:  match.Confidence,
					OverlapTech: match.OverlapTech,
				}
			}
		}
	}

	if len(failedTechIDs) > 0 {
		result.ATTACKFailedTechs = failedTechIDs

		predictedRisk := attck.PredictRisk(hostID, failedTechIDs, 3)
		if predictedRisk.MaxRiskScore > 0 {
			result.ATTACKPredictedRisk = &model.ATTACKPredictedRiskInfo{
				MaxRiskScore:    predictedRisk.MaxRiskScore,
				EnhancedThreat:  predictedRisk.EnhancedThreat,
				PredictedPaths:  len(predictedRisk.PredictedPaths),
				Recommendations: predictedRisk.Recommendations,
			}
		}
	}

	logger.WithComponent("assessor").Info("ATT&CK analysis applied",
		"host_id", hostID,
		"coverages", len(coverages),
		"kill_chain_score", killChain.OverallScore,
		"apt_matches", len(result.ATTACKAPTMatches),
		"failed_techniques", len(failedTechIDs),
		"predicted_risk", result.ATTACKPredictedRisk != nil)
}

func (m *AssessorModule) syncACIToAsset(spc SPCInterface, hostID string, result *model.AssessmentResult) {
	asset := spc.GetAsset(hostID)
	if asset == nil {
		asset = &LocalAsset{HostID: hostID}
	}

	aciChecks := map[string]*bool{
		"AC-001": nil,
		"AC-002": nil,
		"AC-003": nil,
		"AC-004": nil,
		"AC-005": nil,
		"AC-006": nil,
		"AC-007": nil,
		"AC-008": nil,
	}

	for i := range result.Checks {
		c := &result.Checks[i]
		if _, exists := aciChecks[c.CheckID]; exists {
			passed := c.Passed
			aciChecks[c.CheckID] = &passed
		}
	}

	changed := false

	if p := aciChecks["AC-001"]; p != nil && *p {
		if asset.NetworkZone != "internal" && asset.NetworkZone != "lan" {
			asset.NetworkZone = "internal"
			changed = true
		}
	}

	if p := aciChecks["AC-004"]; p != nil && *p {
		if !asset.Compensations.IPSRules {
			asset.Compensations.IPSRules = true
			changed = true
		}
	}

	if p := aciChecks["AC-005"]; p != nil && *p {
		if !asset.Compensations.AppWhitelist {
			asset.Compensations.AppWhitelist = true
			changed = true
		}
	}

	if changed {
		spc.UpsertAsset(*asset)
	}
}

func (m *AssessorModule) recomputeFinalScore(result *model.AssessmentResult) float64 {
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}
	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = 1.0
	}

	ssamEngine := m.engine.SSAMEngine()
	ssamInput := &ssam.AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Threshold:   result.Threshold,
		Checks:      ssam.CheckResultsToInputs(result.Checks),
		ThreatCoeff: result.ThreatCoeff,
		SPCScore:    result.SPCScore,
	}

	ssamOutput, err := ssamEngine.ComputeScore(context.Background(), ssamInput)
	if err != nil {
		logger.WithComponent("assessor").Error("ssam recompute failed", "error", err)
		return 0
	}

	ssam.OutputToModel(ssamOutput, result)
	return ssamOutput.FinalScore
}

func (m *AssessorModule) GetResult(hostID string) *model.AssessmentResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.results[hostID]
}

func (m *AssessorModule) ReloadConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()

	m.engine.ReloadWeights(cfg)

	logger.WithComponent("assessor").Info("config reloaded",
		"threshold", cfg.Threshold,
		"threat_coeff", cfg.ThreatCoeff)
}

type AssessorInterface interface {
	Evaluate(hostID string) *model.AssessmentResult
	EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
	GetResult(hostID string) *model.AssessmentResult
	ReloadConfig(cfg *config.Config)
}

func (m *AssessorModule) extractPackagesFromChecks(checks []model.CheckResult) []string {
	keywordMap := map[string][]string{
		"ssh":        {"openssh", "ssh"},
		"openssl":    {"openssl"},
		"nginx":      {"nginx"},
		"apache":     {"apache", "httpd"},
		"php":        {"php"},
		"mysql":      {"mysql", "mariadb"},
		"postgres":   {"postgresql", "postgres"},
		"redis":      {"redis"},
		"docker":     {"docker"},
		"kernel":     {"linux-kernel"},
		"selinux":    {"selinux", "libselinux"},
		"firewall":   {"iptables", "firewalld", "nftables"},
		"fail2ban":   {"fail2ban"},
		"audit":      {"auditd", "audit"},
		"cron":       {"cronie", "crontabs"},
		"rsyslog":    {"rsyslog"},
		"suricata":   {"suricata"},
		"chrony":     {"chrony"},
		"clamav":     {"clamav"},
		"cryptsetup": {"cryptsetup"},
	}

	pkgSet := make(map[string]bool)
	for _, check := range checks {
		detail := strings.ToLower(check.Detail)
		name := strings.ToLower(check.Name)
		id := strings.ToLower(check.CheckID)
		combined := detail + " " + name + " " + id
		for keyword, pkgs := range keywordMap {
			if strings.Contains(combined, keyword) {
				for _, pkg := range pkgs {
					pkgSet[pkg] = true
				}
			}
		}
	}

	pkgs := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}
	if len(pkgs) > 0 {
		logger.WithComponent("assessor").Info("extracted packages from check results as fallback", "count", len(pkgs), "packages", strings.Join(pkgs, ","))
	}
	return pkgs
}