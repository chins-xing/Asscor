package kernel

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	"github.com/asscor/asscor/internal/integrity"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	ascorprism "github.com/asscor/asscor/internal/prism"
	prismlib "github.com/chins-xing/prism"
)

type ScoringEngineProvider interface {
	Assess(hostID string, hostname string) *model.AssessmentResult
	AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
	PluginEngine() engine.AssessorEngine
	RecomputeFinalScore(result *model.AssessmentResult) float64
	ReloadWeights(cfg *config.Config)
	ValidateEdgeFactors(registeredChecks []model.CheckItem) []string
	PrintReport(result *model.AssessmentResult) string
}

type PrismEngineProvider interface {
	ComputeDynamicScore(node *prismlib.NodeState, incomingEdges []prismlib.EdgeState, allNodes map[string]*prismlib.NodeState, nowUnix int64) prismlib.AssetRiskResult
	ComputeSemanticState(core *prismlib.AssetRiskResult) *prismlib.SemanticRiskReport
	PredictFuture(semantic *prismlib.SemanticRiskReport, model prismlib.InferenceModel) *prismlib.FutureRiskReport
	Config() prismlib.PrismConfig
	UpdateConfig(cfg prismlib.PrismConfig)
}

type AssessorModule struct {
	kernel         KernelContext
	cfg            *config.Config
	engine         ScoringEngineProvider
	prismEngine    PrismEngineProvider
	attackProvider engine.ATTACKProvider
	failTracker    map[string]map[string]int64

	mu      sync.RWMutex
	results map[string]*model.AssessmentResult

	siemPusher    *SIEMPusher
	consoleReport bool
	state         PluginState
	selfCheckDone chan struct{}
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
		{Interface: (*ScoringEngineProvider)(nil)},
	}
}

func (m *AssessorModule) Priority() int {
	return 40
}

func (m *AssessorModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized
	m.results = make(map[string]*model.AssessmentResult)
	m.failTracker = make(map[string]map[string]int64)

	if impl, ok := kc.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	if impl, ok := kc.Container().Resolve((*ScoringEngineProvider)(nil)); ok {
		if engine, ok := impl.(ScoringEngineProvider); ok {
			m.engine = engine
		}
	}

	if m.engine == nil {
		logger.WithComponent("assessor").Error("ScoringEngineProvider not found in DI container")
		return fmt.Errorf("ScoringEngineProvider not registered")
	}

	if impl, ok := kc.Container().Resolve((*PrismEngineProvider)(nil)); ok {
		if prism, ok := impl.(PrismEngineProvider); ok {
			m.prismEngine = prism
		}
	}

	if m.prismEngine == nil {
		m.prismEngine = ascorprism.NewEngine()
		logger.WithComponent("assessor").Info("prism engine initialized (default)", "version", "v3.1")
	}

	m.setupSIEMPusher()
	m.setupConsoleReport()
	m.setupPrismConfig()

	warnings := m.engine.ValidateEdgeFactors(checks.GetAll())
	for _, w := range warnings {
		logger.WithComponent("assessor").Warn("edge factor warning", "warning", w)
	}

	kc.Container().Bind((*AssessorInterface)(nil), m)

	return nil
}

// SetATTACKProvider injects the ATT&CK analysis provider (may be nil to disable).
func (m *AssessorModule) SetATTACKProvider(provider engine.ATTACKProvider) {
	m.attackProvider = provider
}

func filterAssessmentResult(result *model.AssessmentResult) map[string]interface{} {
	if result == nil {
		return nil
	}
	scores := result.DomainScores
	return map[string]interface{}{
		"host_id":     result.HostID,
		"hostname":    result.Hostname,
		"final_score": result.FinalScore,
		"acceptable":  result.Acceptable,
		"threshold":   result.Threshold,
		"check_count": len(result.Checks),
		"domains": map[string]interface{}{
			"attack_surface":     scores.AttackSurface,
			"business_continuity": scores.BusinessContinuity,
			"operation_trust":    scores.OperationTrust,
			"resilience":         scores.Resilience,
		},
	}
}

func (m *AssessorModule) setupSIEMPusher() {
	if m.cfg == nil {
		return
	}
	apiURL := m.cfg.AdapterConfig["wazuh_siem.api_url"]
	username := m.cfg.AdapterConfig["wazuh_siem.username"]
	password := m.cfg.AdapterConfig["wazuh_siem.password"]
	m.siemPusher = NewSIEMPusher(apiURL, username, password)
	if m.siemPusher.Enabled() {
		logger.WithComponent("assessor").Info("SIEM push integration enabled", "url", apiURL)
	}
}

func (m *AssessorModule) pushToSIEM(ctx context.Context, result *model.AssessmentResult) {
	m.kernel.Extensions().Execute(ctx, "siem.pre_push", map[string]interface{}{
		"host_id": result.HostID,
	})
	if m.siemPusher != nil && m.siemPusher.Enabled() {
		go func() {
			m.siemPusher.PushAssessment(ctx, result)
			m.kernel.Extensions().Execute(ctx, "siem.post_push", map[string]interface{}{
				"host_id": result.HostID,
			})
		}()
	}
}

func (m *AssessorModule) setupConsoleReport() {
	if m.cfg == nil {
		return
	}
	v := os.Getenv("ASSCOR_CONSOLE_REPORT")
	if v == "" {
		// Try global key first (config.ini top-level entry), then section-prefixed fallback.
		v = m.cfg.AdapterConfig["console_report"]
		if v == "" {
			v = m.cfg.AdapterConfig["webui.console_report"]
		}
	}
	m.consoleReport = v == "true" || v == "yes" || v == "1"
	if m.consoleReport {
		logger.WithComponent("assessor").Info("console assessment report enabled")
	}
}

func (m *AssessorModule) setupPrismConfig() {
	if m.cfg == nil || m.prismEngine == nil {
		return
	}

	cfg := m.prismEngine.Config()
	ac := m.cfg.AdapterConfig

	if v := parseFloatConfig(ac["prism.debt_alpha"]); v > 0 {
		cfg.DebtAlpha = v
	}
	if v := parseFloatConfig(ac["prism.prop_cap"]); v > 0 {
		cfg.PropCap = v
	}
	if v := parseFloatConfig(ac["prism.debt_cap"]); v > 0 {
		cfg.DebtCap = v
	}
	if v := parseFloatConfig(ac["prism.debt_norm_days"]); v > 0 {
		cfg.DebtNormDays = v
	}
	if v := parseFloatConfig(ac["prism.path_decay"]); v > 0 {
		cfg.PathDecay = v
	}
	if v := parseIntConfig(ac["prism.max_path_depth"]); v > 0 {
		cfg.MaxPathDepth = v
	}
	if v := parseFloatConfig(ac["prism.score_floor"]); v > 0 {
		cfg.ScoreFloor = v
	}
	if v := parseFloatConfig(ac["prism.collapse_beta"]); v > 0 {
		cfg.CollapseBeta = v
	}
	if v := parseFloatConfig(ac["prism.stable_threshold"]); v > 0 {
		cfg.StableThreshold = v
	}
	if v := parseFloatConfig(ac["prism.degraded_threshold"]); v > 0 {
		cfg.DegradedThreshold = v
	}
	if v := parseFloatConfig(ac["prism.untrusted_threshold"]); v > 0 {
		cfg.UntrustedThreshold = v
	}
	if v := parseIntConfig(ac["prism.horizon_days"]); v > 0 {
		cfg.HorizonDays = v
	}

	m.prismEngine.UpdateConfig(cfg)
	logger.WithComponent("assessor").Info("prism config loaded from config.ini",
		"score_floor", cfg.ScoreFloor, "horizon_days", cfg.HorizonDays,
		"debt_alpha", cfg.DebtAlpha, "prop_cap", cfg.PropCap)
}

func parseFloatConfig(s string) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

func parseIntConfig(s string) int {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func (m *AssessorModule) printConsoleReport(result *model.AssessmentResult) {
	if !m.consoleReport || m.engine == nil || result == nil {
		return
	}
	fmt.Fprint(os.Stderr, m.engine.PrintReport(result))
}

func (m *AssessorModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.selfCheckDone = make(chan struct{})
	go m.selfAssessmentLoop()
	logger.WithComponent("assessor").Info("started")
	return nil
}

func (m *AssessorModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.mu.Lock()
	if m.selfCheckDone != nil {
		select {
		case <-m.selfCheckDone:
		default:
			close(m.selfCheckDone)
		}
	}
	m.mu.Unlock()
	m.state = PluginStopped
	logger.WithComponent("assessor").Info("stopped")
	return nil
}

func (m *AssessorModule) selfAssessmentLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("assessor").Error("selfAssessmentLoop panic", "panic", r)
		}
	}()

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-m.selfCheckDone:
			return
		case <-ticker.C:
			m.runSelfAssessment()
		}
	}
}

func (m *AssessorModule) runSelfAssessment() {
	result := m.engine.Assess("kernel", "kernel")

	logger.WithComponent("assessor").Info("kernel self-assessment completed",
		"score", result.FinalScore, "acceptable", result.Acceptable)

	if result.FinalScore < 90 {
		logger.WithComponent("assessor").Warn("kernel self-assessment below threshold",
			"score", result.FinalScore, "threshold", 90)

		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   TopicAssessorSelfCheck,
			Payload: result,
			Source:  "assessor.self_check",
		})
	}
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
	m.kernel.Extensions().Execute(m.kernel.Context(), "verify.pre_check", map[string]interface{}{
		"host_id":   hostID,
		"trigger":   "explicit",
	})

	m.mu.RLock()
	prevResult := m.results[hostID]
	m.mu.RUnlock()

	var prevScore float64
	if prevResult != nil {
		prevScore = prevResult.FinalScore
	}

	result := m.engine.Assess(hostID, hostID)

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_score", result)

	m.applyCTIOnly(result)

	m.applyPrismToResult(hostID, result, time.Now().Unix())

	integrity.GetSigner().Sign(result)

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

		m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", filterAssessmentResult(result))

	m.kernel.Extensions().Execute(m.kernel.Context(), "verify.post_check", map[string]interface{}{
		"host_id":    hostID,
		"trigger":    "explicit",
		"prev_score": prevScore,
		"new_score":  result.FinalScore,
		"delta":      result.FinalScore - prevScore,
		"acceptable": result.Acceptable,
	})
	if result.Acceptable != (prevResult != nil && prevResult.Acceptable) || prevResult == nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "verify.status_changed", map[string]interface{}{
			"host_id":        hostID,
			"prev_acceptable": prevResult != nil && prevResult.Acceptable,
			"new_acceptable": result.Acceptable,
			"prev_score":     prevScore,
			"new_score":      result.FinalScore,
		})
	}

	m.pushToSIEM(m.kernel.Context(), result)
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.outbound", filterAssessmentResult(result))

	m.printConsoleReport(result)
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.report_generated", result)

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

	m.mu.RLock()
	threshold := m.cfg.Threshold
	threatCoeff := m.cfg.ThreatCoeff
	m.mu.RUnlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.pre_evaluate", hostID)
	m.kernel.Extensions().Execute(m.kernel.Context(), "verify.pre_check", map[string]interface{}{
		"host_id":   hostID,
		"trigger":   "heartbeat",
		"checks":    len(checkResults),
	})

	m.mu.RLock()
	prevResult := m.results[hostID]
	m.mu.RUnlock()

	var prevScore float64
	if prevResult != nil {
		prevScore = prevResult.FinalScore
	}

	result := &model.AssessmentResult{
		HostID:         hostID,
		Hostname:       hostname,
		Timestamp:      time.Now(),
		Threshold:      threshold,
		Checks:         checkResults,
		UncertaintyNote: "This score is a model output, not an objective security truth. Use as a decision reference, not a decision substitute. See also Goodhart's Law.",
		ModelCoverageRatio: modelCoverage(checkResults),
	}

	// Fix permission-denied checks: mark as skipped (delta=0) instead of FAIL.
	// This prevents non-root standalone/kernel evaluations from unfairly
	// deducting scores for checks that require elevated privileges.
	for i := range result.Checks {
		c := &result.Checks[i]
		if !c.Passed && isPermDenied(c.Detail) {
			c.Passed = true
			c.Delta = 0
			c.Detail = "skipped — requires root privileges (" + c.Detail + ")"
		}
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
		result.ThreatCoeff = threatCoeff
		result.SPCScore = 1.0
	} else {
		m.applySPCAndCTI(hostID, result)
		m.applyATTACK(hostID, result)
		result.FinalScore = m.engine.RecomputeFinalScore(result)
	}

	logger.WithComponent("assessor").Info("assessment score computed", "host_id", hostID, "score", result.FinalScore, "spc_score", result.SPCScore, "threat_coeff", result.ThreatCoeff)

	m.applyPrismToResult(hostID, result, time.Now().Unix())

	integrity.GetSigner().Sign(result)

	m.mu.Lock()
	m.results[hostID] = result
	m.mu.Unlock()

		m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.post_evaluate", filterAssessmentResult(result))

	m.kernel.Extensions().Execute(m.kernel.Context(), "verify.post_check", map[string]interface{}{
		"host_id":    hostID,
		"trigger":    "heartbeat",
		"prev_score": prevScore,
		"new_score":  result.FinalScore,
		"delta":      result.FinalScore - prevScore,
		"acceptable": result.Acceptable,
	})
	if result.Acceptable != (prevResult != nil && prevResult.Acceptable) || prevResult == nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "verify.status_changed", map[string]interface{}{
			"host_id":        hostID,
			"prev_acceptable": prevResult != nil && prevResult.Acceptable,
			"new_acceptable": result.Acceptable,
			"prev_score":     prevScore,
			"new_score":      result.FinalScore,
		})
	}

	m.pushToSIEM(m.kernel.Context(), result)
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.outbound", filterAssessmentResult(result))

	m.printConsoleReport(result)
	m.kernel.Extensions().Execute(m.kernel.Context(), "assessor.report_generated", result)

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
	m.mu.RLock()
	threatCoeff := m.cfg.ThreatCoeff
	m.mu.RUnlock()

	spcScore := 1.0

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

func (m *AssessorModule) applyCTIOnly(result *model.AssessmentResult) {
	m.mu.RLock()
	ctiCoeff := m.cfg.ThreatCoeff
	m.mu.RUnlock()
	if impl, ok := m.kernel.Container().Resolve((*CTIInterface)(nil)); ok {
		if cti, ok2 := impl.(CTIInterface); ok2 {
			ctiCoeff = cti.GetCoefficient()
		}
	}
	if ctiCoeff != result.ThreatCoeff {
		if result.ThreatCoeff > 0 {
			result.FinalScore = result.FinalScore * ctiCoeff / result.ThreatCoeff
		}
		result.ThreatCoeff = ctiCoeff
		result.Acceptable = result.FinalScore >= result.Threshold
	}
}

func (m *AssessorModule) applyATTACK(hostID string, result *model.AssessmentResult) {
	provider := m.attackProvider
	if provider == nil || !provider.IsEnabled() {
		return
	}

	checkResults := make(map[string]bool)
	for _, c := range result.Checks {
		checkResults[c.CheckID] = c.Passed
	}

	coverages := provider.CalculateCoverage(checkResults)
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

	killChain := provider.AssessKillChain(hostID, checkResults)
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
			for _, tactic := range provider.GetAllTactics() {
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
		aptMatches := provider.MatchAPTGroup(failedTechIDs)
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

		predictedRisk := provider.PredictRisk(hostID, failedTechIDs, 3)
		if predictedRisk.MaxRiskScore > 0 {
			result.ATTACKPredictedRisk = &model.ATTACKPredictedRiskInfo{
				MaxRiskScore:    predictedRisk.MaxRiskScore,
				EnhancedThreat:  predictedRisk.EnhancedThreat,
				PredictedPaths:  predictedRisk.PredictedPaths,
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
	m.setupPrismConfig()
	m.setupConsoleReport()

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

func modelCoverage(results []model.CheckResult) float64 {
	all := checks.GetAll()
	if len(all) == 0 || len(results) == 0 {
		return 0
	}
	scored := make(map[string]bool, len(results))
	for _, r := range results {
		if r.Delta != 0 {
			scored[r.CheckID] = true
		}
	}
	return float64(len(scored)) / float64(len(all))
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

func (m *AssessorModule) applyPrismToResult(hostID string, result *model.AssessmentResult, nowUnix int64) {
	m.updateFailTracker(hostID, result, nowUnix)

	node := m.buildNodeState(hostID, result)
	allNodes, allEdges := m.collectTopologySnapshot(hostID, result)
	incomingEdges := filterIncoming(hostID, allEdges)

	cfg := m.prismEngine.Config()
	prismResult := m.prismEngine.ComputeDynamicScore(node, incomingEdges, allNodes, nowUnix)

	// Core Layer
	result.PrismScore = prismResult.PrismScore
	result.PrismExternalRisk = prismResult.ExternalRisk
	result.PrismPropRisk = prismResult.PropagatedRisk
	result.PrismPropPenalty = prismResult.PropPenalty
	result.PrismDebtRaw = prismResult.DebtRaw
	result.PrismDebtPenalty = prismResult.DebtPenalty
	result.PrismCollapseModifier = prismResult.CollapseModifier
	result.PrismRiskVelocity = prismResult.RiskVelocity

	// Semantic Layer
	semantic := m.prismEngine.ComputeSemanticState(&prismResult)
	if semantic != nil {
		result.PrismSemanticState = semantic.CurrentState
		result.PrismStateVector = semantic.StateVector
		result.PrismStableMem = semantic.StableMembership
		result.PrismDegradedMem = semantic.DegradedMembership
		result.PrismUntrustedMem = semantic.UntrustedMembership
		result.PrismCollapseMem = semantic.CollapseMembership
	}

	// Inference Layer
	// Inference Layer
	future := m.prismEngine.PredictFuture(semantic, nil)
	if future != nil {
		result.PrismInferenceTrend = future.Trend
		result.PrismInferenceConfidence = future.Confidence
		result.PrismInferenceCollapseRisk = future.CollapseRisk
		result.PrismInferenceFutureVector = [4]float64{
			future.StableProb, future.DegradedProb,
			future.UntrustedProb, future.CollapseProb,
		}
		result.PrismInferenceModel = "MarkovChain"
		result.PrismInferenceHorizonDays = future.HorizonDays
	}

	// Prism IR
	if semantic != nil && future != nil {
		edges := make([]prismlib.EdgeState, len(incomingEdges))
		for i, e := range incomingEdges {
			edges[i] = prismlib.EdgeState{
				Source:           e.Source,
				Target:           e.Target,
				RiskTransmission: e.RiskTransmission,
			}
		}
		prismIR := prismlib.NewIR(*node, edges, cfg, prismResult, *semantic, *future, "MarkovChain")
		if data, err := prismIR.MarshalJSON(); err == nil {
			result.PrismIR = data
		}
	}

	logger.WithComponent("assessor").Info("prism score computed",
		"host_id", hostID,
		"ssam_score", result.FinalScore,
		"prism_score", result.PrismScore,
		"semantic_state", result.PrismSemanticState,
		"inference_trend", result.PrismInferenceTrend,
		"debt_penalty", result.PrismDebtPenalty,
		"prop_penalty", result.PrismPropPenalty,
	)
}

func (m *AssessorModule) updateFailTracker(hostID string, result *model.AssessmentResult, nowUnix int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	failMap, exists := m.failTracker[hostID]
	if !exists {
		failMap = make(map[string]int64)
		m.failTracker[hostID] = failMap
	}

	for _, c := range result.Checks {
		if !c.Passed {
			if _, tracked := failMap[c.CheckID]; !tracked {
				failMap[c.CheckID] = nowUnix
			}
		} else {
			delete(failMap, c.CheckID)
		}
	}
}

func (m *AssessorModule) buildNodeState(hostID string, result *model.AssessmentResult) *prismlib.NodeState {
	m.mu.RLock()
	failMap := m.failTracker[hostID]
	m.mu.RUnlock()

	node := &prismlib.NodeState{
		HostID:    hostID,
		SSAMScore: result.FinalScore,
	}

	for _, c := range result.Checks {
		if !c.Passed {
			failAt := int64(0)
			if failMap != nil {
				if t, ok := failMap[c.CheckID]; ok {
					failAt = t
				}
			}
			node.FailedChecks = append(node.FailedChecks, prismlib.CheckFailure{
				CheckID:  c.CheckID,
				Delta:    c.Delta,
				FailUnix: failAt,
			})
		}
	}

	return node
}

func (m *AssessorModule) collectTopologySnapshot(currentHostID string, currentResult *model.AssessmentResult) (map[string]*prismlib.NodeState, []prismlib.EdgeState) {
	nodes := make(map[string]*prismlib.NodeState)
	edges := make([]prismlib.EdgeState, 0)

	nodes[currentHostID] = &prismlib.NodeState{
		HostID:    currentHostID,
		SSAMScore: currentResult.FinalScore,
	}

	defaultTransmission := m.cfg.GetPrismDefaultTransmission()

	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, res := range m.results {
		if id == currentHostID {
			continue
		}
		nodes[id] = &prismlib.NodeState{
			HostID:    id,
			SSAMScore: res.FinalScore,
		}
		edges = append(edges, prismlib.EdgeState{
			Source:           id,
			Target:           currentHostID,
			RiskTransmission: defaultTransmission,
		})
	}

	return nodes, edges
}

func filterIncoming(hostID string, edges []prismlib.EdgeState) []prismlib.EdgeState {
	var result []prismlib.EdgeState
	for _, e := range edges {
		if e.Target == hostID {
			result = append(result, e)
		}
	}
	return result
}


type ScoringEngineModule struct {
	mu     sync.Mutex
	kernel KernelContext
	cfg    *config.Config
	engine *engine.Assessor

	state PluginState
}

func NewScoringEngineModule(cfg *config.Config) *ScoringEngineModule {
	if cfg == nil {
		cfg = config.Default()
	}
	return &ScoringEngineModule{
		cfg:    cfg,
		engine: engine.NewAssessor(cfg),
		state:  PluginUnregistered,
	}
}

func (m *ScoringEngineModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "scoring_engine",
		Version:     "1.0.0",
		Description: "SSAM scoring engine provider - implements ScoringEngineProvider interface",
		Author:      "ASSCOR Core Team",
	}
}

func (m *ScoringEngineModule) Dependencies() []PluginDependency {
	return []PluginDependency{
		{Name: "config", Interface: (*config.Config)(nil)},
	}
}

func (m *ScoringEngineModule) Priority() int {
	return 35
}

func (m *ScoringEngineModule) Init(ctx context.Context, kc KernelContext) error {
	m.mu.Lock()
	m.kernel = kc
	m.state = PluginInitialized
	m.mu.Unlock()
	return nil
}

func (m *ScoringEngineModule) Start(ctx context.Context) error {
	m.mu.Lock()
	m.state = PluginStarted
	m.mu.Unlock()
	return nil
}

func (m *ScoringEngineModule) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.state = PluginStopped
	m.mu.Unlock()
	return nil
}

func (m *ScoringEngineModule) State() PluginState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *ScoringEngineModule) Assess(hostID string, hostname string) *model.AssessmentResult {
	return m.engine.Assess(hostID, hostname)
}

func (m *ScoringEngineModule) AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult {
	return m.engine.AssessFromResults(hostID, hostname, checkResults)
}

func (m *ScoringEngineModule) PluginEngine() engine.AssessorEngine {
	return m.engine.PluginEngine()
}

func (m *ScoringEngineModule) SetPluginEngine(e engine.AssessorEngine) {
	m.engine.SetPluginEngine(e)
}

func (m *ScoringEngineModule) RecomputeFinalScore(result *model.AssessmentResult) float64 {
	return m.engine.RecomputeFinalScore(result)
}

func (m *ScoringEngineModule) ReloadWeights(cfg *config.Config) {
	m.engine.ReloadWeights(cfg)
}

func (m *ScoringEngineModule) ValidateEdgeFactors(registeredChecks []model.CheckItem) []string {
	return m.engine.ValidateEdgeFactors(registeredChecks)
}

func (m *ScoringEngineModule) PrintReport(result *model.AssessmentResult) string {
	return m.engine.PrintReport(result)
}

func isPermDenied(detail string) bool {
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "permission_error") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "eacces") ||
		strings.Contains(lower, "eperm") {
		return true
	}
	if strings.Contains(detail, "权限") ||
		strings.Contains(detail, "无权限") ||
		strings.Contains(detail, "拒绝访问") ||
		strings.Contains(detail, "許可") {
		return true
	}
	if strings.Contains(lower, "open ") && strings.Contains(lower, "permission denied") {
		return true
	}
	return false
}

var _ ScoringEngineProvider = (*ScoringEngineModule)(nil)