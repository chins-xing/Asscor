package kernel

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

const (
	maxAlerts           = 10000
	maxAnomalies        = 5000
	maxIOCs             = 50000
	maxTTPTracks        = 10000
	maxEmulationResults = 1000
	maxAssessmentReports = 500
	maxAttackChains     = 5000
	maxBehavioralAlerts = 10000
	maxBeaconDetections = 5000
	maxHuntHypotheses   = 5000
	maxHuntResults      = 5000
)

type ATTACKTactic struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Techniques  []ATTACKTechnique `json:"techniques"`
	Domain      string   `json:"domain"`
	CoverageDet float64  `json:"coverage_detection"`
	CoveragePrev float64 `json:"coverage_prevention"`
	CoverageComp float64 `json:"coverage_composite"`
	RiskLevel   string   `json:"risk_level"`
}

type ATTACKTechnique struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SubTechniques []string `json:"sub_techniques,omitempty"`
	AsscorChecks  []string `json:"asscor_checks"`
	Detected     bool     `json:"detected"`
	Prevented    bool     `json:"prevented"`
	Weight       float64  `json:"weight"`
}

type ATTACKCoverage struct {
	TacticID        string  `json:"tactic_id"`
	TacticName      string  `json:"tactic_name"`
	TotalTechniques int     `json:"total_techniques"`
	CoveredDet      int     `json:"covered_detection"`
	CoveredPrev     int     `json:"covered_prevention"`
	CoverageDet     float64 `json:"coverage_detection"`
	CoveragePrev    float64 `json:"coverage_prevention"`
	CoverageComp    float64 `json:"coverage_composite"`
	RiskLevel       string  `json:"risk_level"`
	BlindSpots      []string `json:"blind_spots,omitempty"`
}

type APTGroupProfile struct {
	GroupID      string            `json:"group_id"`
	Name         string            `json:"name"`
	Aliases      []string          `json:"aliases"`
	Description  string            `json:"description"`
	PrimaryTargets []string        `json:"primary_targets"`
	Techniques   map[string]float64 `json:"techniques"`
	PreferredCVETypes []string     `json:"preferred_cve_types"`
	MISPGalaxyID string            `json:"misp_galaxy_id"`
}

type APTMatchResult struct {
	GroupID     string  `json:"group_id"`
	GroupName   string  `json:"group_name"`
	Similarity  float64 `json:"similarity"`
	OverlapTech []string `json:"overlap_techniques"`
	Confidence  string  `json:"confidence"`
	MatchCount  int     `json:"match_count"`
}

type TransitionMatrix map[string]map[string]float64

type PredictiveRisk struct {
	HostID          string            `json:"host_id"`
	CurrentTech     []string          `json:"current_techniques"`
	PredictedPaths  []PredictedPath   `json:"predicted_paths"`
	MaxRiskScore    float64           `json:"max_risk_score"`
	EnhancedThreat  float64           `json:"enhanced_threat_coeff"`
	Recommendations []string          `json:"recommendations"`
	Timestamp       time.Time         `json:"timestamp"`
}

type PredictedPath struct {
	Path       []string `json:"path"`
	Probability float64 `json:"probability"`
	EndTech     string  `json:"end_technique"`
	Risk        float64 `json:"risk"`
}

type KillChainStage struct {
	Name        string  `json:"name"`
	Tactics     []string `json:"tactics"`
	Score       float64 `json:"score"`
	Status      string  `json:"status"`
	ChecksPassed int    `json:"checks_passed"`
	ChecksTotal  int    `json:"checks_total"`
}

type KillChainAssessment struct {
	HostID      string           `json:"host_id"`
	Stages      []KillChainStage `json:"stages"`
	OverallScore float64         `json:"overall_score"`
	WeakestStage string          `json:"weakest_stage"`
	AssessmentTime time.Time     `json:"assessment_time"`
}

type ATTACKModule struct {
	kernel             KernelContext
	mu                 sync.RWMutex
	tactics            []ATTACKTactic
	aptGroups          map[string]*APTGroupProfile
	transMatrix        TransitionMatrix
	state              PluginState
	attckVersion       string
	beaconThreshold    float64
	attributionThreshold float64
	autoHunt           bool
	safeEmulation      bool
	detectionRules     []DetectionRule
	alerts             []DetectionAlert
	anomalies          []AnomalyEvent
	iocs               []IOCEntry
	threatActors       map[string]ThreatActorProfile
	ttpTracks          []TTPTrack
	scenarios          []EmulationScenario
	emulationResults   []EmulationResult
	assessmentReports  []AssessmentReport
	improvementTracks  map[string]ImprovementTrack
	attackChains       []AttackChain
	behavioralIndicators []BehavioralIndicator
	baselines          map[string]BehavioralBaseline
	behavioralAlerts   []BehavioralAlert
	beaconDetections   []BeaconDetection
	huntHypotheses     []HuntHypothesis
	huntResults        []HuntResult
	yaraRules          []YARARule
	sigmaRules         []SigmaRule
	reputationDB       []ReputationEntry
	crossHostConns     []CrossHostConnection
	lateralEvidences   []LateralMovementEvidence
	analysisHistory    map[string][]HostAnalysisRecord
}

type HostAnalysisRecord struct {
	HostID            string               `json:"host_id"`
	Timestamp         time.Time            `json:"timestamp"`
	AssessmentScore   float64              `json:"assessment_score"`
	FailedChecks      []string             `json:"failed_checks"`
	FailedTechniques  []string             `json:"failed_techniques"`
	Coverages         []ATTACKCoverage     `json:"coverages"`
	KillChain         KillChainAssessment  `json:"kill_chain"`
	APTMatches        []APTMatchResult     `json:"apt_matches"`
	PredictedRisk     *PredictiveRisk      `json:"predicted_risk,omitempty"`
	AttackChainID     string               `json:"attack_chain_id,omitempty"`
	GapAnalysisID     string               `json:"gap_analysis_id,omitempty"`
	HuntHypothesesGen int                  `json:"hunt_hypotheses_generated"`
	AlertsTriggered   int                  `json:"alerts_triggered"`
}

func NewATTACKModule() *ATTACKModule {
	return &ATTACKModule{
		aptGroups:            make(map[string]*APTGroupProfile),
		transMatrix:          make(TransitionMatrix),
		attckVersion:         "v19",
		beaconThreshold:      0.7,
		attributionThreshold: 0.6,
		autoHunt:             false,
		safeEmulation:        true,
		threatActors:         make(map[string]ThreatActorProfile),
		improvementTracks:    make(map[string]ImprovementTrack),
		reputationDB: []ReputationEntry{
			{Destination: "ntp.org", Service: "ntp", Category: "time_sync", IsLegitimate: true, Reason: "standard NTP service", Source: "builtin"},
			{Destination: "time.windows.com", Service: "ntp", Category: "time_sync", IsLegitimate: true, Reason: "Windows NTP service", Source: "builtin"},
			{Destination: "time.google.com", Service: "ntp", Category: "time_sync", IsLegitimate: true, Reason: "Google NTP service", Source: "builtin"},
			{Destination: "pool.ntp.org", Service: "ntp", Category: "time_sync", IsLegitimate: true, Reason: "NTP pool service", Source: "builtin"},
			{Destination: "updates.microsoft.com", Service: "https", Category: "os_update", IsLegitimate: true, Reason: "Windows Update", Source: "builtin"},
			{Destination: "update.googleapis.com", Service: "https", Category: "os_update", IsLegitimate: true, Reason: "Chrome/Android update", Source: "builtin"},
			{Destination: "api.github.com", Service: "https", Category: "dev_tool", IsLegitimate: true, Reason: "GitHub API", Source: "builtin"},
			{Destination: "registry.npmjs.org", Service: "https", Category: "dev_tool", IsLegitimate: true, Reason: "npm registry", Source: "builtin"},
			{Destination: "pypi.org", Service: "https", Category: "dev_tool", IsLegitimate: true, Reason: "Python package index", Source: "builtin"},
			{Destination: "dns.google", Service: "dns", Category: "dns", IsLegitimate: true, Reason: "Google DNS", Source: "builtin"},
			{Destination: "1.1.1.1", Service: "dns", Category: "dns", IsLegitimate: true, Reason: "Cloudflare DNS", Source: "builtin"},
			{Destination: "8.8.8.8", Service: "dns", Category: "dns", IsLegitimate: true, Reason: "Google DNS", Source: "builtin"},
		},
		baselines:            make(map[string]BehavioralBaseline),
		analysisHistory:      make(map[string][]HostAnalysisRecord),
	}
}

func (m *ATTACKModule) ConfigureFromConfig(cfg *config.Config) {
	if cfg == nil {
		m.loadDefaultMatrix()
		m.loadDefaultAPTProfiles()
		m.buildTransitionMatrix()
		m.loadDefaultDetectionRules()
		m.loadDefaultThreatActors()
		m.loadDefaultScenarios()
		m.loadDefaultBehavioralIndicators()
		return
	}

	m.attckVersion = cfg.ATTACK.Version
	m.beaconThreshold = cfg.ATTACK.BeaconThreshold
	m.attributionThreshold = cfg.ATTACK.AttributionThreshold
	m.autoHunt = cfg.ATTACK.AutoHunt
	m.safeEmulation = cfg.ATTACK.SafeEmulation
	if m.attckVersion == "" {
		m.attckVersion = "v19"
	}
	if m.beaconThreshold <= 0 || m.beaconThreshold > 1.0 {
		m.beaconThreshold = 0.7
	}
	if m.attributionThreshold <= 0 || m.attributionThreshold > 1.0 {
		m.attributionThreshold = 0.6
	}

	m.loadDefaultMatrix()
	m.loadDefaultAPTProfiles()
	m.buildTransitionMatrix()
	m.loadDefaultDetectionRules()
	m.loadDefaultThreatActors()
	m.loadDefaultScenarios()
	m.loadDefaultBehavioralIndicators()
}

func (m *ATTACKModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "attck",
		Version:     "2.0.0",
		Description: "MITRE ATT&CK V19 — detection analytics, threat intelligence, adversary emulation, assessment & engineering",
		Author:      "ASSCOR Core Team",
	}
}

func (m *ATTACKModule) Dependencies() []PluginDependency {
	return nil
}

func (m *ATTACKModule) Priority() int {
	return 21
}

func (m *ATTACKModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

	cfg := kc.GetConfigObj()
	if cfg != nil {
		m.attckVersion = cfg.ATTACK.Version
		m.beaconThreshold = cfg.ATTACK.BeaconThreshold
		m.attributionThreshold = cfg.ATTACK.AttributionThreshold
		m.autoHunt = cfg.ATTACK.AutoHunt
		m.safeEmulation = cfg.ATTACK.SafeEmulation
		if m.attckVersion == "" {
			m.attckVersion = "v19"
		}
		if m.beaconThreshold <= 0 || m.beaconThreshold > 1.0 {
			m.beaconThreshold = 0.7
		}
		if m.attributionThreshold <= 0 || m.attributionThreshold > 1.0 {
			m.attributionThreshold = 0.6
		}
	}

	m.loadDefaultMatrix()
	m.loadDefaultAPTProfiles()
	m.buildTransitionMatrix()
	m.loadDefaultDetectionRules()
	m.loadDefaultThreatActors()
	m.loadDefaultScenarios()
	m.loadDefaultBehavioralIndicators()

	kc.Container().Bind((*ATTACKInterface)(nil), m)

	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.coverage.complete",
		Description: "Called after coverage analysis completes",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.apt.matched",
		Description: "Called when APT group match is detected",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.risk.predicted",
		Description: "Called after predictive risk assessment",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.detection.alert",
		Description: "Called when a detection alert is triggered",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.detection.anomaly",
		Description: "Called when a high-score anomaly is detected",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.emulation.complete",
		Description: "Called after adversary emulation completes",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.assessment.complete",
		Description: "Called after gap analysis assessment completes",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.apt.chain_detected",
		Description: "Called when an APT attack chain is reconstructed",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.apt.attribution",
		Description: "Called when APT attribution is performed",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.apt.hunt_confirmed",
		Description: "Called when a threat hunt hypothesis is confirmed",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.apt.report_generated",
		Description: "Called when an APT analysis report is generated",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.behavioral.alert",
		Description: "Called when a behavioral alert is triggered",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "attck.behavioral.beacon",
		Description: "Called when C2 beaconing is detected",
		Version:     "1.0",
	})

	return nil
}

func (m *ATTACKModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.kernel.Bus().Subscribe(TopicAssessorResult, "attck", m.onAssessmentResult)
	logger.WithComponent("attck").Info("started", "version", m.attckVersion)
	return nil
}

func (m *ATTACKModule) Stop(ctx context.Context) error {
	m.state = PluginStopping

	m.kernel.Bus().UnsubscribeAll("attck")

	m.mu.Lock()
	m.alerts = nil
	m.anomalies = nil
	m.iocs = nil
	m.huntHypotheses = nil
	m.beaconDetections = nil
	m.attackChains = nil
	m.yaraRules = nil
	m.sigmaRules = nil
	m.crossHostConns = nil
	m.lateralEvidences = nil
	m.mu.Unlock()

	m.state = PluginStopped
	logger.WithComponent("attck").Info("stopped")
	return nil
}

func (m *ATTACKModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *ATTACKModule) Version() string {
	return m.attckVersion
}

func (m *ATTACKModule) extractFailedTechniques(checkResults map[string]bool) []string {
	failed := make(map[string]bool)
	for _, tactic := range m.tactics {
		for _, tech := range tactic.Techniques {
			for _, check := range tech.AsscorChecks {
				if passed, ok := checkResults[check]; ok && !passed {
					failed[tech.ID] = true
					break
				}
			}
		}
	}
	result := make([]string, 0, len(failed))
	for techID := range failed {
		result = append(result, techID)
	}
	sort.Strings(result)
	return result
}

func (m *ATTACKModule) extractFailedChecks(checkResults map[string]bool) []string {
	var failed []string
	for checkID, passed := range checkResults {
		if !passed {
			failed = append(failed, checkID)
		}
	}
	sort.Strings(failed)
	return failed
}

func trimSlice[T any](s []T, maxLen int) []T {
	if len(s) > maxLen {
		return s[len(s)-maxLen:]
	}
	return s
}

func (m *ATTACKModule) storeAnalysisRecord(record HostAnalysisRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	history := m.analysisHistory[record.HostID]
	history = append(history, record)
	if len(history) > 50 {
		history = history[len(history)-50:]
	}
	m.analysisHistory[record.HostID] = history
}

func (m *ATTACKModule) GetHostAnalysisHistory(hostID string, limit int) []HostAnalysisRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	history := m.analysisHistory[hostID]
	if len(history) == 0 {
		return nil
	}

	if limit <= 0 || limit > len(history) {
		limit = len(history)
	}

	start := len(history) - limit
	result := make([]HostAnalysisRecord, limit)
	copy(result, history[start:])
	return result
}

func (m *ATTACKModule) onAssessmentResult(ctx context.Context, msg Message) error {
	result, ok := msg.Payload.(*model.AssessmentResult)
	if !ok {
		return nil
	}

	hostID := result.HostID
	checkResults := make(map[string]bool)
	for _, c := range result.Checks {
		checkResults[c.CheckID] = c.Passed
	}

	record := HostAnalysisRecord{
		HostID:          hostID,
		Timestamp:       time.Now(),
		AssessmentScore: result.FinalScore,
		FailedChecks:    m.extractFailedChecks(checkResults),
		FailedTechniques: m.extractFailedTechniques(checkResults),
	}

	logger.WithComponent("attck").Info("assessment pipeline started",
		"host_id", hostID,
		"failed_checks", len(record.FailedChecks),
		"failed_techniques", len(record.FailedTechniques),
	)

	coverages := m.CalculateCoverage(checkResults)
	record.Coverages = coverages

	m.kernel.Extensions().Execute(ctx, "attck.coverage.complete", coverages)

	killChain := m.AssessKillChain(hostID, checkResults)
	record.KillChain = killChain

	var weakTactics []string
	for _, cov := range coverages {
		if cov.CoverageDet < 50 {
			weakTactics = append(weakTactics, cov.TacticID)
		}
	}

	var aptMatches []APTMatchResult
	if len(weakTactics) > 0 {
		aptMatches = m.MatchAPTGroup(weakTactics)
	}
	record.APTMatches = aptMatches

	if len(aptMatches) > 0 {
		m.kernel.Extensions().Execute(ctx, "attck.apt.matched", aptMatches)
	}

	alertsTriggered := 0
	if len(record.FailedTechniques) > 0 {
		alertsTriggered = m.triggerAlertsForFailedChecks(ctx, hostID, checkResults)
	}
	record.AlertsTriggered = alertsTriggered

	huntGen := 0
	if m.autoHunt && len(record.FailedTechniques) > 0 {
		hypotheses, err := m.AutoGenerateHypotheses(hostID)
		if err == nil {
			huntGen = len(hypotheses)
		}
	}
	record.HuntHypothesesGen = huntGen

	var chainID string
	if len(record.FailedTechniques) >= 3 {
		chain, err := m.ReconstructAttackChain([]string{hostID})
		if err == nil && chain != nil {
			chainID = chain.ID
		}
	}
	record.AttackChainID = chainID

	if chainID != "" {
		attribution, err := m.PerformAttribution(chainID)
		if err == nil && attribution != nil {
			m.kernel.Extensions().Execute(ctx, "attck.apt.attribution", attribution)
		}
	}

	var gapID string
	if len(record.FailedTechniques) > 0 {
		gapReport, err := m.PerformGapAnalysis(hostID)
		if err == nil && gapReport != nil {
			gapID = gapReport.ID
		}
	}
	record.GapAnalysisID = gapID

	if len(record.FailedTechniques) > 0 {
		predictedRisk := m.PredictRisk(hostID, record.FailedTechniques, 3)
		record.PredictedRisk = &predictedRisk
		m.kernel.Extensions().Execute(ctx, "attck.risk.predicted", predictedRisk)

		if predictedRisk.EnhancedThreat > 1.0 {
			m.kernel.Bus().Publish(ctx, Message{
				Topic: "attck.threat.enhanced",
				Payload: map[string]interface{}{
					"host_id":       hostID,
					"threat_coeff":  predictedRisk.EnhancedThreat,
					"max_risk":      predictedRisk.MaxRiskScore,
					"techniques":    record.FailedTechniques,
				},
				Source: "attck",
			})
		}
	}

	m.storeAnalysisRecord(record)

	m.kernel.Bus().Publish(ctx, Message{
		Topic: "attck.analysis.complete",
		Payload: map[string]interface{}{
			"host_id":            hostID,
			"coverages":          coverages,
			"kill_chain":         killChain,
			"apt_matches":        aptMatches,
			"failed_techniques":  record.FailedTechniques,
			"alerts_triggered":   alertsTriggered,
			"hunt_generated":     huntGen,
			"attack_chain_id":    chainID,
			"gap_analysis_id":    gapID,
		},
		Source: "attck",
	})

	logger.WithComponent("attck").Info("assessment pipeline completed",
		"host_id", hostID,
		"tactics_analyzed", len(coverages),
		"kill_chain_score", killChain.OverallScore,
		"apt_matches", len(aptMatches),
		"failed_techniques", len(record.FailedTechniques),
		"alerts_triggered", alertsTriggered,
		"hunt_hypotheses", huntGen,
		"attack_chain", chainID,
		"gap_analysis", gapID,
	)

	return nil
}

func (m *ATTACKModule) triggerAlertsForFailedChecks(ctx context.Context, hostID string, checkResults map[string]bool) int {
	triggered := 0

	failedTechs := m.extractFailedTechniques(checkResults)
	if len(failedTechs) == 0 {
		return 0
	}

	failedTechSet := make(map[string]bool, len(failedTechs))
	for _, t := range failedTechs {
		failedTechSet[t] = true
	}

	m.mu.RLock()
	rules := make([]DetectionRule, len(m.detectionRules))
	copy(rules, m.detectionRules)
	m.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if !failedTechSet[rule.TechniqueID] {
			continue
		}

		fields := make(map[string]string)
		for checkID, passed := range checkResults {
			if !passed {
				fields[checkID] = "failed"
			}
		}

		alert, err := m.EvaluateDetectionRule(rule.ID, hostID, "", fields)
		if err != nil || alert == nil {
			continue
		}

		triggered++
		m.kernel.Extensions().Execute(ctx, "attck.detection.alert", alert)
	}

	return triggered
}

func (m *ATTACKModule) GetLastAnalysis(hostID string) map[string]interface{} {
	m.mu.RLock()
	history := m.analysisHistory[hostID]
	m.mu.RUnlock()

	if len(history) > 0 {
		latest := history[len(history)-1]
		m.mu.RLock()
		defer m.mu.RUnlock()
		return map[string]interface{}{
			"host_id":           hostID,
			"attck_version":     m.attckVersion,
			"tactics_count":     len(m.tactics),
			"last_assessment":   latest.Timestamp,
			"assessment_score":  latest.AssessmentScore,
			"failed_checks":     len(latest.FailedChecks),
			"failed_techniques": len(latest.FailedTechniques),
			"coverages":         latest.Coverages,
			"kill_chain":        latest.KillChain,
			"apt_matches":       latest.APTMatches,
			"apt_groups":        len(m.aptGroups),
			"detection_rules":   len(m.detectionRules),
			"threat_actors":     len(m.threatActors),
			"scenarios":         len(m.scenarios),
			"auto_hunt":         m.autoHunt,
			"beacon_threshold":  m.beaconThreshold,
			"alerts_triggered":  latest.AlertsTriggered,
			"hunt_generated":    latest.HuntHypothesesGen,
			"attack_chain_id":   latest.AttackChainID,
			"gap_analysis_id":   latest.GapAnalysisID,
		}
	}

	coverages := m.CalculateCoverage(nil)
	killChain := m.AssessKillChain(hostID, nil)

	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"host_id":          hostID,
		"attck_version":    m.attckVersion,
		"tactics_count":    len(m.tactics),
		"coverages":        coverages,
		"kill_chain":       killChain,
		"apt_groups":       len(m.aptGroups),
		"detection_rules":  len(m.detectionRules),
		"threat_actors":    len(m.threatActors),
		"scenarios":        len(m.scenarios),
		"auto_hunt":        m.autoHunt,
		"beacon_threshold": m.beaconThreshold,
	}
}

func (m *ATTACKModule) loadDefaultMatrix() {
	m.tactics = []ATTACKTactic{
		{
			ID: "TA0043", Name: "Reconnaissance", Domain: "attack_surface",
			Description: "The adversary is trying to gather information they can use to plan future operations.",
			Techniques: m.buildTechniques("TA0043",
				[]string{"T1595", "T1592", "T1589", "T1590", "T1591", "T1593", "T1594", "T1596", "T1597", "T1598"},
				map[string][]string{
					"T1595": {"AS-001", "AS-002"},
					"T1592": {"AS-001"},
				}),
		},
		{
			ID: "TA0042", Name: "Resource Development", Domain: "attack_surface",
			Description: "The adversary is trying to establish resources they can use to support operations.",
			Techniques: m.buildTechniques("TA0042",
				[]string{"T1583", "T1584", "T1585", "T1586", "T1587", "T1588", "T1608", "T1609"},
				map[string][]string{
					"T1588": {"OT-003"},
					"T1608": {"AS-001"},
				}),
		},
		{
			ID: "TA0001", Name: "Initial Access", Domain: "attack_surface",
			Description: "The adversary is trying to get into your network.",
			Techniques: m.buildTechniques("TA0001",
				[]string{"T1189", "T1190", "T1133", "T1200", "T1566", "T1091", "T1195", "T1199", "T1078"},
				map[string][]string{
					"T1190": {"AS-001", "AS-002", "AS-003"},
					"T1133": {"AS-002", "AS-004"},
					"T1566": {"AS-007"},
					"T1078": {"OT-004", "OT-012"},
					"T1200": {"RS-001"},
					"T1195": {"OT-003"},
					"T1091": {"AS-001"},
				}),
		},
		{
			ID: "TA0002", Name: "Execution", Domain: "operation_trust",
			Description: "The adversary is trying to run malicious code.",
			Techniques: m.buildTechniques("TA0002",
				[]string{"T1059", "T1203", "T1559", "T1569", "T1609", "T1106", "T1053", "T1204", "T1210", "T1129", "T1072", "T1647", "T1546", "T1055"},
				map[string][]string{
					"T1059": {"OT-010", "OT-014"},
					"T1203": {"OT-001"},
					"T1053": {"OT-009"},
					"T1055": {"OT-005", "OT-006"},
					"T1546": {"OT-008"},
					"T1210": {"RS-001", "RS-010"},
					"T1569": {"OT-016"},
					"T1559": {"RS-011"},
					"T1106": {"OT-002"},
					"T1072": {"OT-019"},
				}),
		},
		{
			ID: "TA0003", Name: "Persistence", Domain: "operation_trust",
			Description: "The adversary is trying to maintain their foothold.",
			Techniques: m.buildTechniques("TA0003",
				[]string{"T1547", "T1543", "T1546", "T1053", "T1098", "T1505", "T1078", "T1136", "T1137", "T1525", "T1554", "T1037", "T1176", "T1133", "T1574", "T1656", "T1528", "T1559", "T1526", "T1648"},
				map[string][]string{
					"T1547": {"OT-008"},
					"T1053": {"OT-009"},
					"T1505": {"AS-003"},
					"T1078": {"OT-004", "OT-012"},
					"T1136": {"OT-004"},
					"T1546": {"OT-002", "OT-005"},
					"T1574": {"OT-022"},
					"T1543": {"OT-008"},
					"T1525": {"AS-002", "AS-004"},
					"T1528": {"OT-014"},
					"T1176": {"OT-015"},
					"T1559": {"RS-011"},
					"T1037": {"OT-018"},
				}),
		},
		{
			ID: "TA0004", Name: "Privilege Escalation", Domain: "operation_trust",
			Description: "The adversary is trying to gain higher-level permissions.",
			Techniques: m.buildTechniques("TA0004",
				[]string{"T1068", "T1548", "T1134", "T1055", "T1547", "T1543", "T1053", "T1078", "T1546", "T1574", "T1545", "T1611"},
				map[string][]string{
					"T1068": {"OT-005", "OT-007"},
					"T1548": {"OT-005"},
					"T1134": {"OT-006"},
					"T1055": {"OT-005", "OT-006"},
					"T1547": {"OT-008"},
					"T1053": {"OT-009"},
					"T1078": {"OT-004"},
					"T1546": {"OT-002"},
					"T1574": {"OT-022"},
					"T1543": {"OT-008"},
				}),
		},
		{
			ID: "TA0005", Name: "Defense Evasion", Domain: "operation_trust",
			Description: "The adversary is trying to avoid being detected.",
			Techniques: m.buildTechniques("TA0005",
				[]string{"T1562", "T1070", "T1480", "T1027", "T1036", "T1055", "T1548", "T1574", "T1497", "T1564", "T1553", "T1556", "T1202", "T1531", "T1218", "T1140", "T1622", "T1222", "T1550", "T1601"},
				map[string][]string{
					"T1562": {"OT-001", "RS-006"},
					"T1070": {"OT-001", "RS-008"},
					"T1027": {"OT-010"},
					"T1480": {"OT-001"},
					"T1055": {"OT-005", "OT-006"},
					"T1574": {"OT-022"},
					"T1218": {"OT-010"},
					"T1548": {"OT-005"},
					"T1036": {"OT-010"},
					"T1531": {"RS-008"},
					"T1550": {"OT-019"},
					"T1622": {"OT-021"},
					"T1222": {"OT-002", "OT-020"},
					"T1497": {"OT-010"},
					"T1601": {"OT-019"},
					"T1202": {"OT-020"},
					"T1564": {"OT-001"},
					"T1553": {"OT-015"},
				}),
		},
		{
			ID: "TA0006", Name: "Credential Access", Domain: "operation_trust",
			Description: "The adversary is trying to steal account names and passwords.",
			Techniques: m.buildTechniques("TA0006",
				[]string{"T1003", "T1110", "T1552", "T1040", "T1555", "T1539", "T1111", "T1621", "T1187", "T1557", "T1056", "T1528", "T1212", "T1649", "T1606", "T1558", "T1534"},
				map[string][]string{
					"T1003": {"OT-011", "OT-002"},
					"T1110": {"OT-012", "OT-013"},
					"T1552": {"OT-002", "OT-011"},
					"T1555": {"OT-015"},
					"T1040": {"OT-001"},
					"T1056": {"OT-001", "OT-016"},
					"T1558": {"OT-014"},
					"T1528": {"OT-014"},
					"T1621": {"OT-013"},
					"T1539": {"OT-015"},
					"T1606": {"OT-014"},
					"T1187": {"OT-011"},
				}),
		},
		{
			ID: "TA0007", Name: "Discovery", Domain: "resilience",
			Description: "The adversary is trying to figure out your environment.",
			Techniques: m.buildTechniques("TA0007",
				[]string{"T1082", "T1083", "T1018", "T1049", "T1135", "T1016", "T1033", "T1007", "T1069", "T1057", "T1518", "T1526", "T1087", "T1120", "T1497", "T1613", "T1614", "T1615", "T1622"},
				map[string][]string{
					"T1082": {"OT-007"},
					"T1083": {"OT-002"},
					"T1049": {"AS-001", "AS-002"},
					"T1135": {"RS-010"},
					"T1016": {"AS-001"},
					"T1069": {"OT-004"},
					"T1087": {"OT-004"},
					"T1518": {"OT-003"},
				}),
		},
		{
			ID: "TA0008", Name: "Lateral Movement", Domain: "resilience",
			Description: "The adversary is trying to move through your environment.",
			Techniques: m.buildTechniques("TA0008",
				[]string{"T1021", "T1210", "T1550", "T1570", "T1563", "T1021.006", "T1072", "T1091", "T1534"},
				map[string][]string{
					"T1021": {"RS-010", "RS-011", "OT-013"},
					"T1210": {"RS-001", "RS-010"},
					"T1550": {"OT-002", "RS-010"},
					"T1570": {"RS-010"},
					"T1563": {"RS-011"},
					"T1534": {"RS-010"},
					"T1072": {"OT-019"},
				}),
		},
		{
			ID: "TA0009", Name: "Collection", Domain: "resilience",
			Description: "The adversary is trying to gather data of interest to their goal.",
			Techniques: m.buildTechniques("TA0009",
				[]string{"T1005", "T1560", "T1113", "T1056", "T1074", "T1125", "T1115", "T1114", "T1185", "T1557", "T1213", "T1025", "T1123", "T1530", "T1039", "T1602", "T1621"},
				map[string][]string{
					"T1005": {"RS-009"},
					"T1560": {"RS-009"},
					"T1056": {"OT-001", "OT-016"},
					"T1113": {"RS-006"},
					"T1213": {"RS-009"},
				}),
		},
		{
			ID: "TA0011", Name: "Command and Control", Domain: "resilience",
			Description: "The adversary is trying to communicate with compromised systems to control them.",
			Techniques: m.buildTechniques("TA0011",
				[]string{"T1071", "T1573", "T1095", "T1090", "T1102", "T1105", "T1008", "T1571", "T1572", "T1568", "T1219", "T1205", "T1132", "T1011", "T1001", "T1540"},
				map[string][]string{
					"T1071": {"RS-011", "RS-005"},
					"T1573": {"RS-011"},
					"T1090": {"RS-010"},
					"T1102": {"RS-001"},
					"T1219": {"RS-001"},
					"T1008": {"RS-010"},
					"T1568": {"RS-010"},
					"T1205": {"RS-006"},
				}),
		},
		{
			ID: "TA0010", Name: "Exfiltration", Domain: "resilience",
			Description: "The adversary is trying to steal data.",
			Techniques: m.buildTechniques("TA0010",
				[]string{"T1041", "T1048", "T1020", "T1567", "T1052", "T1011", "T1029", "T1530", "T1030"},
				map[string][]string{
					"T1041": {"RS-001", "RS-011"},
					"T1048": {"RS-001", "RS-005"},
					"T1567": {"RS-001"},
					"T1052": {"RS-001"},
					"T1020": {"RS-005"},
					"T1029": {"RS-005"},
				}),
		},
		{
			ID: "TA0040", Name: "Impact", Domain: "business_continuity",
			Description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
			Techniques: m.buildTechniques("TA0040",
				[]string{"T1486", "T1485", "T1565", "T1499", "T1489", "T1498", "T1531", "T1491", "T1529", "T1490", "T1496", "T1482", "T1495"},
				map[string][]string{
					"T1486": {"BC-006", "BC-005"},
					"T1485": {"BC-005", "BC-006", "BC-007"},
					"T1565": {"BC-005"},
					"T1499": {"AS-003"},
					"T1489": {"BC-005"},
					"T1498": {"AS-003"},
					"T1531": {"BC-006"},
					"T1491": {"BC-005"},
					"T1529": {"BC-005"},
					"T1490": {"BC-005"},
				}),
		},
	}
}

func (m *ATTACKModule) buildTechniques(tacticID string, ids []string, checks map[string][]string) []ATTACKTechnique {
	techniques := make([]ATTACKTechnique, 0, len(ids))
	for _, id := range ids {
		t := ATTACKTechnique{
			ID:          id,
			Name:        "Technique " + id,
			AsscorChecks: checks[id],
			Weight:      1.0,
		}
		if len(t.AsscorChecks) > 0 {
			t.Detected = true
			t.Prevented = true
		}
		techniques = append(techniques, t)
	}
	return techniques
}

func (m *ATTACKModule) loadDefaultAPTProfiles() {
	m.aptGroups = map[string]*APTGroupProfile{
		"G0016": {
			GroupID: "G0016", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"},
			Description: "Russian threat group targeting government and diplomatic organizations.",
			PrimaryTargets: []string{"government", "diplomatic", "think_tank"},
			PreferredCVETypes: []string{"mail_client_rce", "auth_bypass"},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"APT 29\"",
			Techniques: map[string]float64{
				"T1566": 0.9, "T1071": 0.8, "T1003": 0.85, "T1059": 0.7,
				"T1133": 0.6, "T1055": 0.5, "T1485": 0.3, "T1070": 0.6,
				"T1027": 0.7, "T1505": 0.4, "T1568": 0.5,
			},
		},
		"G0096": {
			GroupID: "G0096", Name: "APT41", Aliases: []string{"Wicked Spider", "Double Dragon"},
			Description: "Chinese threat group conducting both espionage and financially motivated operations.",
			PrimaryTargets: []string{"multi_industry", "healthcare", "telecom"},
			PreferredCVETypes: []string{"web_server_rce", "supply_chain"},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"APT 41\"",
			Techniques: map[string]float64{
				"T1190": 0.95, "T1059": 0.8, "T1021": 0.7, "T1003": 0.6,
				"T1566": 0.8, "T1574": 0.5, "T1505": 0.6, "T1547": 0.4,
				"T1078": 0.5, "T1486": 0.4,
			},
		},
		"G0032": {
			GroupID: "G0032", Name: "Lazarus Group", Aliases: []string{"HIDDEN COBRA", "Zinc"},
			Description: "North Korean threat group targeting financial institutions and cryptocurrency.",
			PrimaryTargets: []string{"financial", "cryptocurrency", "defense"},
			PreferredCVETypes: []string{"browser_exploit", "document_exploit"},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"Lazarus Group\"",
			Techniques: map[string]float64{
				"T1566": 0.9, "T1203": 0.8, "T1486": 0.85, "T1059": 0.7,
				"T1210": 0.65, "T1021": 0.6, "T1055": 0.5, "T1547": 0.4,
				"T1003": 0.45, "T1070": 0.4, "T1583": 0.3,
			},
		},
		"G0007": {
			GroupID: "G0007", Name: "APT28", Aliases: []string{"Fancy Bear", "Sofacy"},
			Description: "Russian threat group targeting government and military organizations.",
			PrimaryTargets: []string{"government", "military", "media"},
			PreferredCVETypes: []string{"vpn_exploit", "auth_system"},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"APT 28\"",
			Techniques: map[string]float64{
				"T1566": 0.9, "T1133": 0.85, "T1110": 0.8, "T1059": 0.7,
				"T1021": 0.6, "T1547": 0.5, "T1003": 0.65, "T1070": 0.5,
				"T1573": 0.4, "T1090": 0.4,
			},
		},
		"G0046": {
			GroupID: "G0046", Name: "FIN7", Aliases: []string{"Carbanak", "Anunak"},
			Description: "Financially motivated threat group targeting retail and hospitality.",
			PrimaryTargets: []string{"retail", "financial", "hospitality"},
			PreferredCVETypes: []string{"office_app_exploit", "rdp_exploit"},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"FIN7\"",
			Techniques: map[string]float64{
				"T1566": 0.9, "T1055": 0.85, "T1210": 0.8, "T1021": 0.75,
				"T1059": 0.7, "T1003": 0.65, "T1053": 0.5, "T1082": 0.55,
				"T1027": 0.45, "T1070": 0.4,
			},
		},
	}
}

func (m *ATTACKModule) buildTransitionMatrix() {
	m.transMatrix = TransitionMatrix{
		"T1190": {"T1059": 0.7, "T1003": 0.5, "T1082": 0.4, "T1021": 0.3},
		"T1566": {"T1059": 0.6, "T1547": 0.4, "T1082": 0.3},
		"T1133": {"T1059": 0.5, "T1547": 0.5, "T1003": 0.3},
		"T1059": {"T1003": 0.5, "T1082": 0.6, "T1021": 0.4, "T1547": 0.3},
		"T1547": {"T1082": 0.5, "T1003": 0.4, "T1021": 0.3},
		"T1003": {"T1021": 0.5, "T1486": 0.3, "T1041": 0.3},
		"T1082": {"T1003": 0.4, "T1021": 0.5, "T1018": 0.3},
		"T1021": {"T1003": 0.3, "T1486": 0.3, "T1041": 0.4},
		"T1210": {"T1059": 0.5, "T1021": 0.4, "T1082": 0.3},
		"T1203": {"T1059": 0.7, "T1547": 0.3},
		"T1078": {"T1082": 0.6, "T1003": 0.4, "T1021": 0.3},
		"T1110": {"T1078": 0.6, "T1082": 0.3},
		"T1486": {"T1485": 0.4, "T1491": 0.3},
		"T1041": {"T1560": 0.5, "T1486": 0.2},
		"T1071": {"T1041": 0.3, "T1003": 0.2},
	}
}

func (m *ATTACKModule) GetAllTactics() []ATTACKTactic {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ATTACKTactic, len(m.tactics))
	copy(result, m.tactics)
	return result
}

func (m *ATTACKModule) GetTechniquesByTactic(tacticID string) []ATTACKTechnique {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, tac := range m.tactics {
		if tac.ID == tacticID {
			result := make([]ATTACKTechnique, len(tac.Techniques))
			copy(result, tac.Techniques)
			return result
		}
	}
	return nil
}

func (m *ATTACKModule) calculateCoverageLocked(checkResults map[string]bool) []ATTACKCoverage {
	results := make([]ATTACKCoverage, 0, len(m.tactics))

	for _, tactic := range m.tactics {
		total := len(tactic.Techniques)
		if total == 0 {
			continue
		}

		coveredDet := 0
		coveredPrev := 0
		var blindSpots []string

		for _, tech := range tactic.Techniques {
			detPassed := tech.Detected
			prevPassed := tech.Prevented

			if checkResults != nil && len(tech.AsscorChecks) > 0 {
				allDetPassed := true
				allPrevPassed := true
				for _, check := range tech.AsscorChecks {
					if passed, ok := checkResults[check]; ok && !passed {
						allDetPassed = false
						allPrevPassed = false
					}
				}
				if !allDetPassed {
					detPassed = false
				}
				if !allPrevPassed {
					prevPassed = false
				}
			}

			if detPassed {
				coveredDet++
			} else {
				blindSpots = append(blindSpots, tech.ID)
			}
			if prevPassed {
				coveredPrev++
			}
		}

		dc := float64(coveredDet) / float64(total)
		pc := float64(coveredPrev) / float64(total)
		cc := 0.4*dc + 0.6*pc

		riskLevel := "green"
		switch {
		case cc < 0.25:
			riskLevel = "red"
		case cc < 0.50:
			riskLevel = "orange"
		case cc < 0.65:
			riskLevel = "yellow"
		}

		sort.Strings(blindSpots)

		results = append(results, ATTACKCoverage{
			TacticID:        tactic.ID,
			TacticName:      tactic.Name,
			TotalTechniques: total,
			CoveredDet:      coveredDet,
			CoveredPrev:     coveredPrev,
			CoverageDet:     math.Round(dc*1000) / 1000,
			CoveragePrev:    math.Round(pc*1000) / 1000,
			CoverageComp:    math.Round(cc*1000) / 1000,
			RiskLevel:       riskLevel,
			BlindSpots:      blindSpots,
		})
	}

	return results
}

func (m *ATTACKModule) CalculateCoverage(checkResults map[string]bool) []ATTACKCoverage {
	m.mu.RLock()
	results := m.calculateCoverageLocked(checkResults)
	m.mu.RUnlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "attck.coverage.complete", results)
	return results
}

func (m *ATTACKModule) GetCoverageSummary(checkResults map[string]bool) map[string]interface{} {
	coverages := m.CalculateCoverage(checkResults)

	var totalDC, totalPC, totalCC float64
	redCount := 0
	orangeCount := 0

	for _, c := range coverages {
		totalDC += c.CoverageDet
		totalPC += c.CoveragePrev
		totalCC += c.CoverageComp
		switch c.RiskLevel {
		case "red":
			redCount++
		case "orange":
			orangeCount++
		}
	}

	n := float64(len(coverages))
	if n == 0 {
		n = 1
	}

	return map[string]interface{}{
		"avg_detection_coverage":   math.Round(totalDC/n*1000) / 1000,
		"avg_prevention_coverage":  math.Round(totalPC/n*1000) / 1000,
		"avg_composite_coverage":   math.Round(totalCC/n*1000) / 1000,
		"high_blind_tactics":       redCount + orangeCount,
		"total_tactics":           len(coverages),
		"coverage_details":        coverages,
	}
}

func (m *ATTACKModule) MatchAPTGroup(detectedTechniques []string) []APTMatchResult {
	m.mu.RLock()

	detectedSet := make(map[string]bool)
	for _, t := range detectedTechniques {
		detectedSet[t] = true
	}

	var results []APTMatchResult

	for _, group := range m.aptGroups {
		var intersection []string
		union := make(map[string]bool)

		for t := range detectedSet {
			union[t] = true
		}

		var weightedSum float64
		for tech, weight := range group.Techniques {
			union[tech] = true
			if detectedSet[tech] {
				intersection = append(intersection, tech)
				weightedSum += weight
			}
		}

		if len(intersection) == 0 {
			continue
		}

		jaccard := float64(len(intersection)) / float64(len(union))
		similarity := jaccard * weightedSum
		if similarity > 1.0 {
			similarity = 1.0
		}

		confidence := "low"
		switch {
		case similarity >= 0.6 && len(intersection) >= 5:
			confidence = "high"
		case similarity >= 0.4 && len(intersection) >= 3:
			confidence = "medium"
		}

		results = append(results, APTMatchResult{
			GroupID:     group.GroupID,
			GroupName:   group.Name,
			Similarity:  math.Round(similarity*1000) / 1000,
			OverlapTech: intersection,
			Confidence:  confidence,
			MatchCount:  len(intersection),
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Similarity > results[j].Similarity
	})

	var highConfResults []APTMatchResult
	for _, r := range results {
		if r.Confidence == "high" {
			highConfResults = append(highConfResults, r)
		}
	}
	m.mu.RUnlock()

	for _, r := range highConfResults {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   "apt.threat.matched",
			Payload: r,
			Source:  "attck",
		})
		m.kernel.Extensions().Execute(m.kernel.Context(), "attck.apt.matched", r)
	}

	return results
}

func (m *ATTACKModule) GetAPTGroup(groupID string) *APTGroupProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if g, ok := m.aptGroups[groupID]; ok {
		cp := *g
		cp.Techniques = make(map[string]float64, len(g.Techniques))
		for k, v := range g.Techniques {
			cp.Techniques[k] = v
		}
		cp.Aliases = make([]string, len(g.Aliases))
		copy(cp.Aliases, g.Aliases)
		return &cp
	}
	return nil
}

func (m *ATTACKModule) ListAPTGroups() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.aptGroups))
	for _, g := range m.aptGroups {
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names
}

func (m *ATTACKModule) PredictRisk(hostID string, detectedTechniques []string, maxDepth int) PredictiveRisk {
	if maxDepth <= 0 {
		maxDepth = 3
	}

	m.mu.RLock()

	predicted := PredictiveRisk{
		HostID:      hostID,
		CurrentTech: detectedTechniques,
		Timestamp:   time.Now(),
	}

	var maxRisk float64
	var recommendations []string

	for _, startTech := range detectedTechniques {
		paths := m.findPaths(startTech, maxDepth)
		predicted.PredictedPaths = append(predicted.PredictedPaths, paths...)
		for _, p := range paths {
			if p.Risk > maxRisk {
				maxRisk = p.Risk
			}
		}
	}

	predicted.MaxRiskScore = math.Round(maxRisk*1000) / 1000
	predicted.EnhancedThreat = math.Max(0.75, 1.0-predicted.MaxRiskScore*0.25)

	recommendations = m.generateRecommendations(detectedTechniques, predicted.PredictedPaths)
	predicted.Recommendations = recommendations
	m.mu.RUnlock()

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "apt.risk.predicted",
		Payload: predicted,
		Source:  "attck",
	})
	m.kernel.Extensions().Execute(m.kernel.Context(), "attck.risk.predicted", predicted)

	return predicted
}

func (m *ATTACKModule) findPaths(startTech string, maxDepth int) []PredictedPath {
	var paths []PredictedPath

	transitions, ok := m.transMatrix[startTech]
	if !ok {
		return paths
	}

	for nextTech, prob := range transitions {
		path := PredictedPath{
			Path:        []string{startTech, nextTech},
			Probability: math.Round(prob*1000) / 1000,
			EndTech:     nextTech,
			Risk:        prob,
		}

		if maxDepth > 1 {
			subTransitions, ok2 := m.transMatrix[nextTech]
			if ok2 {
				for subNext, subProb := range subTransitions {
					combinedProb := prob * subProb
					subPath := PredictedPath{
						Path:        []string{startTech, nextTech, subNext},
						Probability: math.Round(combinedProb*1000) / 1000,
						EndTech:     subNext,
						Risk:        combinedProb,
					}
					paths = append(paths, subPath)
				}
			}
		}

		paths = append(paths, path)
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Risk > paths[j].Risk
	})

	if len(paths) > 10 {
		paths = paths[:10]
	}

	return paths
}

func (m *ATTACKModule) generateRecommendations(detected []string, paths []PredictedPath) []string {
	var recs []string
	seen := make(map[string]bool)

	for _, p := range paths {
		if p.Risk > 0.3 {
			endTech := p.EndTech
			if seen[endTech] {
				continue
			}
			seen[endTech] = true

			for _, tactic := range m.tactics {
				for _, tech := range tactic.Techniques {
					if tech.ID == endTech && len(tech.AsscorChecks) > 0 {
						recs = append(recs, "加固 "+tech.ID+" "+tactic.Name+": "+strings.Join(tech.AsscorChecks, ","))
						break
					}
				}
			}
		}
	}

	return recs
}

func (m *ATTACKModule) assessKillChainLocked(hostID string, checkResults map[string]bool, stages []KillChainStage) KillChainAssessment {
	for si := range stages {
		stage := &stages[si]
		totalChecks := 0
		passedChecks := 0

		for _, tacticID := range stage.Tactics {
			for _, tactic := range m.tactics {
				if tactic.ID != tacticID {
					continue
				}
				for _, tech := range tactic.Techniques {
					if len(tech.AsscorChecks) > 0 {
						totalChecks += len(tech.AsscorChecks)
						for _, check := range tech.AsscorChecks {
							if checkResults != nil {
								if passed, ok := checkResults[check]; ok && passed {
									passedChecks++
								}
							} else {
								passedChecks++
							}
						}
					}
				}
			}
		}

		stage.ChecksTotal = totalChecks
		stage.ChecksPassed = passedChecks

		if totalChecks > 0 {
			stage.Score = float64(passedChecks) / float64(totalChecks) * 100
		}

		switch {
		case stage.Score >= 80:
			stage.Status = "healthy"
		case stage.Score >= 60:
			stage.Status = "moderate"
		case stage.Score >= 40:
			stage.Status = "vulnerable"
		default:
			stage.Status = "critical"
		}
	}

	var totalScore float64
	var weakestStage string
	var weakestScore float64 = 100

	for _, stage := range stages {
		totalScore += stage.Score
		if stage.Score < weakestScore {
			weakestScore = stage.Score
			weakestStage = stage.Name
		}
	}

	return KillChainAssessment{
		HostID:         hostID,
		Stages:         stages,
		OverallScore:   math.Round(totalScore/float64(len(stages))*100) / 100,
		WeakestStage:   weakestStage,
		AssessmentTime: time.Now(),
	}
}

func (m *ATTACKModule) AssessKillChain(hostID string, checkResults map[string]bool) KillChainAssessment {
	stages := []KillChainStage{
		{Name: "侦察", Tactics: []string{"TA0043", "TA0042"}, Score: 100},
		{Name: "投递", Tactics: []string{"TA0001"}, Score: 100},
		{Name: "突破", Tactics: []string{"TA0002"}, Score: 100},
		{Name: "提权", Tactics: []string{"TA0004"}, Score: 100},
		{Name: "驻留", Tactics: []string{"TA0003"}, Score: 100},
		{Name: "横向移动", Tactics: []string{"TA0008"}, Score: 100},
		{Name: "窃取", Tactics: []string{"TA0010", "TA0009"}, Score: 100},
		{Name: "防御规避", Tactics: []string{"TA0005"}, Score: 100},
		{Name: "破坏", Tactics: []string{"TA0040"}, Score: 100},
	}

	m.mu.RLock()
	result := m.assessKillChainLocked(hostID, checkResults, stages)
	m.mu.RUnlock()

	return result
}

func (m *ATTACKModule) GetTransitionMatrix() TransitionMatrix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(TransitionMatrix)
	for k, v := range m.transMatrix {
		inner := make(map[string]float64)
		for k2, v2 := range v {
			inner[k2] = v2
		}
		result[k] = inner
	}
	return result
}

func (m *ATTACKModule) AddTechniqueToTactic(tacticID string, tech ATTACKTechnique) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, tactic := range m.tactics {
		if tactic.ID == tacticID {
			for _, existing := range tactic.Techniques {
				if existing.ID == tech.ID {
					return
				}
			}
			m.tactics[i].Techniques = append(m.tactics[i].Techniques, tech)
			return
		}
	}
}

func (m *ATTACKModule) UpdateCheckMapping(techID string, AsscorChecks []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for ti, tactic := range m.tactics {
		for tj, tech := range tactic.Techniques {
			if tech.ID == techID {
				m.tactics[ti].Techniques[tj].AsscorChecks = AsscorChecks
				if len(AsscorChecks) > 0 {
					m.tactics[ti].Techniques[tj].Detected = true
					m.tactics[ti].Techniques[tj].Prevented = true
				}
				return
			}
		}
	}
}

func (m *ATTACKModule) UpsertAPTGroup(profile APTGroupProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aptGroups[profile.GroupID] = &profile
}

type ATTACKInterface interface {
	GetAllTactics() []ATTACKTactic
	GetTechniquesByTactic(tacticID string) []ATTACKTechnique
	CalculateCoverage(checkResults map[string]bool) []ATTACKCoverage
	GetCoverageSummary(checkResults map[string]bool) map[string]interface{}
	MatchAPTGroup(detectedTechniques []string) []APTMatchResult
	GetAPTGroup(groupID string) *APTGroupProfile
	ListAPTGroups() []string
	PredictRisk(hostID string, detectedTechniques []string, maxDepth int) PredictiveRisk
	AssessKillChain(hostID string, checkResults map[string]bool) KillChainAssessment
	GetTransitionMatrix() TransitionMatrix
	AddTechniqueToTactic(tacticID string, tech ATTACKTechnique)
	UpdateCheckMapping(techID string, AsscorChecks []string)
	UpsertAPTGroup(profile APTGroupProfile)
	Version() string
	RegisterDetectionRule(rule DetectionRule) error
	GetDetectionRule(ruleID string) *DetectionRule
	ListDetectionRules(techniqueID string, enabledOnly bool) []DetectionRule
	DeleteDetectionRule(ruleID string) bool
	EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error)
	GetAlerts(hostID, severity string, limit int) []DetectionAlert
	AcknowledgeAlert(alertID string) bool
	RecordAnomaly(event AnomalyEvent)
	GetAnomalies(hostID string, minScore float64, limit int) []AnomalyEvent
	CorrelateAlerts(hostID string) []CorrelationResult
	GetDetectionSummary() DetectionSummary
	AddIOC(entry IOCEntry) error
	GetIOCs(iocType string, techniqueID string, limit int) []IOCEntry
	SearchIOC(value string) []IOCEntry
	DeleteIOC(iocID string) bool
	ExpireIOCs() int
	UpsertThreatActor(profile ThreatActorProfile) error
	GetThreatActor(actorID string) *ThreatActorProfile
	ListThreatActors() []ThreatActorProfile
	MatchThreatActor(detectedTechniques []string) []APTMatchResult
	AddTTPTrack(track TTPTrack) error
	GetTTPTracks(actorID, techniqueID string) []TTPTrack
	EnrichAlertWithTI(alertID string) (*DetectionAlert, map[string]interface{})
	GetTISummary() map[string]interface{}
	CreateScenario(scenario EmulationScenario) error
	GetScenario(scenarioID string) *EmulationScenario
	ListScenarios(actorProfile string) []EmulationScenario
	DeleteScenario(scenarioID string) bool
	GenerateScenarioFromActor(actorID string) (*EmulationScenario, error)
	RunEmulation(scenarioID, hostID string, safeMode bool) (*EmulationResult, error)
	GetEmulationResults(scenarioID string, limit int) []EmulationResult
	PerformGapAnalysis(hostID string) (*AssessmentReport, error)
	GetControlMapping(techniqueID string) *ControlMapping
	GetAssessmentReports(hostID string, limit int) []AssessmentReport
	CreateImprovementTrack(track ImprovementTrack) error
	GetImprovementTrack(trackID string) *ImprovementTrack
	ListImprovementTracks() []ImprovementTrack
	UpdateImprovementAction(trackID, actionID string, status string) error
	CalculateImprovementProgress(trackID string) (float64, error)
	ReconstructAttackChain(hostIDs []string) (*AttackChain, error)
	GetAttackChains(hostID string, limit int) []AttackChain
	CorrelateMultiIndicator(hostIDs []string) []MultiIndicatorCorrelation
	RegisterBehavioralIndicator(indicator BehavioralIndicator) error
	ListBehavioralIndicators(techniqueID string) []BehavioralIndicator
	DeleteBehavioralIndicator(indicatorID string) bool
	UpdateBaseline(hostID string, metrics map[string]float64)
	GetBaseline(hostID string) *BehavioralBaseline
	EvaluateBehavioralIndicators(hostID string, metrics map[string]float64) []BehavioralAlert
	GetBehavioralAlerts(hostID string, limit int) []BehavioralAlert
	DetectBeaconing(hostID string, events []TimeSeriesPoint) []BeaconDetection
	GetBeaconDetections(hostID string, limit int) []BeaconDetection
	PerformAttribution(chainID string) (*AttributionResult, error)
	GenerateAPTAnalysisReport(hostIDs []string) (*APTAnalysisReport, error)
	CreateHuntHypothesis(hypothesis HuntHypothesis) error
	GetHuntHypothesis(hypothesisID string) *HuntHypothesis
	ListHuntHypotheses(techniqueID string, status string) []HuntHypothesis
	DeleteHuntHypothesis(hypothesisID string) bool
	ExecuteHunt(hypothesisID string, hostID string) (*HuntResult, error)
	GetHuntResults(hostID string, limit int) []HuntResult
	AutoGenerateHypotheses(hostID string) ([]HuntHypothesis, error)
	ComputeGroupBaseline(role string) *GroupBaseline
	ApplyGroupBaseline(hostID string, role string) bool
	BuildBayesianAttributionNetwork() *BayesianNetwork
	PerformBayesianAttribution(chainID string) (*BayesianInferenceResult, error)
	FilterBeaconWithReputation(detections []BeaconDetection) []BeaconDetection
	AddReputationEntry(entry ReputationEntry)
	GetReputationEntries(category string) []ReputationEntry
	LoadYARARules(rules []YARARule) int
	LoadSigmaRules(rules []SigmaRule) int
	MatchYARARules(hostID string, filePaths []string, fileContents map[string]string) []RuleMatchResult
	MatchSigmaRules(hostID string, logEntries []map[string]string) []RuleMatchResult
	AnalyzeCrossHostConnections(connections []CrossHostConnection) []LateralMovementEvidence
	ComputeCausalChain(techniqueIDs []string) *CausalChain
	GetHostAnalysisHistory(hostID string, limit int) []HostAnalysisRecord
	GetLastAnalysis(hostID string) map[string]interface{}
}