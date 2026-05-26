package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/ssam"
)

type SPCProvider interface {
	Enabled() bool
	GetAsset(hostID string) *SPCLocalAsset
	UpsertAsset(asset SPCLocalAsset)
	Calculate(hostID string, assetPackages []string) SPCCorrection
}

type SPCLocalAsset struct {
	HostID        string
	NetworkZone   string
	Role          string
	Packages      []string
	InstalledCPEs []string
	Compensations SPCCompensations
}

type SPCCompensations struct {
	VirtualPatch  bool
	WAFRules      bool
	IPSRules      bool
	AppWhitelist  bool
}

type SPCCorrection struct {
	Score            float64
	Weights          map[string]float64
	Action           string
	AffectedCVE      []string
	TopCVEImpact     string
	TotalPenalty     float64
	PenaltyBreakdown []interface{}
	KillChainScore   float64
}

type Assessor struct {
	cfg           *config.Config
	scoringEngine *DynamicScoringEngine
	ssamEngine    *ssam.Engine
	spcProvider   SPCProvider
	maxWorkers    int
	resultsCache  sync.Map
	mu            sync.RWMutex
}

func NewAssessor(cfg *config.Config) *Assessor {
	engine := NewDynamicScoringEngine()

	ssamEngine := ssam.NewEngine()
	if cfg != nil {
		ssamEngine.SetWeights(ssam.ConfigToWeights(cfg))
		ssamEngine.SetEdgeFactors(ssam.ConfigToEdgeFactors(cfg))
		w := cfg.Weights
		engine.SetWeight(model.DomainAttackSurface, w.AttackSurface)
		engine.SetWeight(model.DomainBusinessContinuity, w.BusinessContinuity)
		engine.SetWeight(model.DomainOperationTrust, w.OperationTrust)
		engine.SetWeight(model.DomainResilience, w.Resilience)

		for domain, val := range cfg.ExtensionWeights {
			engine.SetWeight(domain, val)
		}
	}

	engine.InitializeDefaults()
	ssamEngine.InitializeDefaults(nil, nil)

	return &Assessor{
		cfg:           cfg,
		scoringEngine: engine,
		ssamEngine:    ssamEngine,
		maxWorkers:    10,
	}
}

func (a *Assessor) SetSPCProvider(provider SPCProvider) {
	a.spcProvider = provider
}

func (a *Assessor) SSAMEngine() *ssam.Engine {
	return a.ssamEngine
}

func (a *Assessor) ScoringEngine() *DynamicScoringEngine {
	return a.scoringEngine
}

func (a *Assessor) Assess(hostID string, hostname string) *model.AssessmentResult {
	ctx := context.Background()
	if hostID == "" {
		hostID, _ = os.Hostname()
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	result := &model.AssessmentResult{
		HostID:    hostID,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: a.cfg.Threshold,
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreCheck, result)

	adapterResults := a.runAdapterPipeline()
	for _, r := range adapterResults {
		for _, f := range r.Findings {
			result.Checks = append(result.Checks, f.ToCheckResult())
		}
		if r.Error != nil {
			logger.WithComponent("assessor").Error("adapter failed", "adapter_id", r.AdapterID, "error", r.Error)
			result.Checks = append(result.Checks, model.CheckResult{
				CheckID: "ADAPTER-" + r.AdapterID,
				Domain:  "attack_surface",
				Name:    "External Adapter: " + r.AdapterName,
				Passed:  false,
				Delta:   -5,
				Detail:  fmt.Sprintf("Adapter %s execution failed: %v", r.AdapterName, r.Error),
			})
		}
	}

	delegatedIDs := a.buildDelegatedSet(adapterResults)

	items := checks.GetAll()
	if len(items) == 0 && len(result.Checks) == 0 {
		return a.buildEmptyResult(result)
	}

	var remainingItems []model.CheckItem
	for _, item := range items {
		if delegatedIDs[item.ID] {
			continue
		}
		if !ShouldActivateCheck(&item, result) {
			continue
		}
		remainingItems = append(remainingItems, item)
	}

	SortChecksByPriority(remainingItems)

	a.runChecksConcurrently(remainingItems, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostCheck, result)

	spcScore := a.computeSPCScore(ctx, hostID, result)

	ssamInput := &ssam.AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Timestamp:   result.Timestamp,
		Threshold:   result.Threshold,
		Checks:      ssam.CheckResultsToInputs(result.Checks),
		ThreatCoeff: a.cfg.ThreatCoeff,
		SPCScore:    spcScore,
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreScore, result)

	ssamOutput, err := a.ssamEngine.ComputeScore(ctx, ssamInput)
	if err != nil {
		logger.WithComponent("assessor").Error("ssam compute failed, fallback to legacy", "error", err)
		dynScores := a.computeDynamicDomainScores(result)
		for domain, score := range dynScores.GetAll() {
			result.DomainScores.Set(domain, score)
		}
		a.evaluateEdgeFactorChain(result)
		a.ensureDefaults(result)
		result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
		result.Acceptable = result.FinalScore >= result.Threshold
	} else {
		ssam.OutputToModel(ssamOutput, result)
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePostScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreReport, result)

	return result
}

func (a *Assessor) buildEmptyResult(result *model.AssessmentResult) *model.AssessmentResult {
	result.Acceptable = true
	result.FinalScore = 100
	result.DomainScores = model.DomainScores{
		AttackSurface:      100,
		BusinessContinuity: 100,
		OperationTrust:     100,
		Resilience:         100,
	}
	result.ThreatCoeff = a.cfg.ThreatCoeff
	result.SPCScore = 1.0
	return result
}

func (a *Assessor) ensureDefaults(result *model.AssessmentResult) {
	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = a.cfg.ThreatCoeff
	}
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}
}

func (a *Assessor) computeSPCScore(ctx context.Context, hostID string, result *model.AssessmentResult) float64 {
	if a.spcProvider == nil || !a.spcProvider.Enabled() {
		return 1.0
	}

	a.syncACIToSPCAsset(hostID, result)

	var packages []string
	if asset := a.spcProvider.GetAsset(hostID); asset != nil {
		packages = asset.Packages
	}
	if len(packages) == 0 {
		packages = a.collectPackageHints(result)
	}

	correction := a.spcProvider.Calculate(hostID, packages)

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
		"affected_cve", len(correction.AffectedCVE),
		"total_penalty", correction.TotalPenalty)

	return correction.Score
}

func (a *Assessor) syncACIToSPCAsset(hostID string, result *model.AssessmentResult) {
	asset := a.spcProvider.GetAsset(hostID)
	if asset == nil {
		asset = &SPCLocalAsset{HostID: hostID}
	}

	aciChecks := map[string]*bool{}
	for i := range result.Checks {
		c := &result.Checks[i]
		if strings.HasPrefix(c.CheckID, "AC-") {
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
		a.spcProvider.UpsertAsset(*asset)
	}
}

func (a *Assessor) collectPackageHints(result *model.AssessmentResult) []string {
	seen := make(map[string]bool)
	var packages []string

	for _, c := range result.Checks {
		detail := strings.ToLower(c.Detail)
		extractPkgHints(detail, seen, &packages)
	}

	return packages
}

func extractPkgHints(detail string, seen map[string]bool, packages *[]string) {
	keywords := []string{
		"openssl", "nginx", "php", "apache", "httpd",
		"openssh", "ssh", "bind", "postfix", "dovecot",
		"mysql", "mariadb", "postgresql", "redis", "mongodb",
		"java", "tomcat", "node", "python", "perl", "ruby",
		"kernel", "linux", "systemd", "docker", "containerd",
		"clamav", "suricata", "fail2ban", "aide", "ossec",
		"rsync", "rclone", "chrony", "ntpd", "auditd",
	}
	for _, kw := range keywords {
		if strings.Contains(detail, kw) && !seen[kw] {
			seen[kw] = true
			*packages = append(*packages, kw)
		}
	}
}

func (a *Assessor) AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult {
	cacheKey := fmt.Sprintf("%s_%d_%s", hostID, len(checkResults), hashCheckResults(checkResults))
	if cached, ok := a.resultsCache.Load(cacheKey); ok {
		cachedResult := cached.(*model.AssessmentResult)
		if time.Since(cachedResult.Timestamp) < 5*time.Minute {
			return cachedResult
		}
		a.resultsCache.Delete(cacheKey)
	}

	ctx := context.Background()
	result := &model.AssessmentResult{
		HostID:    hostID,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: a.cfg.Threshold,
		Checks:    checkResults,
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreCheck, result)

	adapterResults := a.runAdapterPipeline()
	for _, r := range adapterResults {
		for _, f := range r.Findings {
			result.Checks = append(result.Checks, f.ToCheckResult())
		}
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePostCheck, result)

	if len(result.Checks) == 0 {
		return a.buildEmptyResult(result)
	}

	spcScore := a.computeSPCScore(ctx, hostID, result)

	ssamInput := &ssam.AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Timestamp:   result.Timestamp,
		Threshold:   result.Threshold,
		Checks:      ssam.CheckResultsToInputs(result.Checks),
		ThreatCoeff: a.cfg.ThreatCoeff,
		SPCScore:    spcScore,
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePreScore, result)

	ssamOutput, err := a.ssamEngine.ComputeScore(ctx, ssamInput)
	if err != nil {
		logger.WithComponent("assessor").Error("ssam compute failed, fallback to legacy", "error", err)
		dynScores := a.computeDynamicDomainScores(result)
		for domain, score := range dynScores.GetAll() {
			result.DomainScores.Set(domain, score)
		}
		a.evaluateEdgeFactorChain(result)
		a.ensureDefaults(result)
		result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
		result.Acceptable = result.FinalScore >= result.Threshold
	} else {
		ssam.OutputToModel(ssamOutput, result)
	}

	a.scoringEngine.Hooks().Execute(ctx, PhasePostScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreReport, result)

	a.resultsCache.Store(cacheKey, result)

	return result
}

func (a *Assessor) runChecksConcurrently(items []model.CheckItem, result *model.AssessmentResult) {
	sem := make(chan struct{}, a.maxWorkers)
	var wg sync.WaitGroup
	resultsCh := make(chan model.CheckResult, len(items))

	for _, item := range items {
		wg.Add(1)
		go func(it model.CheckItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resultsCh <- it.Run()
		}(item)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		result.Checks = append(result.Checks, r)
	}
}

func (a *Assessor) runAdapterPipeline() []adapter.PipelineResult {
	if len(a.cfg.AdapterConfig) == 0 {
		return nil
	}

	enabledCount := 0
	for _, v := range a.cfg.AdapterConfig {
		if v == "on" || v == "true" || v == "1" {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		return nil
	}

	allAdapters := adapter.List()
	if len(allAdapters) == 0 {
		return nil
	}

	pipeline := adapter.NewPipeline(a.cfg.AdapterConfig)
	pipeline.WithAdapters(allAdapters...)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	return pipeline.RunAll(ctx)
}

func (a *Assessor) buildDelegatedSet(results []adapter.PipelineResult) map[string]bool {
	delegated := make(map[string]bool)
	for _, r := range results {
		if r.Error != nil {
			continue
		}
		for _, f := range r.Findings {
			if f.DelegatedTo != "" {
				delegationRules := adapter.GetDelegationRules(r.AdapterID)
				for _, rule := range delegationRules {
					delegated[rule.CheckID] = true
				}
			}
		}
	}
	return delegated
}

func (a *Assessor) computeDynamicDomainScores(result *model.AssessmentResult) *model.DynamicDomainScores {
	scores := model.NewDynamicDomainScores()

	activeDomains := make(map[string]bool)
	for _, c := range result.Checks {
		activeDomains[c.Domain] = true
	}
	if len(activeDomains) == 0 {
		for _, id := range model.ListDomainIDs() {
			activeDomains[id] = true
		}
	}

	for domain := range activeDomains {
		scores.Set(domain, 100)
	}

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		delta := a.cfg.CheckDeltas[check.CheckID]
		if delta == 0 {
			delta = check.Delta
		}
		current := scores.Get(check.Domain)
		scores.Set(check.Domain, math.Max(0, current+delta))
	}

	return scores
}

func (a *Assessor) evaluateEdgeFactorChain(result *model.AssessmentResult) {
	localFactors := make(map[string]float64)
	for _, ef := range model.ListEdgeFactors() {
		localFactors[ef.ID] = 1.0
	}

	customFactors := a.cfg.EdgeFactorsCustom
	if len(customFactors) == 0 {
		customFactors = map[string]float64{
			"EF-002FA":     a.cfg.EdgeFactors.TwoFactorFailure,
			"EF-SYNCOOKIE": 0.75,
			"EF-SELINUX":   0.80,
			"EF-APPARMOR":  0.82,
			"EF-NO-SIEM":   0.90,
			"EF-NO-IDS":    0.88,
		}
	}

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		switch check.CheckID {
		case "EF-001":
			if v, ok := customFactors["EF-002FA"]; ok {
				localFactors["EF-002FA"] = v
			} else {
				localFactors["EF-002FA"] = a.cfg.EdgeFactors.TwoFactorFailure
			}
		case "EF-002":
			if v, ok := customFactors["EF-3FA"]; ok {
				localFactors["EF-3FA"] = v
			} else {
				localFactors["EF-3FA"] = 0.82
			}
			if v, ok := localFactors["EF-002FA"]; !ok || v > 0.82 {
				localFactors["EF-002FA"] = 0.82
			}
		default:
			if penalty, ok := customFactors[check.CheckID]; ok && penalty < 1.0 {
				localFactors[check.CheckID] = penalty
			}
		}
	}

	mapped := model.EdgeFactors{
		TwoFactorFailure: 1.0,
		SYNCookieDisabled: 1.0,
		SELinuxDisabled:  1.0,
		AppArmorDisabled: 1.0,
		NoSIEM:           1.0,
		NoIDS:            1.0,
	}
	if v, ok := localFactors["EF-002FA"]; ok && v < 1.0 {
		mapped.TwoFactorFailure = v
	}
	if v, ok := localFactors["EF-SYNCOOKIE"]; ok && v < 1.0 {
		mapped.SYNCookieDisabled = v
	}
	if v, ok := localFactors["EF-SELINUX"]; ok && v < 1.0 {
		mapped.SELinuxDisabled = v
	}
	if v, ok := localFactors["EF-APPARMOR"]; ok && v < 1.0 {
		mapped.AppArmorDisabled = v
	}
	if v, ok := localFactors["EF-NO-SIEM"]; ok && v < 1.0 {
		mapped.NoSIEM = v
	}
	if v, ok := localFactors["EF-NO-IDS"]; ok && v < 1.0 {
		mapped.NoIDS = v
	}
	result.EdgeFactors = mapped
}

func (a *Assessor) computeDynamicFinalScore(scores *model.DynamicDomainScores, result *model.AssessmentResult) float64 {
	baseScore := a.scoringEngine.ComputeWeightedSum(scores)

	baseScore *= result.ThreatCoeff
	baseScore *= result.SPCScore

	activeFactors := result.EdgeFactors.ActiveFactors()
	for _, f := range activeFactors {
		baseScore *= f
	}

	return math.Round(baseScore*100) / 100
}

func (a *Assessor) PrintReport(result *model.AssessmentResult) string {
	bar := func(score float64, width int) string {
		filled := int(score / 100 * float64(width))
		if filled > width {
			filled = width
		}
		b := make([]byte, width)
		for i := 0; i < width; i++ {
			if i < filled {
				b[i] = '='
			} else {
				b[i] = ' '
			}
		}
		return string(b)
	}

	report := fmt.Sprintf("[ Core Domain Scores ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	for _, m := range model.ListDomainsByCategory(model.CategoryCore) {
		label := m.Label
		if label == "" {
			label = model.GetDomainLabel(m.ID)
		}
		score := result.DomainScores.Get(m.ID)
		report += fmt.Sprintf("  %-20s : [%-20s] %.0f/100\n", label, bar(score, 20), score)
	}

	checksByDomain := make(map[string][]model.CheckResult)
	for _, c := range result.Checks {
		checksByDomain[c.Domain] = append(checksByDomain[c.Domain], c)
	}

	coreIDs := make(map[string]bool)
	for _, m := range model.ListDomainsByCategory(model.CategoryCore) {
		coreIDs[m.ID] = true
	}

	report += fmt.Sprintf("\n[ Extension Domain Scores ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	extFound := false
	for domain, checks := range checksByDomain {
		if coreIDs[domain] {
			continue
		}
		extFound = true
		passed := 0
		for _, c := range checks {
			if c.Passed {
				passed++
			}
		}
		label := model.GetDomainLabel(domain)
		score := result.DomainScores.Get(domain)
		report += fmt.Sprintf("  %-20s : [%-20s] %.0f/100  (%d of %d checks passed)\n",
			label, bar(score, 20), score, passed, len(checks))
	}
	if !extFound {
		report += fmt.Sprintf("  (none)\n")
	}

	report += fmt.Sprintf("\n[ Edge Factor Report ]\n")
	report += fmt.Sprintf("---------------------------------------------------------------\n")
	for _, ef := range model.ListEdgeFactors() {
		if ef.Active {
			report += fmt.Sprintf("  %-12s : %-30s factor=%.2f (ACTIVE)\n", ef.ID, ef.Name, ef.Factor)
		}
	}

	for domain, checks := range checksByDomain {
		label := model.GetDomainLabel(domain)
		report += fmt.Sprintf("\n[ %s Details ]\n", label)
		report += fmt.Sprintf("---------------------------------------------------------------\n")
		for _, c := range checks {
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			detail := c.Detail
			if detail != "" {
				report += fmt.Sprintf("  [%s] %s : %s (%s)\n", status, c.CheckID, c.Name, detail)
			} else {
				report += fmt.Sprintf("  [%s] %s : %s\n", status, c.CheckID, c.Name)
			}
		}
	}

	report += fmt.Sprintf("\n---------------------------------------------------------------\n")
	var status string
	if result.Acceptable {
		status = "ACCEPTABLE"
	} else {
		status = "NOT ACCEPTABLE"
	}
	report += fmt.Sprintf("  Final Score: %.2f/100    Threshold: %.2f    Status: %s\n",
		result.FinalScore, result.Threshold, status)
	report += fmt.Sprintf("  Threat Coeff: %.2f    SPC Score: %.2f\n",
		result.ThreatCoeff, result.SPCScore)
	report += fmt.Sprintf("---------------------------------------------------------------\n")

	return report
}

func (a *Assessor) ValidateEdgeFactors(registeredChecks []model.CheckItem) []string {
	var warnings []string

	overlapLabels := map[string]string{
		"RS-005": "SYN Cookie edge factor overlap (SSAM 1.3 removed overlap, resilience domain only)",
		"OT-004": "Supply chain edge factor overlap (SSAM 1.3 removed overlap, operation trust domain only)",
		"RS-003": "Auto-block edge factor overlap (SSAM 1.3 removed overlap, resilience domain only)",
		"BC-003": "Resource tension edge factor overlap (SSAM 1.3 removed overlap, business continuity domain only)",
	}

	for _, check := range registeredChecks {
		if label, exists := overlapLabels[check.ID]; exists {
			warnings = append(warnings, fmt.Sprintf("Edge factor conflict: %s", label))
		}
	}

	return warnings
}

func (a *Assessor) ReloadWeights(cfg *config.Config) {
	if cfg == nil {
		return
	}
	w := cfg.Weights
	a.scoringEngine.SetWeight(model.DomainAttackSurface, w.AttackSurface)
	a.scoringEngine.SetWeight(model.DomainBusinessContinuity, w.BusinessContinuity)
	a.scoringEngine.SetWeight(model.DomainOperationTrust, w.OperationTrust)
	a.scoringEngine.SetWeight(model.DomainResilience, w.Resilience)

	for domain, val := range cfg.ExtensionWeights {
		a.scoringEngine.SetWeight(domain, val)
	}

	a.ssamEngine.SetWeights(ssam.ConfigToWeights(cfg))
	a.ssamEngine.SetEdgeFactors(ssam.ConfigToEdgeFactors(cfg))

	logger.WithComponent("assessor").Info("weights reloaded from config (engine + ssam)")
}

func (a *Assessor) RegisterHook(id string, phase AssessmentPhase, hook AssessmentHook, priority int) {
	a.scoringEngine.Hooks().Register(id, phase, hook, priority)
}

func (a *Assessor) UnregisterHook(id string) {
	a.scoringEngine.Hooks().Unregister(id)
}

func hashCheckResults(results []model.CheckResult) string {
	h := sha256.New()
	for _, r := range results {
		h.Write([]byte(r.CheckID))
		if r.Passed {
			h.Write([]byte("1"))
		} else {
			h.Write([]byte("0"))
		}
		var buf [8]byte
		bits := math.Float64bits(r.Delta)
		for i := 0; i < 8; i++ {
			buf[i] = byte(bits >> uint(i*8))
		}
		h.Write(buf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
