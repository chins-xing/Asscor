//go:build engine

package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chins-xing/asscor/internal/adapter"
	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/logger"
	"github.com/chins-xing/asscor/internal/model"
)

// Contract type aliases. The canonical definitions live in the microkernel
// (internal/kernel/engine_types.go); these aliases preserve the historical
// engine.* names for callers that already reference them.
type (
	AssessorEngine        = kernel.AssessorEngine
	SPCProvider           = kernel.SPCProvider
	ATTACKProvider        = kernel.ATTACKProvider
	ATTACKCoverageResult  = kernel.ATTACKCoverageResult
	ATTACKKillChainResult = kernel.ATTACKKillChainResult
	ATTACKKillChainStage  = kernel.ATTACKKillChainStage
	ATTACKAPTMatch        = kernel.ATTACKAPTMatch
	ATTACKPredictedRisk   = kernel.ATTACKPredictedRisk
	ATTACKTacticInfo      = kernel.ATTACKTacticInfo
	ATTACKTechniqueInfo   = kernel.ATTACKTechniqueInfo
	SPCLocalAsset         = kernel.SPCLocalAsset
	SPCCompensations      = kernel.SPCCompensations
	SPCCorrection         = kernel.SPCCorrection
)

type Assessor struct {
	cfg            *config.Config
	scoringEngine  *DynamicScoringEngine
	pluginEngine   AssessorEngine
	spcProvider    SPCProvider
	attackProvider ATTACKProvider
	maxWorkers     int
	resultsCache   sync.Map
	mu             sync.RWMutex
}

func NewAssessor(cfg *config.Config) *Assessor {
	engine := NewDynamicScoringEngine()

	if cfg != nil {
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

	return &Assessor{
		cfg:           cfg,
		scoringEngine: engine,
		maxWorkers:    10,
	}
}

// SetPluginEngine injects an external algorithm engine (e.g., SSAM).
// Call this before the first assessment. If not set or nil, the built-in
// DynamicScoringEngine handles all scoring.
func (a *Assessor) SetPluginEngine(engine AssessorEngine) {
	a.pluginEngine = engine
	if engine != nil && a.cfg != nil {
		engine.ReloadWeights(a.cfg)
	}
}

func (a *Assessor) SetSPCProvider(provider SPCProvider) {
	a.spcProvider = provider
}

func (a *Assessor) SetATTACKProvider(provider ATTACKProvider) {
	a.attackProvider = provider
}

func (a *Assessor) PluginEngine() AssessorEngine {
	return a.pluginEngine
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

	a.computeSPCScore(ctx, hostID, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreScore, result)

	if !a.tryPluginScore(ctx, result) {
		a.runLegacyScoring(result)
	}

	a.applyATTACK(hostID, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreReport, result)
	a.scoringEngine.Hooks().Execute(ctx, PhasePostReport, result)

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

	result.SPCScore = a.computeSPCScore(ctx, hostID, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreScore, result)

	if !a.tryPluginScore(ctx, result) {
		a.runLegacyScoring(result)
	}

	a.applyATTACK(hostID, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePostScore, result)

	a.scoringEngine.Hooks().Execute(ctx, PhasePreReport, result)
	a.scoringEngine.Hooks().Execute(ctx, PhasePostReport, result)

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
		if !r.Passed && isPermDenied(r.Detail) {
			r.Passed = true
			r.Delta = 0
			r.Detail = "skipped — requires root privileges (" + r.Detail + ")"
		}
		result.Checks = append(result.Checks, r)
	}
}

func isPermDenied(detail string) bool {
	lower := strings.ToLower(detail)
	// Standard Go error messages from os.ReadFile / exec.Cmd / syscall
	if strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "permission_error") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "eacces") ||
		strings.Contains(lower, "eperm") {
		return true
	}
	// Chinese / localized error patterns
	if strings.Contains(detail, "权限") ||
		strings.Contains(detail, "无权限") ||
		strings.Contains(detail, "拒绝访问") ||
		strings.Contains(detail, "許可") {
		return true
	}
	// PathError from Go stdlib: "open /etc/shadow: permission denied"
	// regexp-free check: detail contains both "open " and "permission denied"
	if strings.Contains(lower, "open ") && strings.Contains(lower, "permission denied") {
		return true
	}
	return false
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
		// Confidence-native expected deduction (design
		// CONFIDENCE_MODEL_DESIGN_2026-09-08 §2.1): scale the delta by the
		// observation confidence. Under the disabled policy every
		// confidence is 1.0 → identical to the legacy accumulation.
		conf := check.Confidence
		if conf <= 0 || conf > 1 {
			conf = 1.0
		}
		current := scores.Get(check.Domain)
		scores.Set(check.Domain, math.Max(0, current+delta*conf))
	}

	return scores
}

// legacyDefaultCustomFactors 返回 legacy 路径的内置边缘因子默认表。
//
// 六个条目（Factor 与 TriggerCheck）是改造前 assessor.go 内联字面量的**原样搬运**：
// Factor 数值（0.75/0.80/0.82/0.90/0.88）刻意保持字面量，不改成读 cfg.EdgeFactors.*
// —— 那会让 legacy 路径开始跟随 [edge_factors] 配置（行为变化，须独立决策）；
// EF-002FA 的权重沿用既有约定取自 [edge_factors] two_factor_failure。
//
// TriggerCheck 的值与 config.DefaultEdgeFactorTriggerMap 的对应条目一致（由不变式
// 测试锁定），但这里保留独立字面量而不是查表：该字段在 legacy 循环里不参与判定
// （判定用的是 config.ResolveEdgeFactorTriggerMap 派生的触发检查），它是这张默认表
// 的**内容**——P4「默认逐位一致」约束的正是这份内容。
func legacyDefaultCustomFactors(cfg *config.Config) map[string]config.CustomEdgeFactorConfig {
	return map[string]config.CustomEdgeFactorConfig{
		"EF-002FA":     {Factor: cfg.EdgeFactors.TwoFactorFailure, TriggerCheck: "EF-001"},
		"EF-SYNCOOKIE": {Factor: 0.75, TriggerCheck: "RS-005"},
		"EF-SELINUX":   {Factor: 0.80, TriggerCheck: "OT-005"},
		"EF-APPARMOR":  {Factor: 0.82, TriggerCheck: "OT-005"},
		"EF-NO-SIEM":   {Factor: 0.90, TriggerCheck: "RS-007"},
		"EF-NO-IDS":    {Factor: 0.88, TriggerCheck: "RS-006"},
	}
}

// legacyOverrideFactorIDs 是「由显式 trigger.<factor> 覆盖来激活」的因子集合：六个内置因子里
// 除去 EF-002FA（它和 EF-3FA 一起由循环里派生自解析表的两处内置分支处理）。集合外的键
// （EF-3FA 自身、以及 legacy 输出层没有槽位的自定义因子）不在这里激活，理由见各自注释。
var legacyOverrideFactorIDs = map[string]bool{
	"EF-SYNCOOKIE": true, "EF-SELINUX": true, "EF-APPARMOR": true,
	"EF-NO-SIEM": true, "EF-NO-IDS": true,
}

// legacyTriggerOverridesByCheck 把配置里显式的 trigger.<factor> 覆盖整理成
// 「检查 ID → 因子 ID 列表」，供 legacy 循环消费。
//
// 语义与 ssam 路径一致（同一个 config.ResolveEdgeFactorTriggerMap 入口）：
// trigger.<factor> = <check> 表示**该因子改由这个检查激活**。
//
// 值是列表而不是单个因子：默认表里 EF-SELINUX 与 EF-APPARMOR 就共用 OT-005，
// 操作员把两个因子的触发检查都配成同一个检查 ID 是合法且可预期的用法；若用
// map[string]string 就只能留下一个，另一个的覆盖会被静默丢弃 —— 那正是本方向要消除的
// 「配了但静默无效」。列表顺序固定（按因子 ID 字典序），不依赖 map 迭代序。
//
// 空值覆盖不参与（解析层已拒绝；此处是第二道防线，与 config 的解析规则一致）。
func legacyTriggerOverridesByCheck(cfg *config.Config) map[string][]string {
	if cfg == nil {
		return nil
	}
	overrides := make(map[string][]string)
	for factorID, check := range cfg.EdgeFactorModel.TriggerMap {
		if strings.TrimSpace(check) == "" || !legacyOverrideFactorIDs[factorID] {
			continue
		}
		overrides[check] = append(overrides[check], factorID)
	}
	for check := range overrides {
		sort.Strings(overrides[check])
	}
	return overrides
}

// legacyOverridePenalty 返回「覆盖激活」因子 factorID 时应使用的惩罚权重。
//
// 取值优先级与两处内置分支同形（先查 customFactors，再用出厂默认表的字面量兜底）：
//  1. customFactors[factorID] 按**原拼写**（default 分支与两处内置分支就是这么查的）；
//  2. legacyDefaultCustomFactors 的同一份字面量（本函数只为 legacyOverrideFactorIDs 里的
//     五个内置因子调用，默认表必然命中 ⇒ 覆盖激活不会因为配置里没有对应条目而静默失效）。
//
// 这里刻意**不**改读 [edge_factors] 的同名权重（cfg.EdgeFactors.SELinuxDisabled 等）：
// legacy 路径的权重来源是它自己的默认表字面量，把来源一并统一属行为变化，须独立决策
// （见 evaluateEdgeFactorChain 末段）。
func legacyOverridePenalty(cfg *config.Config, customFactors map[string]config.CustomEdgeFactorConfig, factorID string) (float64, bool) {
	if v, ok := customFactors[factorID]; ok && v.Factor > 0 && v.Factor < 1.0 {
		return v.Factor, true
	}
	if v, ok := legacyDefaultCustomFactors(cfg)[factorID]; ok && v.Factor > 0 && v.Factor < 1.0 {
		return v.Factor, true
	}
	return 0, false
}

// evaluateEdgeFactorChain 按失败检查项计算六个边缘因子（legacy 乘性路径）。
//
// 触发映射的单一来源是 internal/config（默认表 + 显式覆盖，见 ResolveEdgeFactorTriggerMap），
// 与 ssam 路径（adapter.ConfigToEdgeFactors）消费同一个解析函数 —— cmd/kernel/engine_on.go
// 同时装配两条路径，配置覆盖不允许只对一半生效。
//
// 默认零行为变化（P4，硬约束）决定了本函数**不能**把默认表整体接进来：改造前 legacy 只用
// case "EF-001" / case "EF-002" 两处内联字面量激活因子，其值恰好是默认表里 EF-002FA /
// EF-3FA 的触发检查；默认表其余四项（RS-005 / OT-005 / RS-007 / RS-006）在 legacy 上
// 从来没有生效过（default 分支是把 check ID 当因子 ID 查表，与触发映射无关），把它们接进来
// 会**新增**默认激活 ⇒ 改变既有评分。因此：
//   - 内置两项的触发检查改为从解析表派生（默认值与旧字面量逐字相同 ⇒ 逐位一致；
//     trigger.EF-002FA / trigger.EF-3FA 写了覆盖时随之替换）；
//   - 其余内置因子只消费**显式覆盖**（无覆盖 ⇒ 与改造前完全一致，一个都不多）；
//   - 自定义因子在 legacy 输出层没有槽位，覆盖它不产生激活（评分不变）。
//
// 权重字面量（0.75/0.80/…）原样保留，不随 [edge_factors] 配置变化：把 legacy 的权重来源
// 也统一起来会让本任务从「触发映射来源」变成「评分语义变化」，须独立决策。
func (a *Assessor) evaluateEdgeFactorChain(result *model.AssessmentResult) {
	localFactors := make(map[string]float64)
	for _, ef := range model.ListEdgeFactors() {
		localFactors[ef.ID] = 1.0
	}
	// localConf 记录**每个因子是被多大可信度的检查触发的**（与 localFactors 同一次写入、
	// 同一个来源），供输出层的观测链写 c_trigger（spec §5.1）。级联写入刻意不动它：
	// 级联值的来源是配置而非触发观测（design §2.4），若该因子自身触发检查未失败，
	// 它的可信度就是 0（"仅由级联激活"，与插件路径 TriggerConfidence=0 同形）。
	localConf := make(map[string]float64)

	customFactors := a.cfg.EdgeFactorsCustom
	if len(customFactors) == 0 {
		customFactors = legacyDefaultCustomFactors(a.cfg)
	}

	// 默认表 + 配置覆盖：EF-002FA / EF-3FA 两处内置分支的检查 ID 由它派生。
	triggers := config.ResolveEdgeFactorTriggerMap(a.cfg)
	// 其余内置因子的显式覆盖：检查 ID → 因子 ID。
	triggerOverrides := legacyTriggerOverridesByCheck(a.cfg)

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		// Confidence-aware trigger attenuation (design §2.4), matching the
		// plugin path ApplyEdgeFactorsToChecksPolicy: a low-confidence trigger
		// applies a milder penalty (effective = 1 − (1−factor)·c_trigger).
		conf := check.Confidence
		if conf <= 0 || conf > 1 {
			conf = 1.0
		}
		attenuate := func(f float64) float64 {
			if f <= 0 || f >= 1.0 {
				return f
			}
			return 1.0 - (1.0-f)*conf
		}
		// 内置两项（改造前是 case "EF-001" / case "EF-002" 两处字面量）：触发检查取自
		// 解析表，因此 trigger.EF-002FA / trigger.EF-3FA 的覆盖是**替换**语义（与 ssam 路径
		// 一致）。两值相同时 switch 只走第一支：这是刻意覆盖才能构造出的退化配置，
		// 默认表两个值不同，默认行为不受影响。
		switch check.CheckID {
		case triggers["EF-002FA"]:
			if v, ok := customFactors["EF-002FA"]; ok {
				localFactors["EF-002FA"] = attenuate(v.Factor)
			} else {
				localFactors["EF-002FA"] = attenuate(a.cfg.EdgeFactors.TwoFactorFailure)
			}
			localConf["EF-002FA"] = conf
		case triggers["EF-3FA"]:
			if v, ok := customFactors["EF-3FA"]; ok {
				localFactors["EF-3FA"] = attenuate(v.Factor)
			} else {
				localFactors["EF-3FA"] = attenuate(0.82)
			}
			localConf["EF-3FA"] = conf
			// EF-3FA cascades a FIXED config penalty onto EF-002FA; cascade
			// values are not confidence-attenuated (design §2.4 — their
			// provenance is the config, not this trigger observation).
			if v, ok := localFactors["EF-002FA"]; !ok || v > 0.82 {
				localFactors["EF-002FA"] = 0.82
			}
		}
		// legacy 既有 identity 分支（原 default 分支）：check ID 恰好是因子 ID 时按该因子的
		// 权重激活。改造前它被上面两个 case 的标签挡住，这里按派生后的标签保持同一形状
		// （默认标签即 EF-001 / EF-002，故默认行为逐位不变）。
		if check.CheckID != triggers["EF-002FA"] && check.CheckID != triggers["EF-3FA"] {
			if penalty, ok := customFactors[check.CheckID]; ok && penalty.Factor < 1.0 {
				localFactors[check.CheckID] = attenuate(penalty.Factor)
				localConf[check.CheckID] = conf
			}
		}
		// 显式触发覆盖（trigger.<factor> = <check>）：配置里明写的映射必须在 legacy 路径上
		// 生效，否则同一个配置只对 ssam 路径有效（本次改造要消除的问题）。
		//
		// 独立于上面的 switch 应用，而不是塞进 default 分支：一个检查 ID 同时是覆盖目标与
		// 内置分支标签时（例如把 trigger.EF-SYNCOOKIE 也指向 EF-001），塞进 default 会让
		// 该覆盖被 switch 静默吞掉。覆盖晚于 identity 写入，故显式配置优先。
		for _, factorID := range triggerOverrides[check.CheckID] {
			if penalty, ok := legacyOverridePenalty(a.cfg, customFactors, factorID); ok {
				localFactors[factorID] = attenuate(penalty)
				localConf[factorID] = conf
			}
		}
	}

	mapped := model.EdgeFactors{
		TwoFactorFailure:  1.0,
		SYNCookieDisabled: 1.0,
		SELinuxDisabled:   1.0,
		AppArmorDisabled:  1.0,
		NoSIEM:            1.0,
		NoIDS:             1.0,
	}
	// 溯源字段（Model / ParamsHash）在 **legacy 评分路径**上**刻意留零值**：
	// 本路径只消费 [edge_factors.model] 段的 trigger.*（ResolveEdgeFactorTriggerMap 与
	// legacyTriggerOverridesByCheck，见本函数上方），**不消费**该段的合成参数
	// （model / p_floor / vector / coupling / λ）—— 它不构造 edgefactor.Params，因此没有
	// 「本次评分用了哪个模型、哪套参数」可言。填一个模型名会把「这次评分走的是历史乘性路径」
	// 写成假事实。零值 + omitempty 同时保证历史输出逐位不变（裁定 1）。
	//
	// 注意区分两个都叫 legacy 的东西（Task 7 评审 I1 的表述口径）：
	//   - **本函数这条 legacy 评分路径**（DynamicScoringEngine）**永远**不盖戳；
	//   - `[edge_factors.model]` 里**显式写 `model = legacy`** 走的是另一条路 —— ssam 插件
	//     路径，引擎会装载这套参数并真的用它评分（总分乘子语义），因此输出
	//     `"model":"legacy"` + 指纹。那是「配置为 legacy」，与本函数的「未配置/不走新框架」
	//     语义不同，必须可区分（见 internal/engine/ssam/provenance_test.go）。
	// ssam 路径的盖戳判据见 adapter_engine.go：**引擎实际装载了什么**，而不是配置里写了什么。
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

	// 观测链（Task 1 / spec §5.1 的 observed.edge_factor_chain[]）：与上面的因子映射同源 ——
	// 只写**真的被乘进总分**的那批值，供 M0 基线记录与离线重算使用。
	result.EdgeFactorChain = legacyObservedFactorChain(mapped, triggers, localConf, time.Now())
}

// legacyObservedFactorChain 把 legacy 路径**实际乘进总分**的因子写成观测链（spec §5.1）。
//
// 三条口径（与插件路径 ssam.observeEdgeFactorChain 刻意保持同一套语义）：
//
//  1. 只写 mapped 里落在 (0,1) 的因子 —— 它们正是 computeDynamicFinalScore 会乘进
//     intrinsicCoeff 的那批值（model.EdgeFactors.ActiveFactors 的同一批），顺序也取同一顺序
//     （六字段序），使离线逐次相乘与在线的算术顺序逐位一致。内部因子表 localFactors 里
//     **没有输出槽位**的项不写：legacy 的 EF-3FA（只作级联入口，影响已体现在 EF-002FA 的
//     0.82 上）与自定义因子被记进 localFactors 却从未参与相乘，写进链会让离线重算凭空产生惩罚。
//  2. EffectiveFactor 写 legacy **实际乘上去的值**（attenuate 之后）；c_trigger 写该因子这次
//     触发观测的可信度。legacy 不消费合成参数，故不存在 spec §10.2 的第二次衰减；级联激活
//     且自身触发检查未失败时 c_trigger 为 0（与插件路径 TriggerConfidence=0 同形）。
//  3. TS 取**评分时刻**（本进程时间）：model.CheckResult 没有采集时间字段（与插件路径同口径）。
//
// TriggerCheck 用**解析后的**触发表查得（默认表 + trigger.* 覆盖，与两条评分路径共用的同一张
// 表）。注意它与"本轮是哪个检查触发了激活"不是一回事：legacy 还保留 identity 分支（检查 ID
// 恰好是因子 ID），此时链上的 trigger_check 仍是该因子登记在解析表里的检查 —— spec §5.1 要求
// 它"与该因子在当前部署实际解析出的触发检查一致"，而观测可信度由 c_trigger 承载。
func legacyObservedFactorChain(mapped model.EdgeFactors, triggers map[string]string, confs map[string]float64, at time.Time) []model.EdgeFactorObservation {
	fields := []struct {
		id    string
		value float64
	}{
		{"EF-002FA", mapped.TwoFactorFailure},
		{"EF-SYNCOOKIE", mapped.SYNCookieDisabled},
		{"EF-SELINUX", mapped.SELinuxDisabled},
		{"EF-APPARMOR", mapped.AppArmorDisabled},
		{"EF-NO-SIEM", mapped.NoSIEM},
		{"EF-NO-IDS", mapped.NoIDS},
	}
	ts := at.UTC().Format(time.RFC3339)
	chain := make([]model.EdgeFactorObservation, 0, len(fields))
	for _, f := range fields {
		if f.value <= 0 || f.value >= 1.0 {
			continue
		}
		chain = append(chain, model.EdgeFactorObservation{
			Factor:          f.id,
			TriggerCheck:    triggers[f.id],
			CTrigger:        confs[f.id],
			EffectiveFactor: f.value,
			TS:              ts,
		})
	}
	return chain
}

func (a *Assessor) applyATTACK(hostID string, result *model.AssessmentResult) {
	if a.attackProvider == nil {
		return
	}

	checkResults := make(map[string]bool)
	for _, c := range result.Checks {
		checkResults[c.CheckID] = c.Passed
	}

	coverages := a.attackProvider.CalculateCoverage(checkResults)
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

	killChain := a.attackProvider.AssessKillChain(hostID, checkResults)
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

	var failedTechIDs []string
	// Fetch tactics once and index by ID instead of copying the whole slice per coverage.
	allTactics := a.attackProvider.GetAllTactics()
	tacticByID := make(map[string]ATTACKTacticInfo, len(allTactics))
	for _, t := range allTactics {
		tacticByID[t.ID] = t
	}
	for _, cov := range coverages {
		if cov.CoverageDet >= 100 {
			continue
		}
		tactic, ok := tacticByID[cov.TacticID]
		if !ok {
			continue
		}
		for _, tech := range tactic.Techniques {
			if len(tech.AsscorChecks) == 0 {
				continue
			}
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

	if len(failedTechIDs) > 0 {
		aptMatches := a.attackProvider.MatchAPTGroup(failedTechIDs)
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

		predRisk := a.attackProvider.PredictRisk(hostID, failedTechIDs, 3)
		if predRisk.MaxRiskScore > 0 || predRisk.PredictedPaths > 0 {
			result.ATTACKPredictedRisk = &model.ATTACKPredictedRiskInfo{
				MaxRiskScore:    predRisk.MaxRiskScore,
				EnhancedThreat:  predRisk.EnhancedThreat,
				PredictedPaths:  predRisk.PredictedPaths,
				Recommendations: predRisk.Recommendations,
			}
		}
	}

	result.ATTACKFailedTechs = failedTechIDs

	logger.WithComponent("assessor").Info("ATT&CK analysis applied",
		"host_id", hostID,
		"coverage_tactics", len(coverages),
		"kill_chain_score", killChain.OverallScore,
		"apt_matches", len(result.ATTACKAPTMatches),
		"failed_techniques", len(failedTechIDs),
		"predicted_risk", result.ATTACKPredictedRisk != nil)
}

func (a *Assessor) tryPluginScore(ctx context.Context, result *model.AssessmentResult) bool {
	if a.pluginEngine == nil {
		return false
	}
	if err := a.pluginEngine.ComputeScore(ctx, result); err != nil {
		logger.WithComponent("assessor").Error("plugin engine compute failed, fallback to legacy",
			"engine", a.pluginEngine.Name(), "error", err)
		return false
	}
	return true
}

func (a *Assessor) runLegacyScoring(result *model.AssessmentResult) {
	a.resolveChecksConfidence(result)
	dynScores := a.computeDynamicDomainScores(result)
	for domain, score := range dynScores.GetAll() {
		result.DomainScores.Set(domain, score)
	}
	a.evaluateEdgeFactorChain(result)
	a.ensureDefaults(result)
	result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
	result.Acceptable = result.FinalScore >= result.Threshold
}

func (a *Assessor) computeDynamicFinalScore(scores *model.DynamicDomainScores, result *model.AssessmentResult) float64 {
	weightedSum := a.scoringEngine.ComputeWeightedSum(scores)

	intrinsicCoeff := weightedSum / 100.0
	activeFactors := result.EdgeFactors.ActiveFactors()
	for _, f := range activeFactors {
		intrinsicCoeff *= f
	}

	exposureCoeff := result.SPCScore
	if exposureCoeff < 0.60 {
		exposureCoeff = 0.60
	}

	threatCoeff := result.ThreatCoeff
	if threatCoeff < 0.60 {
		threatCoeff = 0.60
	}

	intrinsicWeight := 50.0
	exposureWeight := 30.0
	threatWeight := 20.0
	totalLayerWeight := intrinsicWeight + exposureWeight + threatWeight

	weightedAvg := (intrinsicCoeff*intrinsicWeight + exposureCoeff*exposureWeight + threatCoeff*threatWeight) / totalLayerWeight
	finalScore := math.Round(weightedAvg*100*100) / 100

	return finalScore
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
	efMap := map[string]float64{
		"EF-002FA":     result.EdgeFactors.TwoFactorFailure,
		"EF-SYNCOOKIE": result.EdgeFactors.SYNCookieDisabled,
		"EF-SELINUX":   result.EdgeFactors.SELinuxDisabled,
		"EF-APPARMOR":  result.EdgeFactors.AppArmorDisabled,
		"EF-NO-SIEM":   result.EdgeFactors.NoSIEM,
		"EF-NO-IDS":    result.EdgeFactors.NoIDS,
	}
	for _, ef := range model.ListEdgeFactors() {
		if val, ok := efMap[ef.ID]; ok && val > 0 && val < 1.0 {
			report += fmt.Sprintf("  %-12s : %-30s factor=%.2f (ACTIVE)\n", ef.ID, ef.Name, val)
		}
	}
	hasEF := false
	for _, val := range efMap {
		if val > 0 && val < 1.0 {
			hasEF = true
			break
		}
	}
	if !hasEF {
		report += fmt.Sprintf("  (no active edge factors)\n")
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

	if len(result.ATTACKCoverage) > 0 || result.ATTACKKillChain != nil || len(result.ATTACKAPTMatches) > 0 {
		report += fmt.Sprintf("\n[ ATT&CK Coverage Analysis ]\n")
		report += fmt.Sprintf("---------------------------------------------------------------\n")
		for _, cov := range result.ATTACKCoverage {
			report += fmt.Sprintf("  %-6s %-22s Det=%5.1f%% Prev=%5.1f%% Comp=%5.1f%% [%s]\n",
				cov.TacticID, cov.TacticName,
				cov.CoverageDet*100, cov.CoveragePrev*100, cov.CoverageComp*100,
				cov.RiskLevel)
		}

		if result.ATTACKKillChain != nil {
			report += fmt.Sprintf("\n[ Kill Chain Assessment ]\n")
			report += fmt.Sprintf("---------------------------------------------------------------\n")
			for _, stage := range result.ATTACKKillChain.Stages {
				report += fmt.Sprintf("  %-12s : %6.1f/100  [%s]  (%d/%d checks)\n",
					stage.Name, stage.Score, stage.Status,
					stage.ChecksPassed, stage.ChecksTotal)
			}
			report += fmt.Sprintf("  Overall: %.1f/100    Weakest: %s\n",
				result.ATTACKKillChain.OverallScore, result.ATTACKKillChain.WeakestStage)
		}

		if len(result.ATTACKAPTMatches) > 0 {
			report += fmt.Sprintf("\n[ APT Group Matches ]\n")
			report += fmt.Sprintf("---------------------------------------------------------------\n")
			for _, match := range result.ATTACKAPTMatches {
				report += fmt.Sprintf("  %s (%s)  similarity=%.2f  confidence=%s  overlap=%v\n",
					match.GroupName, match.GroupID, match.Similarity, match.Confidence, match.OverlapTech)
			}
		}

		if result.ATTACKPredictedRisk != nil {
			report += fmt.Sprintf("\n[ Predictive Risk ]\n")
			report += fmt.Sprintf("---------------------------------------------------------------\n")
			report += fmt.Sprintf("  Max Risk Score: %.2f    Enhanced Threat: %.2f    Predicted Paths: %d\n",
				result.ATTACKPredictedRisk.MaxRiskScore,
				result.ATTACKPredictedRisk.EnhancedThreat,
				result.ATTACKPredictedRisk.PredictedPaths)
			if len(result.ATTACKPredictedRisk.Recommendations) > 0 {
				report += fmt.Sprintf("  Recommendations:\n")
				for _, rec := range result.ATTACKPredictedRisk.Recommendations {
					report += fmt.Sprintf("    - %s\n", rec)
				}
			}
		}

		if len(result.ATTACKFailedTechs) > 0 {
			report += fmt.Sprintf("\n  Failed Techniques: %v\n", result.ATTACKFailedTechs)
		}
		report += fmt.Sprintf("---------------------------------------------------------------\n")
	}

	if result.PrismScore > 0 {
		report += fmt.Sprintf("\n[ Prism Risk Dynamics ]\n")
		report += fmt.Sprintf("---------------------------------------------------------------\n")
		report += fmt.Sprintf("  Prism Score: %.2f/100    External Risk: %.4f    Risk Velocity: %+.2f\n",
			result.PrismScore, result.PrismExternalRisk, result.PrismRiskVelocity)
		report += fmt.Sprintf("  Propagated Risk: %.4f    Prop Penalty: %.4f    Debt Penalty: %.4f\n",
			result.PrismPropRisk, result.PrismPropPenalty, result.PrismDebtPenalty)

		if result.PrismSemanticState != "" {
			report += fmt.Sprintf("\n  [ Semantic State ]\n")
			report += fmt.Sprintf("    Dominant: %s  |  S=%.2f  D=%.2f  U=%.2f  C=%.2f\n",
				result.PrismSemanticState,
				result.PrismStableMem, result.PrismDegradedMem,
				result.PrismUntrustedMem, result.PrismCollapseMem)
		}

		if result.PrismInferenceTrend != "" {
			report += fmt.Sprintf("\n  [ Inference (%dd) ]\n", result.PrismInferenceHorizonDays)
			report += fmt.Sprintf("    Trend: %s  |  Confidence: %.2f  |  Collapse Risk: %.2f\n",
				result.PrismInferenceTrend, result.PrismInferenceConfidence,
				result.PrismInferenceCollapseRisk)
			report += fmt.Sprintf("    Future: S=%.2f  D=%.2f  U=%.2f  C=%.2f\n",
				result.PrismInferenceFutureVector[0],
				result.PrismInferenceFutureVector[1],
				result.PrismInferenceFutureVector[2],
				result.PrismInferenceFutureVector[3])
		}
		report += fmt.Sprintf("---------------------------------------------------------------\n")
	}

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

	a.cfg = cfg

	w := cfg.Weights
	a.scoringEngine.SetWeight(model.DomainAttackSurface, w.AttackSurface)
	a.scoringEngine.SetWeight(model.DomainBusinessContinuity, w.BusinessContinuity)
	a.scoringEngine.SetWeight(model.DomainOperationTrust, w.OperationTrust)
	a.scoringEngine.SetWeight(model.DomainResilience, w.Resilience)

	for domain, val := range cfg.ExtensionWeights {
		a.scoringEngine.SetWeight(domain, val)
	}

	if a.pluginEngine != nil {
		a.pluginEngine.ReloadWeights(cfg)
	}

	logger.WithComponent("assessor").Info("weights reloaded from config")
}

func (a *Assessor) RegisterHook(id string, phase AssessmentPhase, hook AssessmentHook, priority int) {
	a.scoringEngine.Hooks().Register(id, phase, hook, priority)
}

func (a *Assessor) UnregisterHook(id string) {
	a.scoringEngine.Hooks().Unregister(id)
}

func (a *Assessor) RecomputeFinalScore(result *model.AssessmentResult) float64 {
	if result.SPCScore == 0 {
		result.SPCScore = 1.0
	}
	if result.ThreatCoeff == 0 {
		result.ThreatCoeff = 1.0
	}

	if a.pluginEngine != nil {
		if err := a.pluginEngine.ComputeScore(context.Background(), result); err != nil {
			logger.WithComponent("assessor").Error("plugin engine recompute failed, fallback to legacy",
				"engine", a.pluginEngine.Name(), "error", err)
		} else {
			return result.FinalScore
		}
	}

	// Legacy path: resolve per-check confidences before the expected
	// deduction so confidence-aware scoring works identically here and in the
	// plugin engine.
	a.resolveChecksConfidence(result)
	dynScores := model.NewDynamicDomainScores()
	dynScores.FillFromLegacy(result.DomainScores)
	result.FinalScore = a.computeDynamicFinalScore(dynScores, result)
	result.Acceptable = result.FinalScore >= result.Threshold
	return result.FinalScore
}

// resolveChecksConfidence applies the [confidence] rule table to the result's
// checks (no-op when disabled or plugin engine already resolved them).
func (a *Assessor) resolveChecksConfidence(result *model.AssessmentResult) {
	if a.cfg == nil || result == nil {
		return
	}
	a.cfg.ResolveChecks(result.Checks)
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
