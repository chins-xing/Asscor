//go:build engine

package ssam

import (
	"context"
	"math"
	"sort"
	"sync"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
	"github.com/chins-xing/asscor/internal/logger"
	ssam "github.com/chins-xing/ssam"
)

type Engine struct {
	mu             sync.RWMutex
	cfg            ssam.ScoringConfig
	customFormulas map[string]ssam.ScoringFormula
	hooks          map[HookPhase][]hookEntry

	// 边缘因子合成模型（Task 7）：按配置**实际装载**的参数与其装载状态。
	// 这是溯源（model.EdgeFactors.Model / ParamsHash）的唯一判据 —— 不是"配置里写了
	// 什么"，而是"引擎真的装载了哪套参数"。零值 + edgeFactorLoaded=false 表示未装载
	// （未配置 [edge_factors.model]、参数不可用，或已热重载为未启用）。
	edgeFactorParams edgefactor.Params
	edgeFactorLoaded bool
}

type hookEntry struct {
	id       string
	hook     AssessmentHook
	priority int
}

var _ Provider = (*Engine)(nil)

func NewEngine() *Engine {
	return &Engine{
		cfg:            ssam.DefaultScoringConfig,
		customFormulas: make(map[string]ssam.ScoringFormula),
		hooks:          make(map[HookPhase][]hookEntry),
	}
}

func NewDefaultEngine() *Engine {
	return NewEngine()
}

func (e *Engine) ComputeScore(ctx context.Context, input *ssam.AssessmentInput) (*ssam.AssessmentOutput, error) {
	if input == nil {
		return nil, ErrNilInput
	}

	if err := ValidateInput(*input); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	output := &ssam.AssessmentOutput{
		HostID:      input.HostID,
		Threshold:   input.Threshold,
		ThreatCoeff: input.ThreatCoeff,
		SPCScore:    input.SPCScore,
		Metadata:    make(map[string]string),
	}

	if output.ThreatCoeff == 0 {
		output.ThreatCoeff = 1.0
	}
	if output.SPCScore == 0 {
		output.SPCScore = 1.0
	}
	if output.SPCScore < 0.60 {
		output.SPCScore = 0.60
	}

	e.ExecuteHooks(ctx, HookPreScore, input, output)

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	// Confidence-native domain scoring (design CONFIDENCE_MODEL_DESIGN_2026-09-08):
	// with the default disabled policy this is numerically identical to the
	// legacy ComputeDomainScores.
	domainScores := ssam.ComputeDomainScoresBayes(cfg.Weights, input.Checks, cfg.ConfidencePolicy)
	output.DomainScores = domainScores

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostScore, input, output)

	e.ExecuteHooks(ctx, HookPreEdge, input, output)

	customFactors := e.buildCustomFactorMap()
	edgeFactors := ssam.ApplyEdgeFactorsToChecksPolicy(cfg.EdgeFactors, input.Checks, customFactors, cfg.ConfidencePolicy)
	output.EdgeFactors = edgeFactors

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.ExecuteHooks(ctx, HookPostEdge, input, output)

	// SSAM V2.0 three-layer weighted average is the authoritative formula.
	// Custom formulas registered via RegisterFormula take precedence when their ID is selected.
	var finalScore float64
	customFormulas := e.getCustomFormulas()
	if custom, ok := customFormulas[cfg.FormulaID]; ok && custom != nil {
		finalScore = custom(domainScores, cfg.Weights, output.ThreatCoeff, output.SPCScore, edgeFactors)
	} else {
		riskCtx := ssam.RiskContext{
			Intrinsic: 0,
			Exposure:  output.SPCScore,
			Threat:    output.ThreatCoeff,
		}
		v2Result := ssam.SSAMV20Formula(domainScores, cfg.Weights, riskCtx, edgeFactors)
		finalScore = v2Result.Total
	}
	output.FinalScore = math.Round(finalScore*100) / 100
	output.FormulaID = cfg.FormulaID
	output.Acceptable = output.FinalScore >= output.Threshold

	// Posterior statistics (model-native; degenerate [score,score] and
	// evidence confidence 1.0 under the disabled policy). The interval is
	// centered on the actual final score.
	sigma, _, _ := ssam.FinalBayesStats(cfg.Weights, domainScores)
	output.FinalSigma = sigma
	output.Lower95 = math.Max(0, math.Min(100, output.FinalScore-1.96*sigma))
	output.Upper95 = math.Max(0, math.Min(100, output.FinalScore+1.96*sigma))
	output.EvidenceConfidence = ssam.AggregateNodeConfidence(cfg.Weights, domainScores)

	return output, nil
}

func (e *Engine) custom42Formula(domainScores []ssam.DomainScore, weights []ssam.WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []ssam.EdgeFactorResult) float64 {
	return 42.0
}

func (e *Engine) ComputeScoreV2(ctx context.Context, input *ssam.AssessmentInputV2) (*ssam.AssessmentOutputV2, error) {
	if input == nil {
		return nil, ErrNilInput
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	output, err := ssam.ComputeScoreV2(cfg, *input)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

func (e *Engine) getCustomFormulas() map[string]ssam.ScoringFormula {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]ssam.ScoringFormula, len(e.customFormulas))
	for k, v := range e.customFormulas {
		result[k] = v
	}
	return result
}

func (e *Engine) ComputeDomainScores(checks []ssam.CheckInput) []ssam.DomainScore {
	e.mu.RLock()
	weights := e.cfg.Weights
	e.mu.RUnlock()
	return ssam.ComputeDomainScores(weights, checks)
}

func (e *Engine) ComputeWeightedSum(domainScores []ssam.DomainScore) float64 {
	e.mu.RLock()
	weights := e.cfg.Weights
	e.mu.RUnlock()
	return ssam.ComputeWeightedSum(weights, domainScores)
}

func (e *Engine) ApplyEdgeFactors(baseScore float64, factors []ssam.EdgeFactorResult) float64 {
	return ssam.ApplyEdgeFactors(baseScore, factors)
}

func (e *Engine) ApplyEdgeFactorsToChecks(checks []ssam.CheckInput, customFactors map[string]float64) []ssam.EdgeFactorResult {
	e.mu.RLock()
	edgeFactors := e.cfg.EdgeFactors
	e.mu.RUnlock()
	return ssam.ApplyEdgeFactorsToChecks(edgeFactors, checks, customFactors)
}

func (e *Engine) ListEdgeFactors() []ssam.EdgeFactorResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]ssam.EdgeFactorResult, 0, len(e.cfg.EdgeFactors))
	for _, cfg := range e.cfg.EdgeFactors {
		results = append(results, ssam.EdgeFactorResult{
			ID:     cfg.ID,
			Name:   cfg.Name,
			Factor: cfg.Factor,
			Active: false,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

func (e *Engine) EvaluateEdgeFactors(checks []ssam.CheckInput, customFactors map[string]float64) []ssam.EdgeFactorResult {
	return e.ApplyEdgeFactorsToChecks(checks, customFactors)
}

func (e *Engine) SetWeights(weights []WeightConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Weights = append([]WeightConfig{}, weights...)
}

func (e *Engine) GetWeights() []WeightConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]WeightConfig, len(e.cfg.Weights))
	copy(result, e.cfg.Weights)
	return result
}

func (e *Engine) SetFormula(formulaID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.FormulaID = formulaID
}

func (e *Engine) GetFormula() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.FormulaID
}

func (e *Engine) RegisterFormula(id string, formula ssam.ScoringFormula) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customFormulas[id] = formula
	e.cfg.FormulaID = id
}

func (e *Engine) SetEdgeFactors(factors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.EdgeFactors = append([]EdgeFactorConfig{}, factors...)
}

// SetConfidencePolicy installs the kernel's confidence policy. The default
// (disabled) policy keeps scoring identical to the legacy engine.
func (e *Engine) SetConfidencePolicy(policy ConfidencePolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.ConfidencePolicy = policy
}

// GetConfidencePolicy returns the active confidence policy.
func (e *Engine) GetConfidencePolicy() ConfidencePolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.ConfidencePolicy
}

func (e *Engine) ListDomains() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domains := make([]string, 0, len(e.cfg.Weights))
	for _, w := range e.cfg.Weights {
		domains = append(domains, w.Domain)
	}
	sort.Strings(domains)
	return domains
}

func (e *Engine) GetDomainLabel(id string) string {
	return id
}

func (e *Engine) GetDefaultWeight(id string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, w := range e.cfg.Weights {
		if w.Domain == id {
			return w.Weight
		}
	}
	return 0
}

func (e *Engine) RegisterHook(phase HookPhase, id string, hook AssessmentHook, priority int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks[phase] = append(e.hooks[phase], hookEntry{id: id, hook: hook, priority: priority})
	sort.Slice(e.hooks[phase], func(i, j int) bool {
		return e.hooks[phase][i].priority < e.hooks[phase][j].priority
	})
}

func (e *Engine) UnregisterHook(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for phase, hooks := range e.hooks {
		filtered := hooks[:0]
		for _, h := range hooks {
			if h.id != id {
				filtered = append(filtered, h)
			}
		}
		if len(filtered) == 0 {
			delete(e.hooks, phase)
		} else {
			e.hooks[phase] = filtered
		}
	}
}

func (e *Engine) ExecuteHooks(ctx context.Context, phase HookPhase, input *ssam.AssessmentInput, output *ssam.AssessmentOutput) []error {
	e.mu.RLock()
	hooks := make([]hookEntry, len(e.hooks[phase]))
	copy(hooks, e.hooks[phase])
	e.mu.RUnlock()

	var errs []error
	for _, h := range hooks {
		if err := h.hook(ctx, input, output); err != nil {
			logger.WithComponent("ssam").Warn("hook error", "hook_id", h.id, "phase", phase, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

func (e *Engine) buildCustomFactorMap() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]float64)
	for _, f := range e.cfg.EdgeFactors {
		result[f.ID] = f.Factor
	}
	return result
}

func (e *Engine) InitializeDefaults(defaultWeights map[string]float64, defaultFactors []EdgeFactorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.cfg.Weights) == 0 && len(defaultWeights) > 0 {
		e.cfg.Weights = make([]WeightConfig, 0, len(defaultWeights))
		for k, v := range defaultWeights {
			e.cfg.Weights = append(e.cfg.Weights, WeightConfig{Domain: k, Weight: v})
		}
	}

	if len(e.cfg.EdgeFactors) == 0 && len(defaultFactors) > 0 {
		e.cfg.EdgeFactors = append([]EdgeFactorConfig{}, defaultFactors...)
	}
}

// ---------------------------------------------------------------------------
// 边缘因子合成模型装配（Task 7：把内仓钩子接到生产评分链上）
// ---------------------------------------------------------------------------

// resetEdgeFactorHooks 把内仓的两个钩子恢复成默认（nil == 未注册 ⇒ 逐位一致的历史乘性路径）。
//
// 绝不能用「注册一个语义等价的默认策略」来代替它：内仓 ast.go 的
// edgeFactorStrategyIsDefault 标记决定 applyEdgeFactorStrategyToBase 走「逐次相乘」还是
// 「base×单次乘积」，显式注册等价策略会换掉默认算术顺序，在取整半格边界上产生可观测差异。
func resetEdgeFactorHooks() {
	ssam.RegisterEdgeFactorStrategy(nil)
	ssam.RegisterDomainAdjust(nil)
}

// ApplyEdgeFactorModel 按配置装配边缘因子合成模型：注册合成策略与域级修正两个钩子。
//
// 语义（逐条对应 Task 7 的验收条件）：
//
//   - **未启用**（无 [edge_factors.model] 段，或 cfg == nil）：**零注册** —— 两个钩子
//     恢复成内仓默认，既不安装策略也不安装域级修正，也不安装任何"等价默认策略"。
//   - **启用**：安装两个钩子，它们都在生产公式 SSAMV20Formula 的统一入口上生效（不是
//     AST 入口）：
//     1. RegisterEdgeFactorStrategy —— 总分乘子语义：legacy/M0 返回
//     Result.GlobalMultiplier（∏ effective_f）；V/G/C 恒为 1，用来**抵消**内仓默认的
//     逐次相乘路径（它们的惩罚完全由域级系数 P_d 表达，不能再乘一次）。
//     2. RegisterDomainAdjust —— V/G/C 的域级修正 Score_d' = Base_d · P_d；
//     legacy 注册 nil（域级修正不参与）。
//   - **参数不可用或无法产生任何修正**（ParamsFromConfig / newSynthesizePlan 报错）：
//     清空装载状态、恢复默认路径并返回错误 —— 宁可回落默认乘性路径，也不带着半套参数
//     评分，更不在输出里声称用了某个模型（那正是 Task 5 评审 I1 要消除的假溯源）。
//
// 钩子是**进程级全局状态**（内仓设计如此），所以每次装配都是"全量替换"，且闭包用**值捕获**
// 带上它被装配时的那套参数：热重载后旧闭包不会读到新参数，戳记（引擎装载的参数）与实际
// 计算所用的参数永远同源。
func (e *Engine) ApplyEdgeFactorModel(cfg *config.Config) error {
	if cfg == nil {
		// nil 配置 = 未配置任何模型段（不是"坏配置"），按未启用处理。
		e.clearEdgeFactorModel()
		resetEdgeFactorHooks()
		return nil
	}

	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil {
		e.clearEdgeFactorModel()
		resetEdgeFactorHooks()
		return err
	}
	if !enabled {
		e.clearEdgeFactorModel()
		resetEdgeFactorHooks()
		return nil
	}

	plan, err := newSynthesizePlan(p)
	if err != nil {
		e.clearEdgeFactorModel()
		resetEdgeFactorHooks()
		return err
	}
	e.storeEdgeFactorModel(p)

	ssam.RegisterEdgeFactorStrategy(func(factors []EdgeFactorResult) float64 {
		res, err := synthesizeWithModel(plan, factors)
		if err != nil {
			// 保守：合成失败不额外惩罚（乘子 1 = 恒等），绝不让评分 panic。
			// 装配期已排除本文档化的失败形态（λ 覆盖、向量覆盖、f∈(0,1]），
			// 这里是兜底而不是常规路径。
			return 1
		}
		return res.GlobalMultiplier // V/G/C 恒为 1；legacy 是 ∏ effective_f
	})

	if p.Model == edgefactor.ModelLegacy {
		// legacy 的惩罚完全由总分乘子表达，域级修正保持未注册（恒等）。
		ssam.RegisterDomainAdjust(nil)
		return nil
	}

	ssam.RegisterDomainAdjust(func(scores []DomainScore, factors []EdgeFactorResult) []DomainScore {
		res, err := synthesizeWithModel(plan, factors)
		if err != nil {
			return scores // 恒等：宁可不动域分，也不静默改分
		}
		for i := range scores {
			pd, ok := res.P[scores[i].Domain]
			if !ok {
				// 未配置 λ 的域不参与修正（合成计划已保证至少有一个域参与）。
				continue
			}
			scores[i].Score *= pd
		}
		return scores
	})
	return nil
}

// LoadedEdgeFactorParams 返回引擎**实际装载**的边缘因子参数（Task 5/7 的溯源判据）。
//
// ok=false 表示未装载：未配置 [edge_factors.model] 段、参数不可用，或已热重载为未启用。
// 调用方必须据此留零值 —— **不得**改用"配置里写了模型段"来判断是否盖戳：该配置段里的
// trigger.* 独立于合成模型就生效，所以"配置可解析出参数"不等于"评分用了这套参数"。
func (e *Engine) LoadedEdgeFactorParams() (edgefactor.Params, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.edgeFactorLoaded {
		return edgefactor.Params{}, false
	}
	return e.edgeFactorParams, true
}

// storeEdgeFactorModel 记录**已装载**的参数集（load 状态与参数同时更新，读侧永远看到一致的一对）。
func (e *Engine) storeEdgeFactorModel(p edgefactor.Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.edgeFactorParams = p
	e.edgeFactorLoaded = true
}

// clearEdgeFactorModel 清空装载状态：零值 + loaded=false。任何"未装载"的路径（未启用、
// 参数不可用、装配失败、热重载回未启用）都必须走这里，否则会留下上一个模型的参数
// —— 那会让溯源戳记与新配置不同源。
func (e *Engine) clearEdgeFactorModel() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.edgeFactorParams = edgefactor.Params{}
	e.edgeFactorLoaded = false
}
