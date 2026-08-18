package defensecycle

import (
	"math"

	"github.com/asscor/asscor/internal/attackerstate"
	"github.com/asscor/asscor/internal/engagement"
	"github.com/asscor/asscor/internal/predictor"
)

// 自适应攻防闭环 — 主动防御白皮书 Phase 5（§5.1 攻击者认知闭环 + §5.8
// 决策锐度驱动的策略）
//
// 闭环（§5.1）：
//
//	观测 → 状态估计 → 行为预测 → 引导/欺骗 → 攻击者响应
//	    → 新情报 → 状态更新 → 再次预测
//
// 本组件编排已有引擎（State/Prediction/Engagement）为可运行的闭环控制器：
//   - Step：单轮闭环（OldState + Observations → NewState → ActionDistribution
//     → 决策锐度 → 策略 → 干预选择）；
//   - 决策锐度（§5.8）：预测分布的归一化熵 → [0,1]，低锐度收集情报、
//     高锐度主动引导；
//   - 防御性回退（Defensive Fallback）：意图未知或存在未知 TTP 时进入
//     contain（临时网络隔离/进程挂起，直到新证据到达），保证最差情况下
//     依然安全；
//   - 干预部署后的观测由外部注入（DeceptionRecord → Evidence），驱动下一轮
//     状态更新（诱饵传感器化，§5.6）。
//
// 原则（§3.5/§1.2）：闭环是可解释的规则编排，不宣称"预测准确"或"欺骗
// 必然成功"——每次决策保留状态/分布/锐度/策略轨迹。

// CycleStrategy 是决策锐度驱动的防御策略（§5.8 + Defensive Fallback）。
type CycleStrategy string

const (
	StrategyContain CycleStrategy = "contain" // 意图未知/存在未知 TTP: 临时隔离, 等新证据
	StrategyCollect CycleStrategy = "collect" // 锐度低: 优先收集情报 (高 IG 干预)
	StrategyEngage  CycleStrategy = "engage"  // 锐度高: 允许主动引导 (按效用全选)
)

// Controller 是攻击者认知闭环控制器。
type Controller struct {
	StateEngine        *attackerstate.Engine
	Predictor          *predictor.Engine
	Planner            *engagement.Planner
	SharpnessThreshold float64 // §5.8: 低于此值 → collect, 否则 engage
}

// NewController wires the three engines into a closed loop.
func NewController(se *attackerstate.Engine, pr *predictor.Engine, pl *engagement.Planner) *Controller {
	return &Controller{
		StateEngine:        se,
		Predictor:          pr,
		Planner:            pl,
		SharpnessThreshold: 0.3,
	}
}

// CycleResult 是单轮闭环输出。
type CycleResult struct {
	State         attackerstate.AttackerState
	Distribution  predictor.ActionDistribution
	Sharpness     float64
	Strategy      CycleStrategy
	Interventions []engagement.ScoredIntervention
}

// Step 执行一轮闭环：OldState + Observations → NewState → Prediction →
// Sharpness → Strategy → Engagement（§5.1 + §5.8 + Defensive Fallback）。
func (c *Controller) Step(state attackerstate.AttackerState, observations []attackerstate.Evidence, target predictor.TargetState) CycleResult {
	// 1. 状态更新（§5.4）。
	newState := c.StateEngine.Update(state, observations)

	// 2. 行为预测（§4）。
	dist := c.Predictor.Predict(newState, target)

	// 3. 决策锐度（§5.8：归一化熵）。
	sharp := DistributionSharpness(dist)

	// 4. 策略选择（含防御性回退：意图未知或存在未知 TTP → contain）。
	strategy := c.strategyFor(sharp, newState, observations)

	// 5. 干预选择（§5.5）。
	scored := c.Planner.Select(dist, target)
	interventions := c.applyStrategy(scored, strategy)

	return CycleResult{
		State:         newState,
		Distribution:  dist,
		Sharpness:     sharp,
		Strategy:      strategy,
		Interventions: interventions,
	}
}

// DistributionSharpness computes decision sharpness from distribution
// entropy (normalized to [0,1]): sharp distributions (low entropy) have high
// sharpness; flat distributions (high entropy) have low sharpness.
// NOTE: this metric is a heuristic for action-distribution peakedness, not a
// probabilistic guarantee of correctness.
func DistributionSharpness(dist predictor.ActionDistribution) float64 {
	n := len(dist.Probabilities)
	if n <= 1 {
		return 1.0
	}
	entropy := 0.0
	for _, p := range dist.Probabilities {
		if p > 0 {
			entropy -= p * math.Log(p)
		}
	}
	maxEntropy := math.Log(float64(n))
	if maxEntropy <= 0 {
		return 1.0
	}
	return math.Max(0, math.Min(1, 1.0-entropy/maxEntropy))
}

// strategyFor applies the Defensive Fallback + §5.8 threshold:
//   - contain: intent is unknown OR any observed TTP is unmapped (unknown);
//   - collect: sharpness below threshold (flat distribution: gather intel);
//   - engage:  sharpness at/above threshold (active guidance).
func (c *Controller) strategyFor(sharp float64, state attackerstate.AttackerState, observations []attackerstate.Evidence) CycleStrategy {
	if state.Intent == attackerstate.IntentUnknown || hasUnknownTTP(observations) {
		return StrategyContain
	}
	if sharp < c.SharpnessThreshold {
		return StrategyCollect
	}
	return StrategyEngage
}

// hasUnknownTTP reports whether any observation carries a TTP that cannot be
// mapped to a known intent and has no explicit intent override.
func hasUnknownTTP(observations []attackerstate.Evidence) bool {
	for _, ev := range observations {
		if ev.TTP != "" && ev.Intent != attackerstate.IntentUnknown && ev.Intent != "" {
			continue // explicit intent overrides TTP inference
		}
		if ev.TTP != "" && attackerstate.IntentFromTTP(ev.TTP) == attackerstate.IntentUnknown {
			return true
		}
	}
	return false
}

// applyStrategy filters interventions per strategy:
//   - contain: deploy nothing (temporary isolation, wait for new evidence);
//   - collect: keep only the highest-IG intervention (情报收集);
//   - engage: keep all interventions with positive utility (主动引导).
func (c *Controller) applyStrategy(scored []engagement.ScoredIntervention, strategy CycleStrategy) []engagement.ScoredIntervention {
	switch strategy {
	case StrategyContain:
		// 临时隔离/挂起：不部署诱饵，直到新证据到达。
		return nil
	case StrategyCollect:
		if len(scored) == 0 {
			return nil
		}
		// 收集情报: 选 IG 最高的干预。
		best := scored[0]
		for _, s := range scored {
			if s.IG > best.IG {
				best = s
			}
		}
		return []engagement.ScoredIntervention{best}
	default: // engage
		return scored
	}
}
