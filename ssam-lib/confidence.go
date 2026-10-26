package ssam

import (
	"math"
	"sort"
)

// 置信度聚合算法（[confidence] algorithm）。
//
// weighted_evidence（缺省）：直接以 `c` 作为证据权重 —— E = Σ|δ|·c、U = Σ|δ|²·c·(1−c)。
// beta_bayes：把每条观测的可信度视为对"该扣分成立"这一伯努利事件的**分数次观测**，
// 先验取 κ 个"完全可信"的伪观测（κ = PriorStrength），后验均值
//
//	c̃ = (κ·1 + c) / (κ + 1) = 1 − (1−c)/(κ+1)
//
// 再以 c̃ 代入同一组 E/U 公式。两条不变量：
//   - c = 1 ⇒ c̃ = 1（**完全可信的观测不受先验影响**，与 legacy 逐位一致）；
//   - κ → 0 ⇒ c̃ → c（weighted_evidence 是 beta_bayes 的退化情形）。
//
// 方向要说清：先验是"κ 个完全可信的伪观测"，所以收缩只会把低可信观测**往 1 抬**
// ⇒ 期望扣分 E 变大（**多扣分、分数更低**）、方差 U 变小（区间更窄）；对 c=1 的观测无影响。
// 它不会压低高可信观测，也不会把任何观测推到 1 以上。
const (
	// AlgorithmWeightedEvidence 是缺省聚合（历史口径）。
	AlgorithmWeightedEvidence = "weighted_evidence"
	// AlgorithmBetaBayes 见上方公式；κ 由 ConfidencePolicy.PriorStrength 给出。
	AlgorithmBetaBayes = "beta_bayes"
)

// ConfidencePolicy controls how per-check intelligence confidence is treated
// by the scoring formulas. It is the library-side default used when no policy
// is supplied; the kernel injects its config-derived policy via
// ScoringConfig.ConfidencePolicy.
//
// Design doc: CONFIDENCE_MODEL_DESIGN_2026-09-08 (贝叶斯观测模型).
// A zero/unspecified per-check confidence (CheckInput.Confidence == 0) is
// normalized to Default; an explicit value is clamped to [Floor, 1].
// With the default policy (Enabled=false) every check is treated as fully
// confident (confidence=1) and all formulas reduce EXACTLY to the legacy
// behavior — the backward-compatibility guarantee.
type ConfidencePolicy struct {
	// Enabled turns confidence-aware scoring on. When false, all checks are
	// treated as confidence 1.0 and every formula is bit-identical to the
	// legacy implementation.
	Enabled bool
	// Default is the confidence assigned to a check whose Confidence field
	// is 0 (unspecified). Must be in (0,1]; 0 means fall back to 1.0.
	Default float64
	// Floor is the minimum accepted confidence. Values below floor are
	// clamped up, so a check can never be treated as a fully random
	// observation (which would make variance maximal and the point estimate
	// meaningless). Must be in (0,1).
	Floor float64
	// PriorStrength 是 beta_bayes 的先验强度（κ，等价伪观测数）；weighted_evidence 忽略它。
	// 0 表示未设置 ⇒ 由 EffectiveConfidence 取 2.0（与配置出厂值一致）。
	PriorStrength float64
	// Algorithm 选择聚合算法："" 与 AlgorithmWeightedEvidence 等价（历史口径），
	// AlgorithmBetaBayes 走 Beta 收缩（见文件头常量注释）。
	Algorithm string
}

// DefaultConfidencePolicy returns the identity policy: confidence-aware
// scoring disabled, so legacy behavior is preserved exactly.
func DefaultConfidencePolicy() ConfidencePolicy {
	return ConfidencePolicy{
		Enabled:       false,
		Default:       1.0,
		Floor:         0.05,
		PriorStrength: 2.0,
	}
}

// IsBetaBayes reports whether the policy selects the beta_bayes aggregation.
func (p ConfidencePolicy) IsBetaBayes() bool { return p.Algorithm == AlgorithmBetaBayes }

// BetaShrinkConfidence 是 beta_bayes 的收缩公式（导出以便测试与文档引用）：
//
//	c̃ = (κ + c) / (κ + 1)
//
// κ ≤ 0 ⇒ 原样返回 c（退化为 weighted_evidence）；κ 越大，低可信观测被拉得越靠近 1。
func BetaShrinkConfidence(c, priorStrength float64) float64 {
	if priorStrength <= 0 {
		return c
	}
	return (priorStrength + c) / (priorStrength + 1)
}

// EffectiveConfidence 是**引擎实际消费**的可信度：先按 NormalizeConfidence 归一
// （0 ⇒ Default、floor 夹取、≤1），再在 algorithm=beta_bayes 时做 Beta 收缩。
//
// 两条路径（插件 / legacy）与边因子触发衰减都必须用它，否则同一份配置在不同
// 消费点会得到不同权重。`NormalizeConfidence` 保留为纯归一化原语（不改语义）。
func EffectiveConfidence(raw float64, policy ConfidencePolicy) float64 {
	c := NormalizeConfidence(raw, policy)
	if !policy.Enabled || !policy.IsBetaBayes() {
		return c
	}
	k := policy.PriorStrength
	if k <= 0 {
		k = 2.0 // 与配置出厂值一致：写了 beta_bayes 但没给 prior_strength 时用 2.0
	}
	return BetaShrinkConfidence(c, k)
}

// NormalizeConfidence maps a raw per-check confidence into the policy's
// effective range. 0 (unspecified) becomes Default; anything below Floor is
// clamped up; anything above 1 is clamped down. A disabled policy always
// yields 1.0.
func NormalizeConfidence(raw float64, policy ConfidencePolicy) float64 {
	if !policy.Enabled {
		return 1.0
	}
	d := policy.Default
	if d <= 0 || d > 1 {
		d = 1.0
	}
	f := policy.Floor
	if f <= 0 || f >= 1 {
		f = 0.05
	}
	c := raw
	if c <= 0 {
		c = d
	}
	if c < f {
		c = f
	}
	if c > 1 {
		c = 1
	}
	return c
}

// DomainBayes aggregates one domain's failed checks under the Bayesian
// observation model and returns the point estimate (score), the posterior
// standard deviation (sigma), and the domain-level average confidence of the
// evidence (evidenceConfidence).
//
//	E   = Σ |delta| · c            (expected deduction)
//	U   = Σ |delta|² · c · (1 − c) (variance contribution)
//	score = max(0, 100 − E)
//	sigma = sqrt(U)
//	evidenceConfidence = Σ(|delta|·c) / Σ|delta|   (1 when no failure evidence)
//
// When every failed check has confidence 1 (or the policy is disabled),
// U = 0 → sigma = 0 and score = max(0, 100 − Σ|delta|), identical to the
// legacy accumulation. DomainBayes does not mutate its inputs.
func DomainBayes(domain string, checks []CheckInput, policy ConfidencePolicy) (score, sigma, evidenceConfidence float64) {
	eSum := 0.0
	varSum := 0.0
	absDeltaSum := 0.0
	weightedDeltaSum := 0.0

	for _, c := range checks {
		if c.Domain != domain || c.Passed || c.Delta >= 0 {
			continue
		}
		s := math.Abs(c.Delta)
		conf := EffectiveConfidence(c.Confidence, policy)
		eSum += s * conf
		varSum += s * s * conf * (1.0 - conf)
		absDeltaSum += s
		weightedDeltaSum += s * conf
	}

	score = math.Max(0, 100-eSum)
	sigma = math.Sqrt(varSum)
	if absDeltaSum > 0 {
		evidenceConfidence = weightedDeltaSum / absDeltaSum
	} else {
		evidenceConfidence = 1.0
	}
	return score, sigma, evidenceConfidence
}

// ComputeDomainScoresBayes is the confidence-aware replacement for
// ComputeDomainScores. It returns per-domain point scores WITH their posterior
// sigma and evidence confidence attached to DomainScore.Sigma / .Confidence.
// With a disabled policy it is numerically identical to ComputeDomainScores
// (all sigma zero, all evidence confidence 1).
func ComputeDomainScoresBayes(weights []WeightConfig, checks []CheckInput, policy ConfidencePolicy) []DomainScore {
	wMap := BuildWeightMap(weights)

	activeDomains := make(map[string]bool)
	for _, c := range checks {
		activeDomains[c.Domain] = true
	}
	if len(activeDomains) == 0 {
		for domain := range wMap {
			activeDomains[domain] = true
		}
	}

	results := make([]DomainScore, 0, len(activeDomains))
	for domain := range activeDomains {
		score, sigma, evidence := DomainBayes(domain, checks, policy)
		results = append(results, DomainScore{
			Domain:     domain,
			Score:      score,
			Sigma:      sigma,
			Confidence: evidence,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})
	return results
}

// IntrinsicLayerWeight is the weight of the intrinsic (domain-quality) layer in
// the authoritative SSAM V2.0 three-layer aggregation:
//
//	Total = 0.5·intrinsic + 0.3·exposure·100 + 0.2·threat·100
//
// Only the intrinsic layer is a random quantity: it is the measured domain
// score. Exposure and threat are configuration coefficients (SPC score and CTI
// threat coefficient) and carry no sampling variance under this model. Hence,
// for an independent-domain model,
//
//	∂Total/∂score_d = IntrinsicLayerWeight · w_d / Σw
//	Var(Total)      = Σ (IntrinsicLayerWeight · w_d/Σw)² · σ_d²
//	σ_final         = IntrinsicLayerWeight · sqrt( Σ (w_d·σ_d)² ) / Σw
//
// i.e. the domain RSS must be folded through the intrinsic weight (audit
// I-12). Edge-factor / domain-adjust scaling of the intrinsic layer is NOT
// modelled here — this is a documented heuristic interval, not a valid
// posterior over the three-layer score.
const IntrinsicLayerWeight = 0.5

// FinalBayesStats propagates per-domain sigma into the final-score posterior
// standard deviation under the (documented) independent-domain assumption:
//
//	sigma_final = IntrinsicLayerWeight · sqrt( Σ (w_d · σ_d)² ) / Σ w_d
//
// The 0.5 factor is the intrinsic-layer weight of SSAMV20Formula: variance
// from the domain layer reaches the final score only through the 0.5·intrinsic
// term (see IntrinsicLayerWeight for the derivation). A disabled policy yields
// sigma 0.
//
// The interval itself is NOT returned here: it must be centered on the ACTUAL
// final score (which also contains the 0.3/0.2 deterministic layers), so
// callers use ConfidenceInterval. This keeps a single endpoint implementation
// (audit M-5).
func FinalBayesStats(weights []WeightConfig, domains []DomainScore) (sigmaFinal float64) {
	wMap := BuildWeightMap(weights)

	totalWeight := 0.0
	varSum := 0.0
	for _, ds := range domains {
		w, ok := wMap[ds.Domain]
		if !ok || w <= 0 {
			continue
		}
		totalWeight += w
		varSum += (w * ds.Sigma) * (w * ds.Sigma)
	}
	if totalWeight == 0 {
		return 0
	}
	return IntrinsicLayerWeight * math.Sqrt(varSum) / totalWeight
}

// ConfidenceInterval derives the heuristic 95% interval around a point
// estimate: [point − 1.96σ, point + 1.96σ].
//
// Clamping (audit I-12 / M-1): ONLY the lower bound is clamped at 0. The upper
// bound is deliberately NOT clamped to 100: the three-layer total can exceed
// 100 (e.g. threat_coeff=1.4 gives Total=108), and clamping both ends made the
// interval [100,100] — an interval that did not even contain its own point
// estimate. The nominal score range is 0–100, but this heuristic interval must
// stay consistent with the point estimate. It is NOT a valid posterior
// interval: it is the domain-score uncertainty folded through the intrinsic
// weight, centered on the point estimate.
func ConfidenceInterval(point, sigma float64) (lower95, upper95 float64) {
	if sigma < 0 {
		sigma = 0
	}
	half := 1.96 * sigma
	lower95 = point - half
	upper95 = point + half
	if lower95 < 0 {
		lower95 = 0
	}
	return lower95, upper95
}

// AcceptanceDecision is the SINGLE acceptability rule shared by every scoring
// path (audit B-2). By default the decision compares the point estimate with
// the threshold; with accept_by_lower_bound=true it compares the conservative
// 95% lower bound instead. A degenerate interval (sigma=0) makes both rules
// identical, which is why the factory default (confidence disabled) is
// bit-identical to the historical behavior.
func AcceptanceDecision(point, lower95, threshold float64, acceptByLowerBound bool) bool {
	if acceptByLowerBound {
		return lower95 >= threshold
	}
	return point >= threshold
}

// AggregateNodeConfidence derives a node-level confidence from per-domain
// evidence confidences (used when feeding Prism's NodeState). It is the
// weight-normalized mean of domain evidence confidence; domains with no
// failure evidence carry confidence 1.
func AggregateNodeConfidence(weights []WeightConfig, domains []DomainScore) float64 {
	wMap := BuildWeightMap(weights)
	acc := 0.0
	total := 0.0
	for _, ds := range domains {
		w, ok := wMap[ds.Domain]
		if !ok || w <= 0 {
			continue
		}
		acc += ds.Confidence * w
		total += w
	}
	if total == 0 {
		return 1.0
	}
	return acc / total
}
