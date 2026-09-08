package ssam

import (
	"math"
	"sort"
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
	// PriorStrength is the Beta-prior equivalent sample size used by the
	// strict beta_bayes aggregator (reserved; weighted_evidence ignores it
	// except as documentation). Must be > 0.
	PriorStrength float64
}

// DefaultConfidencePolicy returns the identity policy: confidence-aware
// scoring disabled, so legacy behavior is preserved exactly.
func DefaultConfidencePolicy() ConfidencePolicy {
	return ConfidencePolicy{
		Enabled:      false,
		Default:      1.0,
		Floor:        0.05,
		PriorStrength: 2.0,
	}
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
		conf := NormalizeConfidence(c.Confidence, policy)
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

// FinalBayesStats propagates per-domain sigma into a final-score posterior
// standard deviation under the (documented) independent-domain assumption,
// and derives the 95% interval clipped to [0,100].
//
//	sigma_final = sqrt( Σ (w_d · σ_d)² ) / Σ w_d
//
// A disabled policy yields sigma 0 and the degenerate interval [score, score].
func FinalBayesStats(weights []WeightConfig, domains []DomainScore) (sigmaFinal, lower95, upper95 float64) {
	wMap := BuildWeightMap(weights)

	weightedScore := 0.0
	totalWeight := 0.0
	varSum := 0.0
	for _, ds := range domains {
		w, ok := wMap[ds.Domain]
		if !ok || w <= 0 {
			continue
		}
		weightedScore += ds.Score * w
		totalWeight += w
		varSum += (w * ds.Sigma) * (w * ds.Sigma)
	}
	if totalWeight == 0 {
		return 0, 0, 0
	}
	mean := weightedScore / totalWeight
	sigmaFinal = math.Sqrt(varSum) / totalWeight
	lower := mean - 1.96*sigmaFinal
	upper := mean + 1.96*sigmaFinal
	if lower < 0 {
		lower = 0
	}
	if upper > 100 {
		upper = 100
	}
	return sigmaFinal, lower, upper
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
