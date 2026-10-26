package ssam

import (
	"math"
	"testing"
)

// beta_bayes 聚合：c̃ = (κ + c)/(κ + 1)。
//
// 两条不变量必须成立（否则会破坏历史兼容或让先验"压低"高可信观测）：
//  1. c = 1 ⇒ c̃ = 1；
//  2. κ ≤ 0 ⇒ c̃ = c（weighted_evidence 是它的退化情形）。
func TestBetaShrinkConfidenceInvariants(t *testing.T) {
	if got := BetaShrinkConfidence(1.0, 2); got != 1.0 {
		t.Errorf("c=1 必须保持不变（legacy 恒等），got %v", got)
	}
	if got := BetaShrinkConfidence(0.5, 0); math.Abs(got-0.5) > 1e-12 {
		t.Errorf("κ=0 ⇒ 恒等映射，got %v", got)
	}
	if got := BetaShrinkConfidence(0.5, 2); math.Abs(got-(2.5/3.0)) > 1e-12 {
		t.Errorf("κ=2, c=0.5 ⇒ 0.8333…，got %v", got)
	}
	// 只会往 1 抬，不会压低。
	for _, c := range []float64{0.05, 0.3, 0.7, 0.95} {
		if got := BetaShrinkConfidence(c, 3); got < c-1e-12 || got > 1+1e-12 {
			t.Errorf("κ=3, c=%v ⇒ %v 必须落在 [c,1]", c, got)
		}
	}
}

func TestEffectiveConfidenceRespectsAlgorithm(t *testing.T) {
	p := ConfidencePolicy{Enabled: true, Default: 1.0, Floor: 0.05}

	// weighted_evidence（缺省）：直接归一化，不做收缩。
	if got := EffectiveConfidence(0.5, p); got != 0.5 {
		t.Errorf("weighted_evidence c=0.5 ⇒ 0.5, got %v", got)
	}
	// beta_bayes + κ=2：0.5 → 0.8333…
	p.Algorithm = AlgorithmBetaBayes
	p.PriorStrength = 2
	if got := EffectiveConfidence(0.5, p); math.Abs(got-(2.5/3.0)) > 1e-12 {
		t.Errorf("beta_bayes κ=2 c=0.5 ⇒ 0.8333…, got %v", got)
	}
	// 未给 prior_strength（0）⇒ 用 2.0。
	p.PriorStrength = 0
	if got := EffectiveConfidence(0.5, p); math.Abs(got-(2.5/3.0)) > 1e-12 {
		t.Errorf("beta_bayes 未设 κ ⇒ 按 2.0 收缩，got %v", got)
	}
	// 关闭时恒 1。
	p.Enabled = false
	if got := EffectiveConfidence(0.5, p); got != 1.0 {
		t.Errorf("disabled ⇒ 1.0, got %v", got)
	}
}

// DomainBayes 在 beta_bayes 下必须用 c̃ 同时改 E 与 U：
// 一条失败检查（s=10, c=0.5, κ=2）：
//
//	weighted: E=5   ⇒ score 95，  σ=sqrt(100·0.5·0.5)=5
//	beta:     c̃=5/6 ⇒ E=8.333 ⇒ score 91.667，σ=sqrt(100·(5/6)·(1/6))=sqrt(13.888)=3.727
func TestDomainBayesBetaShrink(t *testing.T) {
	checks := []CheckInput{{CheckID: "X", Domain: "d", Passed: false, Delta: -10, Confidence: 0.5}}

	w := ConfidencePolicy{Enabled: true, Default: 1.0, Floor: 0.05}
	scoreW, sigmaW, evW := DomainBayes("d", checks, w)
	if math.Abs(scoreW-95) > 1e-9 || math.Abs(sigmaW-5) > 1e-9 {
		t.Fatalf("weighted: score=%v sigma=%v, want 95/5", scoreW, sigmaW)
	}

	b := w
	b.Algorithm = AlgorithmBetaBayes
	b.PriorStrength = 2
	scoreB, sigmaB, evB := DomainBayes("d", checks, b)
	ct := 5.0 / 6.0
	wantScore := 100 - 10*ct
	wantSigma := math.Sqrt(100 * ct * (1 - ct))
	if math.Abs(scoreB-wantScore) > 1e-9 {
		t.Errorf("beta score=%v, want %v", scoreB, wantScore)
	}
	if math.Abs(sigmaB-wantSigma) > 1e-9 {
		t.Errorf("beta sigma=%v, want %v", sigmaB, wantSigma)
	}
	if math.Abs(evB-ct) > 1e-9 {
		t.Errorf("beta evidence confidence=%v, want %v", evB, ct)
	}
	// 方向：先验是"κ 个完全可信伪观测" ⇒ 低可信观测被抬向 1 ⇒ 扣分更多（分数更低）、方差更小。
	if !(scoreB < scoreW && sigmaB < sigmaW) {
		t.Errorf("beta_bayes 应更多扣分且方差更小：score %v→%v, sigma %v→%v", scoreW, scoreB, sigmaW, sigmaB)
	}
	if evW != 0.5 {
		t.Errorf("weighted evidence confidence=%v, want 0.5", evW)
	}
}
