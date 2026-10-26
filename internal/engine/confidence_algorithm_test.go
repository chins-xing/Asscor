//go:build engine && assessor

package engine

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	ssamlib "github.com/chins-xing/ssam"
)

// [confidence] algorithm / prior_strength 必须**穿过**配置→policy 的转换，
// 否则库侧实现了 beta_bayes、内核却永远传不到（方向① 里这类"解析了但没消费"已踩过两次）。
func TestConfidencePolicyCarriesAlgorithmAndPriorStrength(t *testing.T) {
	cfg, err := config.Parse(`
[confidence]
enabled = true
algorithm = beta_bayes
prior_strength = 3
default = 1.0
floor = 0.05
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol := ConfidencePolicyFromConfig(cfg)
	if pol.Algorithm != ssamlib.AlgorithmBetaBayes {
		t.Errorf("policy.Algorithm = %q, want %q", pol.Algorithm, ssamlib.AlgorithmBetaBayes)
	}
	if math.Abs(pol.PriorStrength-3) > 1e-12 {
		t.Errorf("policy.PriorStrength = %v, want 3", pol.PriorStrength)
	}
	// 实际消费点必须用收缩后的 c̃：c=0.5, κ=3 ⇒ (3+0.5)/4 = 0.875
	if got := ssamlib.EffectiveConfidence(0.5, pol); math.Abs(got-0.875) > 1e-12 {
		t.Errorf("EffectiveConfidence(0.5, βκ=3) = %v, want 0.875", got)
	}

	// 缺省（不写 algorithm）仍是 weighted_evidence，且 weighted_evidence 不做收缩。
	cfg2, err := config.Parse("[confidence]\nenabled = true\n")
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	pol2 := ConfidencePolicyFromConfig(cfg2)
	if pol2.Algorithm != "" && pol2.Algorithm != ssamlib.AlgorithmWeightedEvidence {
		t.Errorf("缺省 algorithm = %q, want 空或 weighted_evidence", pol2.Algorithm)
	}
	if got := ssamlib.EffectiveConfidence(0.5, pol2); math.Abs(got-0.5) > 1e-12 {
		t.Errorf("weighted_evidence 不得收缩：got %v, want 0.5", got)
	}
}
