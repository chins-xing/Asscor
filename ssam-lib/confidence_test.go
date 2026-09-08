package ssam

import (
	"math"
	"testing"
)

// enabledPolicy returns a confidence-aware policy with the design's typical
// settings for the confidence tests.
func enabledPolicy() ConfidencePolicy {
	p := DefaultConfidencePolicy()
	p.Enabled = true
	p.Default = 1.0
	p.Floor = 0.05
	return p
}

func failedCheck(domain, id string, delta float64) CheckInput {
	return CheckInput{CheckID: id, Domain: domain, Passed: false, Delta: delta}
}

// TestConfidenceDisabledMatchesLegacy: with the default (disabled) policy the
// Bayesian path must reproduce the legacy accumulation exactly — sigma 0,
// confidence 1, and scores identical to plain delta summation.
func TestConfidenceDisabledMatchesLegacy(t *testing.T) {
	checks := []CheckInput{
		failedCheck("attack_surface", "AS-001", -10),
		failedCheck("attack_surface", "AS-002", -5),
		failedCheck("operation_trust", "OT-001", -15),
		{CheckID: "BC-001", Domain: "business_continuity", Passed: true, Delta: 0},
	}
	legacy := ComputeDomainScores(DefaultWeights, checks)
	conf := ComputeDomainScoresWithConfidence(DefaultWeights, checks, DefaultConfidencePolicy())

	if len(legacy) != len(conf) {
		t.Fatalf("length mismatch: legacy=%d conf=%d", len(legacy), len(conf))
	}
	byDomain := map[string]DomainScore{}
	for _, d := range legacy {
		byDomain[d.Domain] = d
	}
	for _, c := range conf {
		l := byDomain[c.Domain]
		if l.Score != c.Score {
			t.Errorf("domain %s: legacy score %.4f != conf score %.4f", c.Domain, l.Score, c.Score)
		}
		if c.Sigma != 0 {
			t.Errorf("domain %s: sigma must be 0 when disabled, got %v", c.Domain, c.Sigma)
		}
		if c.Confidence != 1 {
			t.Errorf("domain %s: evidence confidence must be 1 when disabled, got %v", c.Domain, c.Confidence)
		}
	}

	// attack_surface = 100 - 10 - 5 = 85
	if got := byDomain["attack_surface"].Score; got != 85 {
		t.Errorf("attack_surface score = %v, want 85", got)
	}
}

// TestDomainBayesPointEstimate: E = Σ|delta|·c. conf 1.0 → legacy; conf 0.5
// halves the deduction.
func TestDomainBayesPointEstimate(t *testing.T) {
	checks := []CheckInput{
		failedCheck("attack_surface", "AS-001", -10),
		failedCheck("attack_surface", "AS-002", -5),
	}
	// Fully confident: 100 - 15 = 85.
	s, sigma, conf := DomainBayes("attack_surface", checks, enabledPolicy())
	if math.Abs(s-85) > 1e-9 {
		t.Errorf("full-confidence score = %v, want 85", s)
	}
	if sigma != 0 {
		t.Errorf("full-confidence sigma must be 0, got %v", sigma)
	}
	if conf != 1 {
		t.Errorf("evidence confidence = %v, want 1", conf)
	}

	// Half confidence: E = 10*0.5 + 5*0.5 = 7.5 → score 92.5.
	lowChecks := []CheckInput{
		{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: -10, Confidence: 0.5},
		{CheckID: "AS-002", Domain: "attack_surface", Passed: false, Delta: -5, Confidence: 0.5},
	}
	s, sigma, conf = DomainBayes("attack_surface", lowChecks, enabledPolicy())
	if math.Abs(s-92.5) > 1e-9 {
		t.Errorf("half-confidence score = %v, want 92.5", s)
	}
	// variance = 100*0.25 + 25*0.25 = 31.25 → sigma = 5.590...
	wantSigma := math.Sqrt(31.25)
	if math.Abs(sigma-wantSigma) > 1e-9 {
		t.Errorf("sigma = %v, want %v", sigma, wantSigma)
	}
	// weighted/abs = (5+2.5)/15 = 0.5
	if math.Abs(conf-0.5) > 1e-9 {
		t.Errorf("evidence confidence = %v, want 0.5", conf)
	}
}

// TestNormalizeConfidenceClamps: floor applies to tiny values, ceiling to >1.
func TestNormalizeConfidenceClamps(t *testing.T) {
	p := enabledPolicy()
	if got := NormalizeConfidence(0, p); got != 1.0 {
		t.Errorf("unspecified must become policy default 1.0, got %v", got)
	}
	if got := NormalizeConfidence(0.001, p); got != 0.05 {
		t.Errorf("below-floor must clamp to floor 0.05, got %v", got)
	}
	if got := NormalizeConfidence(1.5, p); got != 1.0 {
		t.Errorf("above-1 must clamp to 1, got %v", got)
	}
	if got := NormalizeConfidence(0.7, DefaultConfidencePolicy()); got != 1.0 {
		t.Errorf("disabled policy must yield 1.0, got %v", got)
	}
}

// TestEdgeFactorTriggerConfidenceAttenuation (design §2.4): a factor triggered
// by a half-confidence check applies a milder penalty; full confidence keeps
// the legacy factor.
func TestEdgeFactorTriggerConfidenceAttenuation(t *testing.T) {
	efs := []EdgeFactorConfig{
		{ID: "EF-X", Name: "X", Factor: 0.75, TriggerCheck: "T-1"},
	}
	// Full confidence → legacy factor 0.75.
	full := []CheckInput{failedCheck("operation_trust", "T-1", -10)}
	fullRes := ApplyEdgeFactorsToChecksPolicy(efs, full, nil, enabledPolicy())
	if !fullRes[0].Active || math.Abs(fullRes[0].Factor-0.75) > 1e-9 {
		t.Errorf("full-confidence trigger: active=%v factor=%v, want true/0.75", fullRes[0].Active, fullRes[0].Factor)
	}

	// Half confidence → effective = 1 - (1-0.75)*0.5 = 0.875.
	half := []CheckInput{{CheckID: "T-1", Domain: "operation_trust", Passed: false, Delta: -10, Confidence: 0.5}}
	halfRes := ApplyEdgeFactorsToChecksPolicy(efs, half, nil, enabledPolicy())
	want := 1.0 - (1.0-0.75)*0.5
	if !halfRes[0].Active || math.Abs(halfRes[0].Factor-want) > 1e-9 {
		t.Errorf("half-confidence trigger: factor=%v, want %v", halfRes[0].Factor, want)
	}
	if math.Abs(halfRes[0].TriggerConfidence-0.5) > 1e-9 {
		t.Errorf("TriggerConfidence = %v, want 0.5", halfRes[0].TriggerConfidence)
	}

	// Disabled policy → no attenuation even with explicit low confidence.
	disabledRes := ApplyEdgeFactorsToChecks(efs, half, nil)
	if math.Abs(disabledRes[0].Factor-0.75) > 1e-9 {
		t.Errorf("disabled policy must keep legacy factor, got %v", disabledRes[0].Factor)
	}
}

// TestFinalBayesStats: RSS variance propagation for two domains.
func TestFinalBayesStats(t *testing.T) {
	checks := []CheckInput{
		{CheckID: "AS-1", Domain: "attack_surface", Passed: false, Delta: -10, Confidence: 0.5},  // σ²=25
		{CheckID: "OT-1", Domain: "operation_trust", Passed: false, Delta: -20, Confidence: 0.5}, // σ²=100
	}
	domains := ComputeDomainScoresBayes(DefaultWeights, checks, enabledPolicy())
	sigma, lo, hi := FinalBayesStats(DefaultWeights, domains)

	// Manual: attack_surface weight 35, σ=5 → w·σ=175; operation_trust w=25, σ=10 → 250.
	// RSS = sqrt(175² + 250²) = sqrt(30625+62500)=sqrt(93125)=305.16; /60 = 5.086.
	want := math.Sqrt(175*175+250*250) / 60
	if math.Abs(sigma-want) > 1e-6 {
		t.Errorf("sigma_final = %v, want %v", sigma, want)
	}
	if lo < 0 || hi > 100 || lo > hi {
		t.Errorf("interval invalid: [%v, %v]", lo, hi)
	}
	// Disabled policy → degenerate interval.
	domainsLegacy := ComputeDomainScoresBayes(DefaultWeights, checks, DefaultConfidencePolicy())
	sigma2, lo2, hi2 := FinalBayesStats(DefaultWeights, domainsLegacy)
	if sigma2 != 0 || lo2 != hi2 {
		t.Errorf("disabled policy interval must be degenerate [score,score], got σ=%v [%v,%v]", sigma2, lo2, hi2)
	}
}

// TestAggregateNodeConfidence: weight-normalized mean of domain confidence.
func TestAggregateNodeConfidence(t *testing.T) {
	// DomainScore lists only contain domains that appear in checks, so cover
	// all four weighted domains (passing checks include the domain without
	// affecting its score or confidence).
	checks := []CheckInput{
		{CheckID: "AS-1", Domain: "attack_surface", Passed: false, Delta: -10, Confidence: 0.5},
		{CheckID: "AS-2", Domain: "attack_surface", Passed: false, Delta: -5, Confidence: 1.0},
		{CheckID: "BC-1", Domain: "business_continuity", Passed: true, Delta: 0},
		{CheckID: "OT-1", Domain: "operation_trust", Passed: true, Delta: 0},
		{CheckID: "RS-1", Domain: "resilience", Passed: true, Delta: 0},
	}
	domains := ComputeDomainScoresBayes(DefaultWeights, checks, enabledPolicy())
	nc := AggregateNodeConfidence(DefaultWeights, domains)
	// attack_surface evidence = (10·0.5 + 5·1.0)/(10+5) = 10/15 = 0.6667;
	// other domains have no failure evidence → confidence 1.
	// node = (0.6667·35 + 1·25 + 1·25 + 1·15)/100 = (23.333+65)/100 = 0.88333.
	want := (35.0*10/15 + 25.0 + 25.0 + 15.0) / 100.0
	if math.Abs(nc-want) > 1e-9 {
		t.Errorf("node confidence = %v, want %v", nc, want)
	}
}
