package model

import (
	"runtime"
	"time"
)

const (
	DomainAttackSurface      = "attack_surface"
	DomainBusinessContinuity = "business_continuity"
	DomainOperationTrust     = "operation_trust"
	DomainResilience         = "resilience"
)

type CheckFunc func() (passed bool, detail string)

type CheckItem struct {
	ID            string
	Domain        string
	Name          string
	Description   string
	Delta         float64
	ComplianceRef string
	Platform      string
	Check         CheckFunc
}

func (c CheckItem) Run() CheckResult {
	passed, detail := c.Check()
	return CheckResult{
		CheckID:       c.ID,
		Domain:        c.Domain,
		Name:          c.Name,
		Passed:        passed,
		Delta:         c.Delta,
		Detail:        detail,
		ComplianceRef: c.ComplianceRef,
	}
}

func (c CheckItem) MatchesPlatform() bool {
	return c.Platform == "" || c.Platform == runtime.GOOS
}

var AllDomains = []string{
	DomainAttackSurface,
	DomainBusinessContinuity,
	DomainOperationTrust,
	DomainResilience,
}

type CheckResult struct {
	CheckID   string  `json:"check_id"`
	Domain    string  `json:"domain"`
	Name      string  `json:"name"`
	Passed    bool    `json:"passed"`
	Delta     float64 `json:"delta"`
	Detail    string  `json:"detail"`
	ComplianceRef string `json:"compliance_ref,omitempty"`
}

type DomainScores struct {
	AttackSurface      float64 `json:"attack_surface"`
	BusinessContinuity float64 `json:"business_continuity"`
	OperationTrust     float64 `json:"operation_trust"`
	Resilience         float64 `json:"resilience"`
}

func (d DomainScores) Get(domain string) float64 {
	switch domain {
	case DomainAttackSurface:
		return d.AttackSurface
	case DomainBusinessContinuity:
		return d.BusinessContinuity
	case DomainOperationTrust:
		return d.OperationTrust
	case DomainResilience:
		return d.Resilience
	default:
		return 0
	}
}

func (d *DomainScores) Set(domain string, score float64) {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	switch domain {
	case DomainAttackSurface:
		d.AttackSurface = score
	case DomainBusinessContinuity:
		d.BusinessContinuity = score
	case DomainOperationTrust:
		d.OperationTrust = score
	case DomainResilience:
		d.Resilience = score
	}
}

type EdgeFactors struct {
	TwoFactorFailure     float64 `json:"two_factor_failure"`
	SynCookieOff         float64 `json:"syn_cookie_off"`
	ResourceCritical     float64 `json:"resource_critical"`
	SupplyChainUnchecked float64 `json:"supply_chain_unchecked"`
	AutoBlockNoWhitelist float64 `json:"auto_block_no_whitelist"`
}

func (e EdgeFactors) ActiveFactors() []float64 {
	var factors []float64
	if e.TwoFactorFailure < 1.0 {
		factors = append(factors, e.TwoFactorFailure)
	}
	if e.SynCookieOff < 1.0 {
		factors = append(factors, e.SynCookieOff)
	}
	if e.ResourceCritical < 1.0 {
		factors = append(factors, e.ResourceCritical)
	}
	if e.SupplyChainUnchecked < 1.0 {
		factors = append(factors, e.SupplyChainUnchecked)
	}
	if e.AutoBlockNoWhitelist < 1.0 {
		factors = append(factors, e.AutoBlockNoWhitelist)
	}
	return factors
}

type AssessmentResult struct {
	HostID       string            `json:"host_id"`
	Hostname     string            `json:"hostname"`
	Timestamp    time.Time         `json:"timestamp"`
	FinalScore   float64           `json:"final_score"`
	Acceptable   bool              `json:"acceptable"`
	Threshold    float64           `json:"threshold"`
	DomainScores DomainScores      `json:"domain_scores"`
	EdgeFactors  EdgeFactors       `json:"edge_factors"`
	ThreatCoeff  float64           `json:"threat_coefficient"`
	SPCScore     float64           `json:"spc_score,omitempty"`
	Checks       []CheckResult     `json:"checks"`
}

type Weights struct {
	AttackSurface      float64
	BusinessContinuity float64
	OperationTrust     float64
	Resilience         float64
}

func (w *Weights) Normalize() {
	sum := w.AttackSurface + w.BusinessContinuity + w.OperationTrust + w.Resilience
	if sum == 0 || sum == 100 {
		return
	}
	w.AttackSurface = w.AttackSurface / sum * 100
	w.BusinessContinuity = w.BusinessContinuity / sum * 100
	w.OperationTrust = w.OperationTrust / sum * 100
	w.Resilience = w.Resilience / sum * 100
}

func (w Weights) Get(domain string) float64 {
	switch domain {
	case DomainAttackSurface:
		return w.AttackSurface
	case DomainBusinessContinuity:
		return w.BusinessContinuity
	case DomainOperationTrust:
		return w.OperationTrust
	case DomainResilience:
		return w.Resilience
	default:
		return 0
	}
}
