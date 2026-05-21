package model

import (
	"fmt"
	"runtime"
	"time"
)

const (
	DomainAttackSurface      = "attack_surface"
	DomainBusinessContinuity = "business_continuity"
	DomainOperationTrust     = "operation_trust"
	DomainResilience         = "resilience"

	DomainKernelSecurity = "kernel_security"
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
	var passed bool
	var detail string

	func() {
		defer func() {
			if r := recover(); r != nil {
				passed = false
				detail = fmt.Sprintf("panic: %v", r)
			}
		}()
		passed, detail = c.Check()
	}()

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

var ExtensionDomains = []string{
	DomainKernelSecurity,
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
	KernelSecurity     float64 `json:"kernel_security,omitempty"`
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
	case DomainKernelSecurity:
		return d.KernelSecurity
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
	case DomainKernelSecurity:
		d.KernelSecurity = score
	}
}

type EdgeFactors struct {
	TwoFactorFailure float64 `json:"two_factor_failure"`
	SYNCookieDisabled float64 `json:"syn_cookie_disabled"`
	SELinuxDisabled  float64 `json:"selinux_disabled"`
	AppArmorDisabled float64 `json:"apparmor_disabled"`
	NoSIEM           float64 `json:"no_siem"`
	NoIDS            float64 `json:"no_ids"`
}

func (e EdgeFactors) ActiveFactors() []float64 {
	var factors []float64
	if e.TwoFactorFailure > 0 && e.TwoFactorFailure < 1.0 {
		factors = append(factors, e.TwoFactorFailure)
	}
	if e.SYNCookieDisabled > 0 && e.SYNCookieDisabled < 1.0 {
		factors = append(factors, e.SYNCookieDisabled)
	}
	if e.SELinuxDisabled > 0 && e.SELinuxDisabled < 1.0 {
		factors = append(factors, e.SELinuxDisabled)
	}
	if e.AppArmorDisabled > 0 && e.AppArmorDisabled < 1.0 {
		factors = append(factors, e.AppArmorDisabled)
	}
	if e.NoSIEM > 0 && e.NoSIEM < 1.0 {
		factors = append(factors, e.NoSIEM)
	}
	if e.NoIDS > 0 && e.NoIDS < 1.0 {
		factors = append(factors, e.NoIDS)
	}
	return factors
}

type AssessmentResult struct {
	HostID             string            `json:"host_id"`
	Hostname           string            `json:"hostname"`
	Timestamp          time.Time         `json:"timestamp"`
	FinalScore         float64           `json:"final_score"`
	Acceptable         bool              `json:"acceptable"`
	Threshold          float64           `json:"threshold"`
	DomainScores       DomainScores      `json:"domain_scores"`
	DomainWeightShift  map[string]float64 `json:"domain_weight_shift,omitempty"`
	EdgeFactors        EdgeFactors       `json:"edge_factors"`
	ThreatCoeff        float64           `json:"threat_coefficient"`
	SPCScore           float64           `json:"spc_score,omitempty"`
	Checks             []CheckResult     `json:"checks"`
}

type Weights struct {
	AttackSurface      float64
	BusinessContinuity float64
	OperationTrust     float64
	Resilience         float64
	KernelSecurity     float64
}

func (w *Weights) Normalize() {
	sum := w.AttackSurface + w.BusinessContinuity + w.OperationTrust + w.Resilience + w.KernelSecurity
	if sum == 0 || sum == 100 {
		return
	}
	w.AttackSurface = w.AttackSurface / sum * 100
	w.BusinessContinuity = w.BusinessContinuity / sum * 100
	w.OperationTrust = w.OperationTrust / sum * 100
	w.Resilience = w.Resilience / sum * 100
	w.KernelSecurity = w.KernelSecurity / sum * 100
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

type SPCConfig struct {
	Enabled            bool
	MinPScore          float64
	CacheRetentionDays int
	FetchIntervalH     int

	NVD   NVConfig
	EPSS  EPSSConfig
	CISAKEV CISAKEVConfig
	MISP  MISPConfig
	OSCAL OSCALConfig
}

type NVConfig struct {
	BaseURL        string
	APIKey         string
	SyncIntervalH  int
}

type EPSSConfig struct {
	Enabled       bool
	DataURL       string
	SyncIntervalH int
}

type CISAKEVConfig struct {
	Enabled       bool
	CatalogURL    string
	SyncIntervalH int
}

type MISPConfig struct {
	BaseURL        string
	APIKey         string
	VerifyTLS      bool
	SyncIntervalH  int
	TLPFilter      string
}

type OSCALConfig struct {
	Enabled      bool
	InputFormat  string
	ResultsPath  string
	PlanPath     string
}
