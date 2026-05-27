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
	SPCCVEs            []SPCCVEInfo      `json:"spc_cves,omitempty"`
	ATTACKCoverage     []ATTACKCoverageInfo `json:"attck_coverage,omitempty"`
	ATTACKKillChain    *ATTACKKillChainInfo `json:"attck_kill_chain,omitempty"`
	ATTACKAPTMatches   []ATTACKAPTMatchInfo `json:"attck_apt_matches,omitempty"`
	ATTACKPredictedRisk *ATTACKPredictedRiskInfo `json:"attck_predicted_risk,omitempty"`
	ATTACKFailedTechs  []string             `json:"attck_failed_techniques,omitempty"`
	Checks             []CheckResult     `json:"checks"`
}

type ATTACKCoverageInfo struct {
	TacticID        string  `json:"tactic_id"`
	TacticName      string  `json:"tactic_name"`
	TotalTechniques int     `json:"total_techniques"`
	CoveredDet      int     `json:"covered_detection"`
	CoverageDet     float64 `json:"coverage_detection"`
	CoveragePrev    float64 `json:"coverage_prevention"`
	CoverageComp    float64 `json:"coverage_composite"`
	RiskLevel       string  `json:"risk_level"`
}

type ATTACKKillChainInfo struct {
	Stages       []ATTACKKillChainStage `json:"stages"`
	OverallScore float64                `json:"overall_score"`
	WeakestStage string                 `json:"weakest_stage"`
}

type ATTACKKillChainStage struct {
	Name         string  `json:"name"`
	Score        float64 `json:"score"`
	Status       string  `json:"status"`
	ChecksPassed int     `json:"checks_passed"`
	ChecksTotal  int     `json:"checks_total"`
}

type ATTACKAPTMatchInfo struct {
	GroupID     string   `json:"group_id"`
	GroupName   string   `json:"group_name"`
	Similarity  float64  `json:"similarity"`
	Confidence  string   `json:"confidence"`
	OverlapTech []string `json:"overlap_techniques"`
}

type ATTACKPredictedRiskInfo struct {
	MaxRiskScore    float64  `json:"max_risk_score"`
	EnhancedThreat  float64  `json:"enhanced_threat_coeff"`
	PredictedPaths  int      `json:"predicted_paths"`
	Recommendations []string `json:"recommendations,omitempty"`
}

type SPCCVEInfo struct {
	CVEID   string  `json:"cve_id"`
	CVSS    float64 `json:"cvss"`
	EPSS    float64 `json:"epss"`
	InKEV   bool    `json:"in_kev"`
	HasPoC  bool    `json:"has_poc"`
	Penalty float64 `json:"penalty"`
	Product string  `json:"product,omitempty"`
}

type Weights struct {
	AttackSurface      float64
	BusinessContinuity float64
	OperationTrust     float64
	Resilience         float64
	KernelSecurity     float64
}

func (w *Weights) Normalize() {
	coreSum := w.AttackSurface + w.BusinessContinuity + w.OperationTrust + w.Resilience
	if coreSum == 0 || coreSum == 100 {
		return
	}
	w.AttackSurface = w.AttackSurface / coreSum * 100
	w.BusinessContinuity = w.BusinessContinuity / coreSum * 100
	w.OperationTrust = w.OperationTrust / coreSum * 100
	w.Resilience = w.Resilience / coreSum * 100
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
	MaxCacheSize       int

	NVD     NVConfig
	EPSS    EPSSConfig
	CISAKEV CISAKEVConfig
	MISP    MISPConfig
	OSCAL   OSCALConfig
	CNNVD   CNNVDConfig
	CNVD    CNVDConfig
}

type NVConfig struct {
	BaseURL        string
	APIKey         string
	SyncIntervalH  int
	UseLastMod     bool
	NoRejected     bool
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

type CNNVDConfig struct {
	Enabled       bool
	BaseURL       string
	APIKey        string
	SyncIntervalH int
}

type CNVDConfig struct {
	Enabled       bool
	BaseURL       string
	SyncIntervalH int
}

type ATTACKConfig struct {
	Enabled              bool
	Version              string
	AutoHunt             bool
	BeaconThreshold      float64
	AttributionThreshold float64
	SafeEmulation        bool
}
