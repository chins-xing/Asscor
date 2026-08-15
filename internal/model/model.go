package model

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	DomainAttackSurface      = "attack_surface"
	DomainBusinessContinuity = "business_continuity"
	DomainOperationTrust     = "operation_trust"
	DomainResilience         = "resilience"
	DomainKernelSecurity     = "kernel_security"
)

var AllDomains = []string{
	DomainAttackSurface,
	DomainBusinessContinuity,
	DomainOperationTrust,
	DomainResilience,
}

var ExtensionDomains = []string{
	DomainKernelSecurity,
}

type CheckFunc func() (passed bool, detail string)

type PrivilegeLevel int

const (
	PrivNormal PrivilegeLevel = iota
	PrivRoot
)

func (p PrivilegeLevel) String() string {
	switch p {
	case PrivRoot:
		return "root"
	default:
		return "normal"
	}
}

// CheckSource identifies the origin of a check item, separating built-in
// platform checks from configuration-defined user checks.
type CheckSource string

const (
	// CheckSourceBuiltin marks compiled-in platform checks (internal/checks/linux).
	// Zero value ("") also means builtin for backward compatibility.
	CheckSourceBuiltin CheckSource = "builtin"
	// CheckSourceUser marks configuration-defined checks ([user_check.*]).
	CheckSourceUser CheckSource = "user"
)

type CheckItem struct {
	ID            string
	Domain        string
	Name          string
	Description   string
	Delta         float64
	ComplianceRef string
	Platform      string
	Check         CheckFunc
	Privilege     PrivilegeLevel
	// Source distinguishes user-defined checks from builtin ones. Empty means
	// builtin. It lets consumers (registry, reporting, auditing) tell apart
	// configuration-injected checks from the compiled-in platform set.
	Source CheckSource
}

func (c CheckItem) Run() CheckResult {
	if c.Privilege == PrivRoot && os.Geteuid() != 0 {
		return c.skipResult("skipped — requires root privileges")
	}

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

	// A check that failed solely because it could not read a root-only file
	// or directory (EACCES/EPERM) is not a real failure — it is an
	// "insufficient privilege" skip. Convert it so non-root agents do not get
	// penalized for checks they cannot perform.
	if !passed && IsPermissionDeniedDetail(detail) {
		return c.skipResult("skipped — requires root privileges (" + detail + ")")
	}

	return CheckResult{
		CheckID:       c.ID,
		Domain:        c.Domain,
		Name:          c.Name,
		Passed:        passed,
		Delta:         c.Delta,
		Detail:        detail,
		ComplianceRef: c.ComplianceRef,
		Source:        c.Source,
	}
}

// skipResult builds a neutral "skipped" CheckResult. A skipped check carries
// Delta 0 (no score impact) and Passed true (not counted as a failure).
func (c CheckItem) skipResult(detail string) CheckResult {
	return CheckResult{
		CheckID:       c.ID,
		Domain:        c.Domain,
		Name:          c.Name,
		Passed:        true,
		Delta:         0,
		Detail:        detail,
		ComplianceRef: c.ComplianceRef,
		Source:        c.Source,
	}
}

// IsPermissionDeniedDetail reports whether a check detail string indicates the
// check could not complete because of insufficient permission (EACCES/EPERM).
// It recognizes both Go error strings and the Chinese detail text emitted by
// checks reading root-only files/directories.
func IsPermissionDeniedDetail(detail string) bool {
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "eacces") ||
		strings.Contains(lower, "eperm") ||
		strings.Contains(lower, "requires root") {
		return true
	}
	return strings.Contains(detail, "权限不足") ||
		strings.Contains(detail, "无权限") ||
		strings.Contains(detail, "拒绝访问") ||
		strings.Contains(detail, "需要 root") ||
		strings.Contains(detail, "需要root")
}

func (c CheckItem) MatchesPlatform() bool {
	return c.Platform == "" || c.Platform == runtime.GOOS
}

type CheckResult struct {
	CheckID       string  `json:"check_id"`
	Domain        string  `json:"domain"`
	Name          string  `json:"name"`
	Passed        bool    `json:"passed"`
	Delta         float64 `json:"delta"`
	Detail        string  `json:"detail"`
	ComplianceRef string  `json:"compliance_ref,omitempty"`
	// Source carries the origin of the check (builtin/user). Empty means
	// builtin; user-defined checks carry CheckSourceUser so reports and
	// auditing can distinguish configuration-injected checks.
	Source CheckSource `json:"source,omitempty"`
}

type DomainScores struct {
	AttackSurface      float64            `json:"attack_surface"`
	BusinessContinuity float64            `json:"business_continuity"`
	OperationTrust     float64            `json:"operation_trust"`
	Resilience         float64            `json:"resilience"`
	KernelSecurity     float64            `json:"kernel_security,omitempty"`
	Extra              map[string]float64 `json:"extra_scores,omitempty"`
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
		if d.Extra != nil {
			if v, ok := d.Extra[domain]; ok {
				return v
			}
		}
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
	default:
		if d.Extra == nil {
			d.Extra = make(map[string]float64)
		}
		d.Extra[domain] = score
	}
}

func (d DomainScores) GetAllDomainScores() map[string]float64 {
	m := map[string]float64{
		DomainAttackSurface:      d.AttackSurface,
		DomainBusinessContinuity: d.BusinessContinuity,
		DomainOperationTrust:     d.OperationTrust,
		DomainResilience:         d.Resilience,
	}
	if d.KernelSecurity != 0 {
		m[DomainKernelSecurity] = d.KernelSecurity
	}
	for k, v := range d.Extra {
		m[k] = v
	}
	return m
}

type EdgeFactors struct {
	TwoFactorFailure  float64 `json:"two_factor_failure"`
	SYNCookieDisabled float64 `json:"syn_cookie_disabled"`
	SELinuxDisabled   float64 `json:"selinux_disabled"`
	AppArmorDisabled  float64 `json:"apparmor_disabled"`
	NoSIEM            float64 `json:"no_siem"`
	NoIDS             float64 `json:"no_ids"`
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
	HostID                     string                   `json:"host_id"`
	Hostname                   string                   `json:"hostname"`
	Timestamp                  time.Time                `json:"timestamp"`
	FinalScore                 float64                  `json:"final_score"`
	Acceptable                 bool                     `json:"acceptable"`
	Threshold                  float64                  `json:"threshold"`
	DomainScores               DomainScores             `json:"domain_scores"`
	DomainWeightShift          map[string]float64       `json:"domain_weight_shift,omitempty"`
	EdgeFactors                EdgeFactors              `json:"edge_factors"`
	ThreatCoeff                float64                  `json:"threat_coefficient"`
	SPCScore                   float64                  `json:"spc_score,omitempty"`
	SPCCVEs                    []SPCCVEInfo             `json:"spc_cves,omitempty"`
	ATTACKCoverage             []ATTACKCoverageInfo     `json:"attck_coverage,omitempty"`
	ATTACKKillChain            *ATTACKKillChainInfo     `json:"attck_kill_chain,omitempty"`
	ATTACKAPTMatches           []ATTACKAPTMatchInfo     `json:"attck_apt_matches,omitempty"`
	ATTACKPredictedRisk        *ATTACKPredictedRiskInfo `json:"attck_predicted_risk,omitempty"`
	ATTACKFailedTechs          []string                 `json:"attck_failed_techniques,omitempty"`
	PrismScore                 float64                  `json:"prism_score,omitempty"`
	PrismExternalRisk          float64                  `json:"prism_external_risk,omitempty"`
	PrismPropRisk              float64                  `json:"prism_prop_risk,omitempty"`
	PrismPropPenalty           float64                  `json:"prism_prop_penalty,omitempty"`
	PrismDebtRaw               float64                  `json:"prism_debt_raw,omitempty"`
	PrismDebtPenalty           float64                  `json:"prism_debt_penalty,omitempty"`
	PrismCollapseModifier      float64                  `json:"prism_collapse_modifier,omitempty"`
	PrismRiskVelocity          float64                  `json:"prism_risk_velocity,omitempty"`
	PrismSemanticState         string                   `json:"prism_semantic_state,omitempty"`
	PrismStateVector           [4]float64               `json:"prism_state_vector,omitempty"`
	PrismStableMem             float64                  `json:"prism_stable_membership,omitempty"`
	PrismDegradedMem           float64                  `json:"prism_degraded_membership,omitempty"`
	PrismUntrustedMem          float64                  `json:"prism_untrusted_membership,omitempty"`
	PrismCollapseMem           float64                  `json:"prism_collapse_membership,omitempty"`
	PrismInferenceTrend        string                   `json:"prism_inference_trend,omitempty"`
	PrismInferenceConfidence   float64                  `json:"prism_inference_confidence,omitempty"`
	PrismInferenceCollapseRisk float64                  `json:"prism_inference_collapse_risk,omitempty"`
	PrismInferenceFutureVector [4]float64               `json:"prism_inference_future_vector,omitempty"`
	PrismInferenceModel        string                   `json:"prism_inference_model,omitempty"`
	PrismInferenceHorizonDays  int                      `json:"prism_inference_horizon_days,omitempty"`
	PrismIR                    json.RawMessage          `json:"prism_ir,omitempty"`
	Checks                     []CheckResult            `json:"checks"`
	Signature                  string                   `json:"signature,omitempty"`
	UncertaintyNote            string                   `json:"uncertainty_note,omitempty"`
	ModelCoverageRatio         float64                  `json:"model_coverage_ratio,omitempty"`
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
