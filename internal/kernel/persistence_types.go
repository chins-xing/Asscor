package kernel

import (
	"encoding/json"
	"time"

	"github.com/asscor/asscor/internal/model"
)

// PrismResultFields holds the Prism engine output fields shared by AssessmentRecord and DashboardReport.
type PrismResultFields struct {
	PrismScore             float64         `json:"prism_score,omitempty"`
	PrismPropRisk          float64         `json:"prism_prop_risk,omitempty"`
	PrismDebtRaw           float64         `json:"prism_debt_raw,omitempty"`
	PrismExternalRisk      float64         `json:"prism_external_risk,omitempty"`
	PrismPropPenalty       float64         `json:"prism_prop_penalty,omitempty"`
	PrismDebtPenalty       float64         `json:"prism_debt_penalty,omitempty"`
	PrismCollapseModifier  float64         `json:"prism_collapse_modifier,omitempty"`
	PrismRiskVelocity      float64         `json:"prism_risk_velocity,omitempty"`
	PrismSemanticState     string          `json:"prism_semantic_state,omitempty"`
	PrismStateVector       [4]float64      `json:"prism_state_vector,omitempty"`
	PrismStableMem         float64         `json:"prism_stable_membership,omitempty"`
	PrismDegradedMem       float64         `json:"prism_degraded_membership,omitempty"`
	PrismUntrustedMem      float64         `json:"prism_untrusted_membership,omitempty"`
	PrismCollapseMem       float64         `json:"prism_collapse_membership,omitempty"`
	PrismInferenceTrend        string      `json:"prism_inference_trend,omitempty"`
	PrismInferenceConfidence   float64     `json:"prism_inference_confidence,omitempty"`
	PrismInferenceCollapseRisk float64     `json:"prism_inference_collapse_risk,omitempty"`
	PrismInferenceFutureVector [4]float64  `json:"prism_inference_future_vector,omitempty"`
	PrismInferenceModel        string      `json:"prism_inference_model,omitempty"`
	PrismInferenceHorizonDays  int         `json:"prism_inference_horizon_days,omitempty"`
	PrismIR                    json.RawMessage `json:"prism_ir,omitempty"`
}

// PrismFieldsFromResult populates PrismResultFields from an AssessmentResult.
func PrismFieldsFromResult(ar *model.AssessmentResult) PrismResultFields {
	return PrismResultFields{
		PrismScore:                ar.PrismScore,
		PrismPropRisk:             ar.PrismPropRisk,
		PrismDebtRaw:              ar.PrismDebtRaw,
		PrismExternalRisk:         ar.PrismExternalRisk,
		PrismPropPenalty:          ar.PrismPropPenalty,
		PrismDebtPenalty:          ar.PrismDebtPenalty,
		PrismCollapseModifier:     ar.PrismCollapseModifier,
		PrismRiskVelocity:         ar.PrismRiskVelocity,
		PrismSemanticState:        ar.PrismSemanticState,
		PrismStateVector:          ar.PrismStateVector,
		PrismStableMem:            ar.PrismStableMem,
		PrismDegradedMem:          ar.PrismDegradedMem,
		PrismUntrustedMem:         ar.PrismUntrustedMem,
		PrismCollapseMem:          ar.PrismCollapseMem,
		PrismInferenceTrend:        ar.PrismInferenceTrend,
		PrismInferenceConfidence:   ar.PrismInferenceConfidence,
		PrismInferenceCollapseRisk: ar.PrismInferenceCollapseRisk,
		PrismInferenceFutureVector: ar.PrismInferenceFutureVector,
		PrismInferenceModel:        ar.PrismInferenceModel,
		PrismInferenceHorizonDays:  ar.PrismInferenceHorizonDays,
		PrismIR:                    ar.PrismIR,
	}
}

type AssessmentRecord struct {
	Timestamp       time.Time         `json:"timestamp"`
	HostID          string            `json:"host_id"`
	Hostname        string            `json:"hostname,omitempty"`
	FinalScore      float64           `json:"final_score"`
	Threshold       float64           `json:"threshold,omitempty"`
	Acceptable      bool              `json:"acceptable"`
	AttackSurface   float64           `json:"attack_surface"`
	BusinessCont    float64           `json:"business_continuity"`
	OperationTrust  float64           `json:"operation_trust"`
	Resilience      float64           `json:"resilience"`
	KernelSecurity  float64           `json:"kernel_security,omitempty"`
	ExtraScores     map[string]float64 `json:"extra_scores,omitempty"`
	TwoFactorFail   float64           `json:"two_factor_failure"`
	SYNCookieDis    float64           `json:"syn_cookie_disabled,omitempty"`
	SELinuxDis      float64           `json:"selinux_disabled,omitempty"`
	AppArmorDis     float64           `json:"apparmor_disabled,omitempty"`
	NoSIEM          float64           `json:"no_siem,omitempty"`
	NoIDS           float64           `json:"no_ids,omitempty"`
	ThreatCoeff     float64           `json:"threat_coefficient"`
	SPCScore        float64           `json:"spc_score,omitempty"`
	PrismResultFields
	SPCCVEs          []model.SPCCVEInfo     `json:"spc_cves,omitempty"`
	DomainWeightShift map[string]float64    `json:"domain_weight_shift,omitempty"`
	CheckCount       int                    `json:"check_count"`
	FailedCount      int                    `json:"failed_count"`
	Checks           []CheckDetail          `json:"checks,omitempty"`
	ATTACKCoverage      []model.ATTACKCoverageInfo    `json:"attck_coverage,omitempty"`
	ATTACKKillChain     *model.ATTACKKillChainInfo     `json:"attck_kill_chain,omitempty"`
	ATTACKAPTMatches    []model.ATTACKAPTMatchInfo     `json:"attck_apt_matches,omitempty"`
	ATTACKPredictedRisk *model.ATTACKPredictedRiskInfo `json:"attck_predicted_risk,omitempty"`
	ATTACKFailedTechs   []string                       `json:"attck_failed_techniques,omitempty"`
}

type CheckDetail struct {
	CheckID       string  `json:"check_id"`
	Domain        string  `json:"domain"`
	Name          string  `json:"name"`
	Passed        bool    `json:"passed"`
	Delta         float64 `json:"delta"`
	Detail        string  `json:"detail"`
	ComplianceRef string  `json:"compliance_ref,omitempty"`
}

type DashboardReport struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	HostID        string            `json:"host_id"`
	Hostname      string            `json:"hostname"`
	Framework     string            `json:"framework"`
	SSAMVersion   string            `json:"ssam_version"`

	FinalScore float64 `json:"final_score"`
	Threshold  float64 `json:"threshold"`
	Acceptable bool    `json:"acceptable"`

	DomainScores  map[string]float64 `json:"domain_scores"`
	DomainWeights map[string]float64 `json:"domain_weights"`

	EdgeFactors map[string]float64 `json:"edge_factors"`
	ThreatCoeff float64            `json:"threat_coefficient"`
	SPCScore    float64            `json:"spc_score"`

	PrismResultFields
	SPCCVEs            []model.SPCCVEInfo `json:"spc_cves,omitempty"`
	DomainWeightShift  map[string]float64 `json:"domain_weight_shift,omitempty"`

	Summary struct {
		TotalChecks  int `json:"total_checks"`
		PassedChecks int `json:"passed_checks"`
		FailedChecks int `json:"failed_checks"`
	} `json:"summary"`

	Checks []CheckDetail `json:"checks"`

	ATTACKCoverage      []model.ATTACKCoverageInfo    `json:"attck_coverage,omitempty"`
	ATTACKKillChain     *model.ATTACKKillChainInfo     `json:"attck_kill_chain,omitempty"`
	ATTACKAPTMatches    []model.ATTACKAPTMatchInfo     `json:"attck_apt_matches,omitempty"`
	ATTACKPredictedRisk *model.ATTACKPredictedRiskInfo `json:"attck_predicted_risk,omitempty"`
	ATTACKFailedTechs   []string                       `json:"attck_failed_techniques,omitempty"`

	ComplianceFramework string `json:"compliance_framework,omitempty"`
}

type AgentRegistrationRecord struct {
	Timestamp time.Time `json:"timestamp"`
	HostID    string    `json:"host_id"`
	Hostname  string    `json:"hostname"`
	Version   string    `json:"version"`
	Event     string    `json:"event"`
}

type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Target    string                 `json:"target"`
	Detail    map[string]interface{} `json:"detail"`
	Success   bool                   `json:"success"`
}

type CommandRecord struct {
	Timestamp time.Time         `json:"timestamp"`
	CommandID string            `json:"command_id"`
	HostID    string            `json:"host_id"`
	Command   string            `json:"command"`
	Params    map[string]string `json:"params"`
	Status    string            `json:"status"`
	Signature string            `json:"signature"`
}

type CVECacheRecord struct {
	Timestamp  time.Time              `json:"timestamp"`
	TotalCount int                    `json:"total_count"`
	HighCount  int                    `json:"high_count"`
	KEVCount   int                    `json:"kev_count"`
	TopCVEs    []string               `json:"top_cves"`
	Sources    map[string]interface{} `json:"sources"`
}
