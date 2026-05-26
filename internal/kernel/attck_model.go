package kernel

import (
	"time"
)

type DetectionRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	TechniqueID string            `json:"technique_id"`
	TacticIDs   []string          `json:"tactic_ids"`
	Severity    string            `json:"severity"`
	LogSources  []string          `json:"log_sources"`
	Query       string            `json:"query"`
	Enabled     bool              `json:"enabled"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type DetectionAlert struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	TechniqueID string            `json:"technique_id"`
	TacticIDs   []string          `json:"tactic_ids"`
	Severity    string            `json:"severity"`
	HostID      string            `json:"host_id"`
	Description string            `json:"description"`
	RawLog      string            `json:"raw_log,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	Status      string            `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Acknowledged bool             `json:"acknowledged"`
}

type AnomalyEvent struct {
	ID          string            `json:"id"`
	HostID      string            `json:"host_id"`
	EventType   string            `json:"event_type"`
	Description string            `json:"description"`
	TechniqueID string            `json:"technique_id,omitempty"`
	Score       float64           `json:"score"`
	Baseline    float64           `json:"baseline"`
	Deviation   float64           `json:"deviation"`
	Fields      map[string]string `json:"fields,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

type CorrelationResult struct {
	ID           string            `json:"id"`
	AlertIDs     []string          `json:"alert_ids"`
	TechniqueIDs []string          `json:"technique_ids"`
	TacticIDs    []string          `json:"tactic_ids"`
	Score        float64           `json:"score"`
	Description  string            `json:"description"`
	AttackPhase  string            `json:"attack_phase"`
	IsKillChain  bool              `json:"is_kill_chain"`
	Fields       map[string]string `json:"fields,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

type DetectionSummary struct {
	TotalRules       int                    `json:"total_rules"`
	ActiveRules      int                    `json:"active_rules"`
	TotalAlerts      int                    `json:"total_alerts"`
	OpenAlerts       int                    `json:"open_alerts"`
	AlertsBySeverity map[string]int         `json:"alerts_by_severity"`
	AlertsByTactic   map[string]int         `json:"alerts_by_tactic"`
	AlertsByTechnique map[string]int        `json:"alerts_by_technique"`
	Anomalies        int                    `json:"anomalies"`
	Correlations     int                    `json:"correlations"`
	TopAlertHosts    []string               `json:"top_alert_hosts"`
	CoverageGaps     []string               `json:"coverage_gaps"`
}

type IOCEntry struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	Source      string            `json:"source"`
	TechniqueIDs []string         `json:"technique_ids,omitempty"`
	TacticIDs   []string          `json:"tactic_ids,omitempty"`
	ThreatActor string            `json:"threat_actor,omitempty"`
	Confidence  float64           `json:"confidence"`
	Tags        []string          `json:"tags,omitempty"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ThreatActorProfile struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Aliases        []string          `json:"aliases"`
	Description    string            `json:"description"`
	Country        string            `json:"country,omitempty"`
	Motivation     string            `json:"motivation,omitempty"`
	TargetSectors  []string          `json:"target_sectors"`
	Techniques     map[string]float64 `json:"techniques"`
	Software       []string          `json:"software,omitempty"`
	Campaigns      []CampaignInfo    `json:"campaigns,omitempty"`
	IOCs           []IOCEntry        `json:"iocs,omitempty"`
	MISPGalaxyID   string            `json:"misp_galaxy_id,omitempty"`
	LastUpdated    time.Time         `json:"last_updated"`
}

type CampaignInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date,omitempty"`
	Techniques  []string  `json:"techniques"`
	Targets     []string  `json:"targets"`
}

type TTPTrack struct {
	ID          string    `json:"id"`
	TechniqueID string    `json:"technique_id"`
	TacticID    string    `json:"tactic_id"`
	ActorID     string    `json:"actor_id,omitempty"`
	CampaignID  string    `json:"campaign_id,omitempty"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type EmulationScenario struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ActorProfile string           `json:"actor_profile,omitempty"`
	Objective   string            `json:"objective"`
	Phases      []EmulationPhase  `json:"phases"`
	Tags        []string          `json:"tags,omitempty"`
	Difficulty  string            `json:"difficulty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type EmulationPhase struct {
	Order        int              `json:"order"`
	Name         string           `json:"name"`
	TacticID     string           `json:"tactic_id"`
	TechniqueID  string           `json:"technique_id"`
	Description  string           `json:"description"`
	Commands     []EmulationCommand `json:"commands"`
	ExpectedDetections []string   `json:"expected_detections"`
	RiskLevel    string           `json:"risk_level"`
}

type EmulationCommand struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Platform    string            `json:"platform"`
	Executor    string            `json:"executor"`
	Command     string            `json:"command"`
	Cleanup     string            `json:"cleanup,omitempty"`
	Timeout     int               `json:"timeout,omitempty"`
	SafeMode    bool              `json:"safe_mode"`
	Params      map[string]string `json:"params,omitempty"`
}

type EmulationResult struct {
	ScenarioID       string             `json:"scenario_id"`
	HostID           string             `json:"host_id"`
	Status           string             `json:"status"`
	PhaseResults     []EmulationPhaseResult `json:"phase_results"`
	TotalTechniques  int                `json:"total_techniques"`
	DetectedCount    int                `json:"detected_count"`
	MissedCount      int                `json:"missed_count"`
	DetectionRate    float64            `json:"detection_rate"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
	Duration         time.Duration      `json:"duration"`
	Recommendations  []string           `json:"recommendations,omitempty"`
}

type EmulationPhaseResult struct {
	PhaseOrder       int       `json:"phase_order"`
	TechniqueID      string    `json:"technique_id"`
	Status           string    `json:"status"`
	Detected         bool      `json:"detected"`
	DetectionRuleID  string    `json:"detection_rule_id,omitempty"`
	DetectionDelay   time.Duration `json:"detection_delay,omitempty"`
	ExecutionOutput  string    `json:"execution_output,omitempty"`
	Error            string    `json:"error,omitempty"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
}

type ControlGap struct {
	TechniqueID   string  `json:"technique_id"`
	TechniqueName string  `json:"technique_name"`
	TacticID      string  `json:"tactic_id"`
	TacticName    string  `json:"tactic_name"`
	GapType       string  `json:"gap_type"`
	Severity      string  `json:"severity"`
	Description   string  `json:"description"`
	CurrentState  string  `json:"current_state,omitempty"`
	DesiredState  string  `json:"desired_state,omitempty"`
	Score         float64 `json:"score"`
}

type ControlMapping struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	TacticID      string   `json:"tactic_id"`
	AsscorChecks   []string `json:"asscor_checks"`
	DetectionRules []string `json:"detection_rules"`
	Mitigations   []Mitigation `json:"mitigations"`
	CoverageLevel string   `json:"coverage_level"`
	Score         float64  `json:"score"`
}

type Mitigation struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Effectiveness float64 `json:"effectiveness"`
	AsscorCheck  string   `json:"asscor_check,omitempty"`
}

type AssessmentReport struct {
	ID              string          `json:"id"`
	HostID          string          `json:"host_id"`
	Framework       string          `json:"framework"`
	Version         string          `json:"version"`
	TotalTechniques int             `json:"total_techniques"`
	CoveredTechs    int             `json:"covered_techs"`
	CoverageRate    float64         `json:"coverage_rate"`
	Gaps            []ControlGap    `json:"gaps"`
	ControlMaps     []ControlMapping `json:"control_maps"`
	Recommendations []Recommendation `json:"recommendations"`
	Score           float64         `json:"score"`
	AssessmentTime  time.Time       `json:"assessment_time"`
}

type Recommendation struct {
	ID          string   `json:"id"`
	Priority    string   `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	TechniqueIDs []string `json:"technique_ids"`
	Effort      string   `json:"effort"`
	Impact      string   `json:"impact"`
	Status      string   `json:"status"`
}

type ImprovementTrack struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	StartDate      time.Time    `json:"start_date"`
	TargetDate     time.Time    `json:"target_date"`
	BaselineScore  float64      `json:"baseline_score"`
	CurrentScore   float64      `json:"current_score"`
	TargetScore    float64      `json:"target_score"`
	Actions        []ImprovementAction `json:"actions"`
	Status         string       `json:"status"`
	LastUpdated    time.Time    `json:"last_updated"`
}

type ImprovementAction struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	TechniqueIDs []string `json:"technique_ids"`
	Status      string    `json:"status"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type AttackChain struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	HostIDs      []string        `json:"host_ids"`
	Stages       []AttackStage   `json:"stages"`
	TotalScore   float64         `json:"total_score"`
	Severity     string          `json:"severity"`
	Attribution  *AttributionResult `json:"attribution,omitempty"`
	Status       string          `json:"status"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	DetectedAt   time.Time       `json:"detected_at"`
}

type AttackStage struct {
	Order        int       `json:"order"`
	TacticID     string    `json:"tactic_id"`
	TacticName   string    `json:"tactic_name"`
	TechniqueID  string    `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	AlertIDs     []string  `json:"alert_ids"`
	HostIDs      []string  `json:"host_ids"`
	IOCIDs       []string  `json:"ioc_ids,omitempty"`
	AnomalyIDs   []string  `json:"anomaly_ids,omitempty"`
	Confidence   float64   `json:"confidence"`
	Evidence     []string  `json:"evidence"`
	Timestamp    time.Time `json:"timestamp"`
}

type AttributionResult struct {
	PrimaryActor   string              `json:"primary_actor"`
	PrimaryGroupID string              `json:"primary_group_id"`
	Confidence     float64             `json:"confidence"`
	Evidence       []AttributionEvidence `json:"evidence"`
	AlternativeActors []AlternativeActor `json:"alternative_actors"`
	Methodology    string              `json:"methodology"`
	Country        string              `json:"country,omitempty"`
	Motivation     string              `json:"motivation,omitempty"`
}

type AttributionEvidence struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Source      string  `json:"source"`
}

type AlternativeActor struct {
	GroupID    string  `json:"group_id"`
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type BehavioralBaseline struct {
	HostID      string             `json:"host_id"`
	Metrics     map[string]float64 `json:"metrics"`
	SampleCount int                `json:"sample_count"`
	Period      time.Duration      `json:"period"`
	ComputedAt  time.Time          `json:"computed_at"`
}

type BehavioralIndicator struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	TechniqueID string            `json:"technique_id"`
	TacticIDs   []string          `json:"tactic_ids"`
	Category    string            `json:"category"`
	Metric      string            `json:"metric"`
	Operator    string            `json:"operator"`
	Threshold   float64           `json:"threshold"`
	Window      time.Duration     `json:"window"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
}

type BehavioralAlert struct {
	ID           string            `json:"id"`
	IndicatorID  string            `json:"indicator_id"`
	IndicatorName string           `json:"indicator_name"`
	TechniqueID  string            `json:"technique_id"`
	HostID       string            `json:"host_id"`
	ObservedValue float64          `json:"observed_value"`
	BaselineValue float64          `json:"baseline_value"`
	Deviation    float64           `json:"deviation"`
	Severity     string            `json:"severity"`
	Fields       map[string]string `json:"fields,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type BeaconDetection struct {
	ID            string    `json:"id"`
	HostID        string    `json:"host_id"`
	Destination   string    `json:"destination"`
	Interval      float64   `json:"interval_seconds"`
	Jitter        float64   `json:"jitter"`
	Score         float64   `json:"score"`
	TechniqueID   string    `json:"technique_id"`
	DataPoints    int       `json:"data_points"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type HuntHypothesis struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TechniqueID string   `json:"technique_id"`
	TacticIDs   []string `json:"tactic_ids"`
	DataSource  string   `json:"data_source"`
	Query       string   `json:"query"`
	Priority    string   `json:"priority"`
	Status      string   `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type HuntResult struct {
	ID           string            `json:"id"`
	HypothesisID string            `json:"hypothesis_id"`
	HostID       string            `json:"host_id"`
	Findings     []HuntFinding     `json:"findings"`
	Confirmed    bool              `json:"confirmed"`
	Confidence   float64           `json:"confidence"`
	Timestamp    time.Time         `json:"timestamp"`
}

type HuntFinding struct {
	Description string            `json:"description"`
	TechniqueID string            `json:"technique_id"`
	Evidence    string            `json:"evidence"`
	Fields      map[string]string `json:"fields,omitempty"`
}

type APTAnalysisReport struct {
	ID              string            `json:"id"`
	HostIDs         []string          `json:"host_ids"`
	AttackChains    []AttackChain     `json:"attack_chains"`
	Attributions    []AttributionResult `json:"attributions"`
	BehavioralAlerts []BehavioralAlert `json:"behavioral_alerts"`
	BeaconDetections []BeaconDetection `json:"beacon_detections"`
	HuntResults     []HuntResult      `json:"hunt_results"`
	RiskScore       float64           `json:"risk_score"`
	RiskLevel       string            `json:"risk_level"`
	Summary         string            `json:"summary"`
	Recommendations []string          `json:"recommendations"`
	Timestamp       time.Time         `json:"timestamp"`
}

type MultiIndicatorCorrelation struct {
	ID            string   `json:"id"`
	IndicatorIDs  []string `json:"indicator_ids"`
	TechniqueIDs  []string `json:"technique_ids"`
	TacticIDs     []string `json:"tactic_ids"`
	HostIDs       []string `json:"host_ids"`
	Score         float64  `json:"score"`
	Description   string   `json:"description"`
	CorrelationType string `json:"correlation_type"`
	Timestamp     time.Time `json:"timestamp"`
}
