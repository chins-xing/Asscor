package model

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

type ATTACKConfig struct {
	Enabled              bool
	Version              string
	AutoHunt             bool
	BeaconThreshold      float64
	AttributionThreshold float64
	SafeEmulation        bool
}
