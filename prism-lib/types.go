package prism

type NodeState struct {
	HostID       string
	SSAMScore    float64
	FailedChecks []CheckFailure
}

type CheckFailure struct {
	CheckID  string
	Delta    float64
	FailUnix int64
}

type EdgeState struct {
	Source           string
	Target           string
	RiskTransmission float64
}

type PrismConfig struct {
	DebtAlpha     float64
	PropCap       float64
	DebtCap       float64
	DebtNormDays  float64
	PathDecay     float64
	MaxPathDepth  int
	ScoreFloor    float64
}

type AssetRiskResult struct {
	HostID         string
	SsamScore      float64
	PrismScore     float64
	ExternalRisk   float64
	PropagatedRisk float64
	PropPenalty    float64
	DebtRaw        float64
	DebtPenalty    float64
}

type PathResult struct {
	Path           []string
	CumulativeRisk float64
}
