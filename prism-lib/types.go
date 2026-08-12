package prism

// ============================================================
// Input Types
// ============================================================

type NodeState struct {
	HostID       string
	SSAMScore    float64
	FailedChecks []CheckFailure
	Criticality  float64 // 0.0–1.0, 节点重要性权重 (默认 0.5); 被攻陷的关键节点传播更高风险
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

// ============================================================
// Configuration (Core + Semantic + Inference)
// ============================================================

type PrismConfig struct {
	// Core Layer
	DebtAlpha    float64 // 安全债务超线性指数，默认 1.2
	PropCap      float64 // 传播惩罚上限，默认 0.25
	DebtCap      float64 // 债务惩罚上限，默认 0.30
	DebtNormDays float64 // 债务归一化分母（天），默认 1500
	PathDecay    float64 // 路径衰减因子，默认 0.80
	MaxPathDepth int     // 最大搜索深度，默认 5
	ScoreFloor   float64 // 下界稳定项，默认 0.40
	CollapseBeta float64 // 塌缩超线性指数，默认 1.5
	AggregationMode string // 传播聚合模式: "rss"(默认)/"max"/"linear"

	// Semantic Layer
	StableThreshold    float64 // Stable 隶属度上界阈值，默认 0.90
	DegradedThreshold  float64 // Degraded 隶属度上界阈值，默认 0.70
	UntrustedThreshold float64 // Untrusted 隶属度上界阈值，默认 0.50
	// Collapse 阈值由 UntrustedThreshold 下界隐含

	// Inference Layer
	HorizonDays int // 默认预测时间窗口（天），默认 7
}

// ============================================================
// Core Layer Outputs
// ============================================================

// AssetRiskResult is Core Layer output (formerly RawRiskReport).
type AssetRiskResult struct {
	HostID           string  // 节点 ID
	SsamScore        float64 // 原始 SSAM 分数 [0,100]
	PrismScore       float64 // 正交化动态评分 [0,100]
	ExternalRisk     float64 // 本节点外部风险 E(v) ∈ [0,1]
	PropagatedRisk   float64 // 入边传播风险 R_prop ∈ [0,1]
	PropPenalty      float64 // 实际传播惩罚 ∈ [0, Cap_prop]
	DebtRaw          float64 // 未归一化的债务总值
	DebtPenalty      float64 // 归一化后的债务惩罚 ∈ [0, Cap_debt]
	CollapseModifier float64 // 塌缩修正值 ∈ [0,1]
	RiskVelocity     float64 // 风险变化速度（评分/天，负值表示恶化）
}

// RiskSnapshot stores a timestamped score for velocity computation.
type RiskSnapshot struct {
	HostID     string
	PrismScore float64
	Timestamp  int64 // Unix 秒
}

type PathResult struct {
	Path           []string
	CumulativeRisk float64
}

// ============================================================
// Semantic Layer Outputs
// ============================================================

// SemanticRiskReport is Semantic Layer output.
type SemanticRiskReport struct {
	HostID              string     // 节点 ID
	StableMembership    float64    // Stable 隶属度 [0,1]
	DegradedMembership  float64    // Degraded 隶属度 [0,1]
	UntrustedMembership float64    // Untrusted 隶属度 [0,1]
	CollapseMembership  float64    // Collapse 隶属度 [0,1]
	CurrentState        string     // 主导状态: "Stable" / "Degraded" / "Untrusted" / "Collapse"
	StateVector         [4]float64 // 归一化状态向量 [Stable, Degraded, Untrusted, Collapse]
}

// ============================================================
// Inference Layer Outputs
// ============================================================

// InferenceModel is the pluggable state inference model interface.
// Callers can inject custom models; the default is MarkovChainModel.
type InferenceModel interface {
	// Predict returns the future state probability distribution after k steps.
	// Input: current state vector [Stable, Degraded, Untrusted, Collapse]
	// Output: future state vector and confidence [0,1].
	Predict(current [4]float64, steps int) (future [4]float64, confidence float64)
	// Name returns the model identifier for traceability.
	Name() string
}

// FutureRiskReport is Inference Layer output.
type FutureRiskReport struct {
	HostID        string  // 节点 ID
	HorizonDays   int     // 预测时间窗口（天）
	StableProb    float64 // P(Stable) at t+HorizonDays
	DegradedProb  float64 // P(Degraded) at t+HorizonDays
	UntrustedProb float64 // P(Untrusted) at t+HorizonDays
	CollapseProb  float64 // P(Collapse) at t+HorizonDays
	Confidence    float64 // 预测置信度 [0,1]
	Trend         string  // "improving" / "stable" / "degrading" / "collapsing"
	CollapseRisk  float64 // P(Untrusted) + P(Collapse)
}
