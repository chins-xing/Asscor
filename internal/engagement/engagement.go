package engagement

import (
	"sort"
	"time"

	"github.com/asscor/asscor/internal/attackerstate"
	"github.com/asscor/asscor/internal/predictor"
)

// 引导/欺骗干预引擎 — 主动防御白皮书 Phase 4（§5.5 Engagement Planner +
// §5.6 诱饵传感器化 + §8 诱饵映射复用）
//
// 从"根据意图部署诱饵"升级为"选择最大化新情报获取量的干预"：
//
//	Utility(E) = α·IG(E) + β·DP(E) + γ·AV(E) − δ·Risk(E)
//
// IG=Information Gain（针对高概率动作 → 情报增益高）；DP=Detection
// Probability（诱饵固有检测能力）；AV=Attribution Value（归因价值）；
// Risk=暴露风险（部署成本 × 被识破/误伤概率）。
//
// 诱饵映射（§8 保留）：横向移动→假SSH、凭据窃取→假凭据、数据窃取→假
// 文档、Web攻击→假Web、扫描探测→扫描端口。
//
// 原则（§1.2 轻量欺骗 + §3.5）：诱饵只需制造"突破口假象"（够用原则），
// 不追求高逼真蜜凭证；本引擎只做可解释的效用排序，不宣称欺骗必然成功。

// DecoyType 是诱饵类型（§8 五类映射）。
type DecoyType string

const (
	DecoyFakeSSH       DecoyType = "fake_ssh"        // 横向移动诱饵
	DecoyFakeCredential DecoyType = "fake_credential" // 凭据窃取诱饵
	DecoyFakeDocument  DecoyType = "fake_document"   // 数据窃取诱饵
	DecoyFakeWeb       DecoyType = "fake_web"        // Web 攻击诱饵
	DecoyScanPort      DecoyType = "scan_port"       // 扫描探测诱饵
)

// Intervention 是一次引导干预（§5.6 Deception Object = Sensor + Control
// Point）：诱饵类型 + 针对动作 + 控制点 + 成本/暴露。
type Intervention struct {
	ID           string
	Decoy        DecoyType
	TargetAction predictor.Action // 针对的攻击者动作（§8 映射）
	ControlPoint string           // 控制点（部署位置/假服务标识）
	Cost         float64          // 部署成本 [0,1]
	Exposure     float64          // 暴露风险 [0,1]（被识破/误伤业务）
}

// PlannerParams 是效用权重（§5.5: U = α·IG + β·DP + γ·AV − δ·Risk）。
type PlannerParams struct {
	Alpha float64 // IG 权重 (信息增益)
	Beta  float64 // DP 权重 (检测概率)
	Gamma float64 // AV 权重 (归因价值)
	Delta float64 // Risk 权重 (暴露风险)
}

// DefaultParams returns balanced utility weights.
func DefaultParams() PlannerParams {
	return PlannerParams{Alpha: 1.0, Beta: 0.8, Gamma: 0.6, Delta: 1.2}
}

// ScoredIntervention 是排序后的干预（含效用分解）。
type ScoredIntervention struct {
	Intervention
	Utility  float64
	IG       float64 // Information Gain
	DP       float64 // Detection Probability
	AV       float64 // Attribution Value
	Risk     float64 // 暴露风险
}

// Planner 选择最大化情报获取的干预。
type Planner struct {
	Params  PlannerParams
	Catalog []Intervention // 候选干预目录
}

// NewPlanner builds a planner with the default decoy catalog (§8 映射)。
func NewPlanner(params PlannerParams) *Planner {
	catalog := []Intervention{
		{ID: "decoy-ssh", Decoy: DecoyFakeSSH, TargetAction: predictor.ActionLateral, ControlPoint: "tcp/22", Cost: 0.3, Exposure: 0.2},
		{ID: "decoy-cred", Decoy: DecoyFakeCredential, TargetAction: predictor.ActionCredential, ControlPoint: "fake-credentials", Cost: 0.2, Exposure: 0.15},
		{ID: "decoy-doc", Decoy: DecoyFakeDocument, TargetAction: predictor.ActionDataTheft, ControlPoint: "share/fake-docs", Cost: 0.2, Exposure: 0.15},
		{ID: "decoy-web", Decoy: DecoyFakeWeb, TargetAction: predictor.ActionWebAttack, ControlPoint: "fake-app:8080", Cost: 0.4, Exposure: 0.3},
		{ID: "decoy-scan", Decoy: DecoyScanPort, TargetAction: predictor.ActionRecon, ControlPoint: "tcp/8081", Cost: 0.1, Exposure: 0.1},
	}
	return &Planner{Params: params, Catalog: catalog}
}

// Select ranks catalog interventions by utility given the predicted action
// distribution (§5.5)。Returns interventions with Utility > 0, descending。
func (p *Planner) Select(dist predictor.ActionDistribution, target predictor.TargetState) []ScoredIntervention {
	scored := make([]ScoredIntervention, 0, len(p.Catalog))
	for _, inv := range p.Catalog {
		prob := dist.Probabilities[inv.TargetAction]

		// IG: 针对动作概率 × 覆盖系数（脆弱目标覆盖更高）。
		coverage := 0.5 + 0.5*((100.0-target.SSAMScore)/100.0+target.Exposure)/2
		ig := prob * coverage

		// DP: 诱饵固有检测能力（诱饵类型 → 检测率）。
		dp := decoyDetection[inv.Decoy]

		// AV: 归因价值（诱饵类型 → 捕获归因信息量）。
		av := decoyAttribution[inv.Decoy]

		// Risk: 成本 × 暴露。
		risk := inv.Cost * inv.Exposure

		utility := p.Params.Alpha*ig + p.Params.Beta*dp + p.Params.Gamma*av - p.Params.Delta*risk
		if utility <= 0 {
			continue
		}
		scored = append(scored, ScoredIntervention{
			Intervention: inv,
			Utility:      round4(utility),
			IG:           round4(ig),
			DP:           dp,
			AV:           av,
			Risk:         round4(risk),
		})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].Utility == scored[j].Utility {
			return scored[i].ID < scored[j].ID
		}
		return scored[i].Utility > scored[j].Utility
	})
	return scored
}

// decoyDetection 是各诱饵的固有检测概率 (DP)。
var decoyDetection = map[DecoyType]float64{
	DecoyFakeSSH:       0.9, // 假 SSH 交互链完整, 检测率高
	DecoyFakeCredential: 0.8,
	DecoyFakeDocument:  0.75,
	DecoyFakeWeb:       0.7,
	DecoyScanPort:      0.85,
}

// decoyAttribution 是各诱饵的归因价值 (AV, [0,1])。
var decoyAttribution = map[DecoyType]float64{
	DecoyFakeSSH:       0.6, // 命令交互捕获归因
	DecoyFakeCredential: 0.9, // 账号/凭据尝试 → 高归因
	DecoyFakeDocument:  0.85, // 数据窃取意图 → 高归因
	DecoyFakeWeb:       0.5,
	DecoyScanPort:      0.3, // 扫描仅探测 → 低归因
}

// DeceptionRecord 是诱饵交互链记录（§5.6 诱饵传感器化：连接→尝试账号→
// 尝试凭据→执行命令→系统发现→连接其他服务）。
type DeceptionRecord struct {
	Decoy             DecoyType
	Timestamp         time.Time
	InteractionType   string // connect | credential_attempt | command | system_discovery | follow_up
	CredentialAttempt string
	Command           string
	Sequence          int
	FollowUpAction    string
	TTP               string
	Outcome           string
	Confidence        float64
}

// ToEvidence converts the record into attacker-state evidence（反馈到
// State Engine：诱饵触发 = 新情报 → 状态更新，§5.1 攻击者认知闭环）。
// TTP/Intent 由调用方按交互链推断；这里保守起见仅当有 TTP 时带意图。
func (r DeceptionRecord) ToEvidence() attackerstate.Evidence {
	ev := attackerstate.Evidence{
		Source:     "decoy:" + string(r.Decoy),
		SourceType: "decoy_trigger",
		At:         r.Timestamp,
		Target:     r.FollowUpAction,
		Outcome:    r.Outcome,
		Confidence: r.Confidence,
		TTP:        r.TTP,
	}
	return ev
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000
}
