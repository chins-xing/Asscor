package predictor

import (
	"math"
	"sort"

	"github.com/asscor/asscor/internal/attackerstate"
)

// 行动预测引擎 — 主动防御白皮书 Phase 3（§4 Prediction: Action Distribution）
//
// 预测目标（§4.2）:
//
//	P(A_{t+1} | AttackerState_t, TargetState_t, Observation_t)
//
// 而非确定性 NextTTP。初期规则 + 权重（§4.1 不追求确定性预测；§3.5 不把
// 假设写成结论——输出是概率分布，不是事实断言）。
//
// 多输出（§4.2）: Most Likely / Most Dangerous / Most Observable + 降序。
// 两层模型（§4.3）: Attacker State → Action Distribution → TTP Distribution
// （ATT&CK 作为攻击行为语义层，不被替代）。

// Action 是候选行动（白皮书 Intent 五类 + 状态维持）。
type Action string

const (
	ActionRecon      Action = "recon"       // 侦察
	ActionCredential Action = "credential"  // 凭据获取
	ActionLateral    Action = "lateral"     // 横向移动
	ActionDataTheft  Action = "data_theft"  // 数据窃取
	ActionWebAttack  Action = "web_attack"  // Web 攻击
	ActionMaintain   Action = "maintain"    // 状态维持/潜伏
)

// AllActions returns the candidate action space (stable order).
func AllActions() []Action {
	return []Action{ActionRecon, ActionCredential, ActionLateral, ActionDataTheft, ActionWebAttack, ActionMaintain}
}

// TargetState 是目标资产状态（预测的 TargetState_t 输入）。
type TargetState struct {
	ID        string
	SSAMScore float64 // 资产安全分数 (低=脆弱)
	Exposure  float64 // 暴露面 [0,1]
	Zone      string
}

// ActionDistribution 是预测输出（§4.2 多输出）。
type ActionDistribution struct {
	Probabilities  map[Action]float64 // 归一化概率
	MostLikely     Action
	MostDangerous  Action
	MostObservable Action
	Ranked         []Action // 按概率降序
}

// Engine 是预测引擎（规则 + 权重 + softmax）。
type Engine struct {
	Temperature  float64           // softmax 温度 (低=尖锐, 高=平滑)
	DangerWeight map[Action]float64 // 危险度权重 (MostDangerous)
}

// NewEngine creates a prediction engine with default rules.
func NewEngine() *Engine {
	return &Engine{
		Temperature: 1.0,
		DangerWeight: map[Action]float64{
			ActionDataTheft: 1.0, ActionLateral: 0.8, ActionCredential: 0.6,
			ActionWebAttack: 0.5, ActionRecon: 0.3, ActionMaintain: 0.2,
		},
	}
}

// actionBase is the baseline weight of each action (common-path prior).
var actionBase = map[Action]float64{
	ActionRecon:      1.0,
	ActionCredential: 1.2,
	ActionLateral:    1.1,
	ActionDataTheft:  0.9,
	ActionWebAttack:  1.0,
	ActionMaintain:   0.5,
}

// intentOfAction maps an action to its attacker intent (continuity bias).
func intentOfAction(a Action) attackerstate.Intent {
	switch a {
	case ActionRecon:
		return attackerstate.IntentRecon
	case ActionCredential:
		return attackerstate.IntentCredential
	case ActionLateral:
		return attackerstate.IntentLateral
	case ActionDataTheft:
		return attackerstate.IntentDataTheft
	case ActionWebAttack:
		return attackerstate.IntentWebAttack
	default:
		return attackerstate.IntentUnknown
	}
}

// Predict computes the action distribution (规则 + 权重, §4.2)。
//
// 可解释规则:
//  1. 基础权重 (常见路径先验);
//  2. 意图延续: 当前 Intent 对应动作加权 (+1.5);
//  3. 经验: 高经验偏向执行类高级动作 (Lateral/DataTheft +exp, Recon −exp);
//  4. 目标知识: 高知识偏向执行类 (Credential/Lateral/DataTheft +kn);
//  5. AI 依赖: 高依赖偏向常见攻击向量 (Credential/WebAttack +ai, Recon −ai);
//  6. 目标脆弱性: 低 SSAM 分数/高暴露 → 执行类动作加权。
func (e *Engine) Predict(state attackerstate.AttackerState, target TargetState) ActionDistribution {
	scores := make(map[Action]float64, len(AllActions()))
	for _, a := range AllActions() {
		s := actionBase[a]
		// 规则 2: 意图延续。
		if intentOfAction(a) == state.Intent {
			s += 1.5
		}
		// 规则 3: 经验。
		switch a {
		case ActionLateral, ActionDataTheft:
			s += state.Experience
		case ActionRecon:
			s -= state.Experience * 0.5
		}
		// 规则 4: 目标知识。
		switch a {
		case ActionCredential, ActionLateral, ActionDataTheft:
			s += state.TargetKnowledge
		}
		// 规则 5: AI 依赖。
		switch a {
		case ActionCredential, ActionWebAttack:
			s += state.AIDependence
		case ActionRecon:
			s -= state.AIDependence * 0.5
		}
		// 规则 6: 目标脆弱性。
		vuln := (100.0-target.SSAMScore)/100.0 + target.Exposure
		switch a {
		case ActionCredential, ActionLateral, ActionDataTheft, ActionWebAttack:
			s += vuln * 0.8
		}
		if s < 0 {
			s = 0
		}
		scores[a] = s
	}

	probs := softmax(scores, e.Temperature)

	// Most Likely / Most Dangerous / Ranked。
	ranked := make([]Action, 0, len(probs))
	for a := range probs {
		ranked = append(ranked, a)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if probs[ranked[i]] == probs[ranked[j]] {
			return ranked[i] < ranked[j]
		}
		return probs[ranked[i]] > probs[ranked[j]]
	})

	mostLikely := ranked[0]
	mostDangerous := mostLikely
	bestDanger := 0.0
	for _, a := range ranked {
		d := probs[a] * e.DangerWeight[a]
		if d > bestDanger {
			bestDanger = d
			mostDangerous = a
		}
	}
	// Most Observable: 诱饵最容易捕获的动作 (执行类)。
	mostObservable := ActionRecon
	if probs[ActionCredential] >= probs[ActionRecon] {
		mostObservable = ActionCredential
	}
	if probs[ActionLateral] > probs[mostObservable] {
		mostObservable = ActionLateral
	}

	return ActionDistribution{
		Probabilities:  probs,
		MostLikely:     mostLikely,
		MostDangerous:  mostDangerous,
		MostObservable: mostObservable,
		Ranked:         ranked,
	}
}

// TTPDistribution maps the action distribution onto the ATT&CK TTP layer
// (两层模型 §4.3: P(TTP_i) = Σ_j P(TTP_i|Action_j) P(Action_j))。
// 同一 action 下各 TTP 均匀分配该 action 的概率。
func (e *Engine) TTPDistribution(dist ActionDistribution) map[string]float64 {
	out := make(map[string]float64)
	for action, p := range dist.Probabilities {
		ttps := ttpForAction[action]
		if len(ttps) == 0 {
			continue
		}
		share := p / float64(len(ttps))
		for _, t := range ttps {
			out[t] += share
		}
	}
	return out
}

// ttpForAction maps actions to the ATT&CK techniques they most likely employ
// (reverse of attackerstate's TTP→Intent mapping; unknown techniques omitted).
var ttpForAction = map[Action][]string{
	ActionRecon:      {"T1595", "T1592", "T1590", "T1046"},
	ActionCredential: {"T1110", "T1003", "T1555", "T1078"},
	ActionLateral:    {"T1021", "T1570", "T1550"},
	ActionDataTheft:  {"T1567", "T1048", "T1537"},
	ActionWebAttack:  {"T1190", "T1566"},
}

// softmax converts raw scores to a normalized probability distribution.
func softmax(scores map[Action]float64, temperature float64) map[Action]float64 {
	if temperature <= 0 {
		temperature = 1.0
	}
	maxS := 0.0
	for _, s := range scores {
		if s > maxS {
			maxS = s
		}
	}
	exp := make(map[Action]float64, len(scores))
	sum := 0.0
	for a, s := range scores {
		v := math.Exp((s - maxS) / temperature)
		exp[a] = v
		sum += v
	}
	out := make(map[Action]float64, len(exp))
	for a, v := range exp {
		out[a] = v / sum
	}
	return out
}
