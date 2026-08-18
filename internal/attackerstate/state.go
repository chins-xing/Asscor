package attackerstate

import (
	"time"
)

// 攻击者状态引擎 — 主动防御白皮书 Phase 2（§3.2 AttackerState + §5.4
// State Update）
//
// 定位：攻击者认知状态模型（OldState + Evidence → NewState）。本组件是
// 纯状态库（不接 kernel），供上层（Prediction/Engagement）与 SRD 资产
// 状态消费。初期用规则 + 权重近似（白皮书 §2.1/§7：不引入完整 I-POMDP²
// 求解器，代价高昂）。
//
// 严格原则（白皮书 §3.5）：不把假设写成结论——本引擎只做可解释的规则
// 更新，不宣称"预测准确"；所有推断带置信度与来源（Evidence）。

// Intent 是攻击者当前阶段目的（白皮书 §3.2 枚举）。
type Intent string

const (
	IntentRecon      Intent = "recon"       // 侦察/信息收集
	IntentCredential Intent = "credential"  // 凭据获取
	IntentLateral    Intent = "lateral"     // 横向移动
	IntentDataTheft  Intent = "data_theft"  // 数据窃取
	IntentWebAttack  Intent = "web_attack"  // Web 攻击
	IntentUnknown    Intent = "unknown"
)

// AttackerState 是攻击者认知状态（白皮书 §3.2 结构）。
// 所有字段保持可解释；概率型字段为 [0,1] 置信度。
type AttackerState struct {
	ID                   string             // Actor/攻击者标识
	Capability           []string           // 实际可执行能力集合（能力 ID）
	Experience           float64            // [0,1] 经验水平
	Intent               Intent             // 当前阶段目的
	TTPRepertoire        []string           // 熟悉/可调用的 TTP 子集
	SharedCapability     float64            // [0,1] 依赖公共能力（共享工具/AI）
	IndividualCapability float64            // [0,1] 自身能力/经验
	AIDependence         float64            // [0,1] 决策/执行对 AI 依赖度
	TargetKnowledge      float64            // [0,1] 对当前目标已知程度
	BeliefState          map[string]float64 // 对目标环境的主观认知（方面→置信度）
	Objective            string             // 最终目标
	UpdatedAt            time.Time
}

// Evidence 是状态更新的输入（白皮书 §5.2 简化：来源/时间/意图/TTP/目标/
// 置信度/结果）。
type Evidence struct {
	Source     string  // 来源（日志/诱饵/告警/CTI...）
	SourceType string  // source type
	At         time.Time
	Actor      string  // 归属攻击者
	Intent     Intent  // 观测意图（可空 → 由 TTP 推断）
	TTP        string  // ATT&CK 技术 ID（可空）
	Target     string  // 目标（主机/资产）
	Outcome    string  // outcome: success | failure | ""（未知）
	Confidence float64 // [0,1]
}

// Engine 是状态更新引擎（规则 + 权重）。
type Engine struct {
	// 无内部状态（纯函数式更新），规则常量见 mapping.go。
}

// NewEngine creates a state engine with default rules.
func NewEngine() *Engine { return &Engine{} }

// NewState creates an initial attacker state (all-zero belief, unknown intent).
func NewState(id string) AttackerState {
	return AttackerState{
		ID:          id,
		Intent:      IntentUnknown,
		BeliefState: make(map[string]float64),
		UpdatedAt:   time.Now(),
	}
}

// Update applies evidence to a state (OldState + Evidence → NewState).
// Rules (初期规则 + 权重，白皮书 §5.4)：
//
//  1. Intent 推断：Evidence.TTP 映射到意图（mapping.go 表）；显式
//     Evidence.Intent 优先；高置信度证据覆盖低置信度。
//  2. TargetKnowledge：每次带 Target 的观察提升（0.1 × Confidence，封顶 1）。
//  3. TTPRepertoire：观测到的 TTP 加入已知集（去重）。
//  4. Experience：Outcome=success +0.05 / failure −0.03（clamp [0,1]）。
//  5. Capability：新 TTP 的能力需求写入 Capability（mapping.go）。
func (e *Engine) Update(state AttackerState, evs []Evidence) AttackerState {
	out := state
	if out.BeliefState == nil {
		out.BeliefState = make(map[string]float64)
	}

	bestIntent := out.Intent
	bestConf := 0.0

	for _, ev := range evs {
		// 规则 3: TTP 去重入集。
		if ev.TTP != "" {
			out.TTPRepertoire = appendUnique(out.TTPRepertoire, ev.TTP)
		}
		// 规则 2: 目标知识。
		if ev.Target != "" {
			inc := 0.1 * clamp01(ev.Confidence)
			out.TargetKnowledge = clamp01(out.TargetKnowledge + inc)
		}
		// 规则 4: 经验。
		switch ev.Outcome {
		case "success":
			out.Experience = clamp01(out.Experience + 0.05)
		case "failure":
			out.Experience = clamp01(out.Experience - 0.03)
		}
		// 规则 1: 意图（显式优先，否则 TTP 映射；高置信覆盖）。
		intent := ev.Intent
		if intent == "" || intent == IntentUnknown {
			intent = IntentFromTTP(ev.TTP)
		}
		if intent != "" && intent != IntentUnknown && ev.Confidence >= bestConf {
			bestIntent = intent
			bestConf = ev.Confidence
		}
		// 规则 5: 能力集合（TTP 对应能力需求）。
		if capID := CapabilityForTTP(ev.TTP); capID != "" {
			out.Capability = appendUnique(out.Capability, capID)
		}
		// BeliefState: 对目标环境的观测认知（方面=target, 值=置信度加权）。
		if ev.Target != "" {
			cur := out.BeliefState[ev.Target]
			out.BeliefState[ev.Target] = clamp01(cur + 0.15*clamp01(ev.Confidence))
		}
	}

	if bestIntent != "" && bestIntent != IntentUnknown {
		out.Intent = bestIntent
	}
	out.UpdatedAt = time.Now()
	return out
}

// IntentFromTTP maps an ATT&CK technique ID to the most likely attacker
// intent (白皮书 §3.1 Intent 五类 + Unknown)。未知 TTP → unknown。
func IntentFromTTP(ttp string) Intent {
	if i, ok := ttpIntent[ttp]; ok {
		return i
	}
	return IntentUnknown
}

// CapabilityForTTP returns the capability ID required by a TTP (empty when
// unknown)。
func CapabilityForTTP(ttp string) string {
	return ttpCapability[ttp]
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
