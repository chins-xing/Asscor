package predictor

import (
	"testing"

	"github.com/asscor/asscor/internal/attackerstate"
)

// TestPredictDistribution: 概率归一化 + 输出结构完整。
func TestPredictDistribution(t *testing.T) {
	e := NewEngine()
	s := attackerstate.NewState("actor-1")
	s.Intent = attackerstate.IntentCredential
	s.Experience = 0.5
	s.TargetKnowledge = 0.4

	dist := e.Predict(s, TargetState{ID: "host-a", SSAMScore: 60, Exposure: 0.5})

	// 归一化。
	sum := 0.0
	for _, p := range dist.Probabilities {
		sum += p
	}
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("probabilities must sum to 1, got %.4f", sum)
	}
	// 六动作全覆盖。
	if len(dist.Probabilities) != len(AllActions()) {
		t.Errorf("distribution size = %d, want %d", len(dist.Probabilities), len(AllActions()))
	}
	// Ranked 降序。
	for i := 1; i < len(dist.Ranked); i++ {
		if dist.Probabilities[dist.Ranked[i-1]] < dist.Probabilities[dist.Ranked[i]] {
			t.Errorf("ranked not descending: %v", dist.Ranked)
		}
	}
	// MostLikely 必须是概率最高的。
	if dist.Probabilities[dist.MostLikely] < dist.Probabilities[dist.Ranked[0]]-1e-9 {
		t.Errorf("MostLikely %s != top ranked %s", dist.MostLikely, dist.Ranked[0])
	}
	if dist.MostDangerous == "" || dist.MostObservable == "" {
		t.Error("multi-outputs must be populated")
	}
}

// TestPredictIntentContinuity: 意图延续 — 当前 Intent 对应动作概率最高。
func TestPredictIntentContinuity(t *testing.T) {
	e := NewEngine()
	cases := []struct {
		intent attackerstate.Intent
		action Action
	}{
		{attackerstate.IntentRecon, ActionRecon},
		{attackerstate.IntentCredential, ActionCredential},
		{attackerstate.IntentLateral, ActionLateral},
		{attackerstate.IntentDataTheft, ActionDataTheft},
		{attackerstate.IntentWebAttack, ActionWebAttack},
	}
	for _, c := range cases {
		s := attackerstate.NewState("actor-1")
		s.Intent = c.intent
		dist := e.Predict(s, TargetState{ID: "h", SSAMScore: 70, Exposure: 0.2})
		if dist.MostLikely != c.action {
			t.Errorf("intent %s: MostLikely = %s, want %s (continuity)", c.intent, dist.MostLikely, c.action)
		}
	}
}

// TestPredictDangerousVsLikely: MostDangerous = argmax(prob × dangerWeight)
// (引擎语义确定性验证) — 危险度加权最优可能 ≠ MostLikely。
func TestPredictDangerousVsLikely(t *testing.T) {
	e := NewEngine()
	// 高经验 + 高目标知识 + 高脆弱目标 → 执行类动作概率高。
	s := attackerstate.NewState("actor-1")
	s.Intent = attackerstate.IntentCredential
	s.Experience = 0.9
	s.TargetKnowledge = 0.9
	s.AIDependence = 0.8

	dist := e.Predict(s, TargetState{ID: "h", SSAMScore: 30, Exposure: 0.9})

	// MostDangerous 必须是 prob×danger 最大的动作。
	best := -1.0
	bestAction := ActionMaintain
	for _, a := range AllActions() {
		d := dist.Probabilities[a] * e.DangerWeight[a]
		if d > best {
			best = d
			bestAction = a
		}
	}
	if dist.MostDangerous != bestAction {
		t.Errorf("MostDangerous = %s, want %s (argmax prob×danger)", dist.MostDangerous, bestAction)
	}
	// 高威胁场景: DataTheft 概率非零时, 其危险度加权应显著。
	if dist.Probabilities[ActionDataTheft] <= 0 {
		t.Error("data_theft must have non-zero probability under high-risk scenario")
	}
}

// TestPredictVulnerabilityBias: 脆弱目标偏向执行类 — 低 SSAM 目标提升
// 执行类动作概率。
func TestPredictVulnerabilityBias(t *testing.T) {
	e := NewEngine()
	s := attackerstate.NewState("actor-1")
	s.Intent = attackerstate.IntentUnknown

	weak := e.Predict(s, TargetState{ID: "h", SSAMScore: 20, Exposure: 0.9})
	strong := e.Predict(s, TargetState{ID: "h", SSAMScore: 95, Exposure: 0.1})

	execScore := func(d ActionDistribution) float64 {
		return d.Probabilities[ActionCredential] + d.Probabilities[ActionLateral] +
			d.Probabilities[ActionDataTheft] + d.Probabilities[ActionWebAttack]
	}
	if execScore(weak) <= execScore(strong) {
		t.Errorf("weak target must bias toward execution actions: weak=%.3f strong=%.3f",
			execScore(weak), execScore(strong))
	}
}

// TestTTPDistribution: 两层模型 §4.3 — 行动分布映射到 TTP 分布。
func TestTTPDistribution(t *testing.T) {
	e := NewEngine()
	s := attackerstate.NewState("actor-1")
	s.Intent = attackerstate.IntentCredential

	dist := e.Predict(s, TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})
	ttps := e.TTPDistribution(dist)

	if len(ttps) == 0 {
		t.Fatal("TTP distribution must not be empty")
	}
	// TTP 概率和 = 有映射 action 的概率和 (≤1)。
	sum := 0.0
	for _, p := range ttps {
		sum += p
	}
	if sum <= 0 || sum > 1.0001 {
		t.Errorf("TTP probability sum = %.4f, want (0,1]", sum)
	}
	// 意图延续 → Credential 相关 TTP 概率占比高。
	credTTPs := map[string]bool{"T1110": true, "T1003": true, "T1555": true, "T1078": true}
	credSum := 0.0
	for t, p := range ttps {
		if credTTPs[t] {
			credSum += p
		}
	}
	if credSum <= 0 {
		t.Error("credential TTPs must have non-zero probability under credential intent")
	}
}

// TestPredictImmutability: Predict 不改输入状态。
func TestPredictImmutability(t *testing.T) {
	e := NewEngine()
	s := attackerstate.NewState("actor-1")
	s.Intent = attackerstate.IntentRecon
	before := s

	e.Predict(s, TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})

	if s.Intent != before.Intent || s.Experience != before.Experience {
		t.Error("Predict must not mutate input state")
	}
}
