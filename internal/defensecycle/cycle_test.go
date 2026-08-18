package defensecycle

import (
	"testing"
	"time"

	"github.com/asscor/asscor/internal/attackerstate"
	"github.com/asscor/asscor/internal/engagement"
	"github.com/asscor/asscor/internal/predictor"
)

func newTestController() *Controller {
	return NewController(
		attackerstate.NewEngine(),
		predictor.NewEngine(),
		engagement.NewPlanner(engagement.DefaultParams()),
	)
}

func mkObs(ttp, intent, target, outcome string, conf float64) attackerstate.Evidence {
	return attackerstate.Evidence{
		Source:     "obs",
		SourceType: "test",
		At:         time.Now(),
		TTP:        ttp,
		Intent:     attackerstate.Intent(intent),
		Target:     target,
		Outcome:    outcome,
		Confidence: conf,
	}
}

// TestStepBasic: 单轮闭环 — 观测 → 状态 → 预测 → 策略 → 干预。
func TestStepBasic(t *testing.T) {
	c := newTestController()
	s := attackerstate.NewState("actor-1")

	res := c.Step(s, []attackerstate.Evidence{mkObs("T1595", "", "host-a", "", 0.7)},
		predictor.TargetState{ID: "host-a", SSAMScore: 60, Exposure: 0.5})

	if res.State.Intent != attackerstate.IntentRecon {
		t.Errorf("state intent = %s, want recon (driven by observation)", res.State.Intent)
	}
	if res.Distribution.MostLikely != predictor.ActionRecon {
		t.Errorf("prediction = %s, want recon", res.Distribution.MostLikely)
	}
	if res.Confidence <= 0 || res.Confidence > 1 {
		t.Errorf("confidence = %.3f, want (0,1]", res.Confidence)
	}
	if res.Strategy != StrategyCollect && res.Strategy != StrategyEngage {
		t.Errorf("strategy = %s", res.Strategy)
	}
	if len(res.Interventions) == 0 {
		t.Error("must select at least one intervention")
	}
}

// TestConfidenceStrategy: 低置信 → collect (高 IG), 高置信 → engage (全选)。
func TestConfidenceStrategy(t *testing.T) {
	c := newTestController()

	// 低置信: 意图 unknown + 无观测 → 分布平坦。
	s := attackerstate.NewState("actor-1")
	resLow := c.Step(s, nil, predictor.TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})
	if resLow.Strategy != StrategyCollect {
		t.Errorf("flat distribution strategy = %s, want collect", resLow.Strategy)
	}
	if len(resLow.Interventions) != 1 {
		t.Errorf("collect strategy must keep exactly 1 (highest-IG) intervention, got %d", len(resLow.Interventions))
	}

	// 高置信: 强意图证据 → 分布尖锐。
	s2 := attackerstate.NewState("actor-1")
	resHigh := c.Step(s2, []attackerstate.Evidence{
		mkObs("T1110", "credential", "h", "success", 0.95),
		mkObs("T1110", "credential", "h", "success", 0.9),
	}, predictor.TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})
	if resHigh.Strategy != StrategyEngage {
		t.Errorf("sharp distribution strategy = %s, want engage", resHigh.Strategy)
	}
	if len(resHigh.Interventions) < 2 {
		t.Errorf("engage strategy should keep all positive-utility interventions, got %d", len(resHigh.Interventions))
	}
}

// TestDistributionConfidence: 归一化熵置信度 — 尖锐分布高, 平坦分布低。
func TestDistributionConfidence(t *testing.T) {
	sharp := predictor.ActionDistribution{Probabilities: map[predictor.Action]float64{
		predictor.ActionCredential: 0.95, predictor.ActionRecon: 0.01, predictor.ActionLateral: 0.01,
		predictor.ActionDataTheft: 0.01, predictor.ActionWebAttack: 0.01, predictor.ActionMaintain: 0.01,
	}}
	flat := predictor.ActionDistribution{Probabilities: map[predictor.Action]float64{
		predictor.ActionCredential: 1.0 / 6, predictor.ActionRecon: 1.0 / 6, predictor.ActionLateral: 1.0 / 6,
		predictor.ActionDataTheft: 1.0 / 6, predictor.ActionWebAttack: 1.0 / 6, predictor.ActionMaintain: 1.0 / 6,
	}}
	if c := DistributionConfidence(sharp); c <= 0.5 {
		t.Errorf("sharp confidence = %.3f, want > 0.5", c)
	}
	if c := DistributionConfidence(flat); c > 0.05 {
		t.Errorf("flat confidence = %.3f, want ~0", c)
	}
}

// TestMultiRoundConvergence: 多轮闭环 — 诱饵触发证据持续指向凭据攻击 →
// 意图收敛到 Credential, 置信度上升, 策略转主动 (§5.1 闭环收敛)。
func TestMultiRoundConvergence(t *testing.T) {
	c := newTestController()
	s := attackerstate.NewState("actor-1")
	target := predictor.TargetState{ID: "host-a", SSAMScore: 55, Exposure: 0.6}

	var lastRes CycleResult
	evidence := []attackerstate.Evidence{
		mkObs("T1595", "", "host-a", "", 0.6), // 轮1: 侦察
		mkObs("T1110", "", "host-a", "success", 0.85), // 轮2: 凭据攻击成功
		mkObs("T1003", "", "host-a", "success", 0.9),  // 轮3: 凭据转储
	}
	for _, ev := range evidence {
		lastRes = c.Step(s, []attackerstate.Evidence{ev}, target)
		s = lastRes.State
	}

	if s.Intent != attackerstate.IntentCredential {
		t.Errorf("converged intent = %s, want credential", s.Intent)
	}
	if lastRes.Distribution.MostLikely != predictor.ActionCredential {
		t.Errorf("converged prediction = %s, want credential", lastRes.Distribution.MostLikely)
	}
	if lastRes.Strategy != StrategyEngage {
		t.Errorf("high-confidence converged strategy = %s, want engage", lastRes.Strategy)
	}
	if lastRes.State.Experience <= 0 || lastRes.State.TargetKnowledge <= 0 {
		t.Errorf("state must accumulate experience/knowledge: %+v", lastRes.State)
	}
}

// TestStepImmutability: Step 不改输入状态。
func TestStepImmutability(t *testing.T) {
	c := newTestController()
	s := attackerstate.NewState("actor-1")
	before := s

	c.Step(s, []attackerstate.Evidence{mkObs("T1595", "", "h", "", 0.7)}, predictor.TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})

	if s.Intent != before.Intent || s.TargetKnowledge != before.TargetKnowledge {
		t.Error("Step must not mutate input state")
	}
}
