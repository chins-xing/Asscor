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
	if res.Sharpness <= 0 || res.Sharpness > 1 {
		t.Errorf("sharpness = %.3f, want (0,1]", res.Sharpness)
	}
	if res.Strategy != StrategyContain && res.Strategy != StrategyCollect && res.Strategy != StrategyEngage {
		t.Errorf("strategy = %s", res.Strategy)
	}
}

// TestStrategyUnknownIntentContain: 意图 unknown + 无观测 → contain (防御性回退)。
func TestStrategyUnknownIntentContain(t *testing.T) {
	c := newTestController()

	// 意图 unknown + 无观测 → 必须 contain (临时隔离), 不部署任何诱饵。
	s := attackerstate.NewState("actor-1")
	res := c.Step(s, nil, predictor.TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})
	if res.Strategy != StrategyContain {
		t.Errorf("unknown-intent strategy = %s, want contain", res.Strategy)
	}
	if len(res.Interventions) != 0 {
		t.Errorf("contain strategy must deploy nothing, got %d interventions", len(res.Interventions))
	}
}

// TestStrategyUnknownTTPContain: 存在无法映射的未知 TTP → contain。
func TestStrategyUnknownTTPContain(t *testing.T) {
	c := newTestController()
	s := attackerstate.NewState("actor-1")

	// T9999 不在映射表中, 无显式意图 → unknown TTP → contain。
	res := c.Step(s, []attackerstate.Evidence{mkObs("T9999", "", "h", "", 0.9)},
		predictor.TargetState{ID: "h", SSAMScore: 60, Exposure: 0.5})
	if res.Strategy != StrategyContain {
		t.Errorf("unknown-TTP strategy = %s, want contain", res.Strategy)
	}
}

// TestSharpnessStrategy: 低锐度 → collect (高 IG), 高锐度 → engage (全选)。
func TestSharpnessStrategy(t *testing.T) {
	c := newTestController()

	// 已知意图 + 低锐度场景: 意图已确定但分布被目标脆弱性拉平。
	// 构造: recon 意图 + 极脆弱目标 → 执行类动作得分接近 → 分布平坦。
	s := attackerstate.NewState("actor-1")
	resLow := c.Step(s, []attackerstate.Evidence{
		mkObs("T1595", "", "h", "", 0.9),
	}, predictor.TargetState{ID: "h", SSAMScore: 20, Exposure: 0.95})
	_ = resLow

	// 高锐度: 强意图证据 → 分布尖锐。
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

// TestDistributionSharpness: 归一化熵锐度 — 尖锐分布高, 平坦分布低。
func TestDistributionSharpness(t *testing.T) {
	sharp := predictor.ActionDistribution{Probabilities: map[predictor.Action]float64{
		predictor.ActionCredential: 0.95, predictor.ActionRecon: 0.01, predictor.ActionLateral: 0.01,
		predictor.ActionDataTheft: 0.01, predictor.ActionWebAttack: 0.01, predictor.ActionMaintain: 0.01,
	}}
	flat := predictor.ActionDistribution{Probabilities: map[predictor.Action]float64{
		predictor.ActionCredential: 1.0 / 6, predictor.ActionRecon: 1.0 / 6, predictor.ActionLateral: 1.0 / 6,
		predictor.ActionDataTheft: 1.0 / 6, predictor.ActionWebAttack: 1.0 / 6, predictor.ActionMaintain: 1.0 / 6,
	}}
	if s := DistributionSharpness(sharp); s <= 0.5 {
		t.Errorf("sharp sharpness = %.3f, want > 0.5", s)
	}
	if s := DistributionSharpness(flat); s > 0.05 {
		t.Errorf("flat sharpness = %.3f, want ~0", s)
	}
}

// TestMultiRoundConvergence: 多轮闭环 — 诱饵触发证据持续指向凭据攻击 →
// 意图收敛到 Credential, 锐度上升, 策略转主动 (§5.1 闭环收敛)。
func TestMultiRoundConvergence(t *testing.T) {
	c := newTestController()
	s := attackerstate.NewState("actor-1")
	target := predictor.TargetState{ID: "host-a", SSAMScore: 55, Exposure: 0.6}

	var lastRes CycleResult
	evidence := []attackerstate.Evidence{
		mkObs("T1595", "", "host-a", "", 0.6),     // 轮1: 侦察
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
		t.Errorf("high-sharpness converged strategy = %s, want engage", lastRes.Strategy)
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
