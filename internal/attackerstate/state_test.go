package attackerstate

import (
	"testing"
	"time"
)

func mkEv(ttp, intent, target, outcome string, conf float64) Evidence {
	return Evidence{
		Source:     "test",
		SourceType: "unit",
		At:         time.Now(),
		TTP:        ttp,
		Intent:     Intent(intent),
		Target:     target,
		Outcome:    outcome,
		Confidence: conf,
	}
}

// TestNewState: 初始状态 — 全零置信度 + unknown 意图。
func TestNewState(t *testing.T) {
	s := NewState("actor-1")
	if s.ID != "actor-1" || s.Intent != IntentUnknown || s.Experience != 0 || s.TargetKnowledge != 0 {
		t.Fatalf("initial state = %+v", s)
	}
	if len(s.TTPRepertoire) != 0 || len(s.Capability) != 0 {
		t.Fatalf("initial state must have empty sets: %+v", s)
	}
}

// TestIntentFromTTP: TTP→意图映射 + 未知 TTP。
func TestIntentFromTTP(t *testing.T) {
	cases := map[string]Intent{
		"T1595": IntentRecon,
		"T1110": IntentCredential,
		"T1021": IntentLateral,
		"T1567": IntentDataTheft,
		"T1190": IntentWebAttack,
		"T9999": IntentUnknown,
		"":      IntentUnknown,
	}
	for ttp, want := range cases {
		if got := IntentFromTTP(ttp); got != want {
			t.Errorf("IntentFromTTP(%q) = %s, want %s", ttp, got, want)
		}
	}
}

// TestUpdateIntentInference: 证据经 TTP 推断意图 + 高置信覆盖。
func TestUpdateIntentInference(t *testing.T) {
	e := NewEngine()
	s := NewState("actor-1")

	// 侦察 TTP → Recon。
	s = e.Update(s, []Evidence{mkEv("T1595", "", "host-a", "", 0.7)})
	if s.Intent != IntentRecon {
		t.Errorf("intent = %s, want recon", s.Intent)
	}
	// 凭据 TTP (更高置信) → Credential (覆盖)。
	s = e.Update(s, []Evidence{mkEv("T1110", "", "host-a", "", 0.9)})
	if s.Intent != IntentCredential {
		t.Errorf("intent = %s, want credential (high-conf override)", s.Intent)
	}
	// 显式 Intent 优先于 TTP 推断。
	s = e.Update(s, []Evidence{mkEv("T1110", "lateral", "host-a", "", 0.8)})
	if s.Intent != IntentLateral {
		t.Errorf("explicit intent = %s, want lateral", s.Intent)
	}
}

// TestUpdateKnowledgeAndRepertoire: 目标知识提升 + TTP 集累积 + 能力集合。
func TestUpdateKnowledgeAndRepertoire(t *testing.T) {
	e := NewEngine()
	s := NewState("actor-1")

	s = e.Update(s, []Evidence{
		mkEv("T1595", "", "host-a", "", 0.5),
		mkEv("T1595", "", "host-a", "", 0.8),
		mkEv("T1110", "", "host-b", "success", 0.9),
	})

	if s.TargetKnowledge <= 0 {
		t.Error("target knowledge must increase after observations")
	}
	if s.TargetKnowledge > 1 {
		t.Error("target knowledge must be capped at 1")
	}
	if len(s.TTPRepertoire) != 2 {
		t.Errorf("TTP repertoire = %v, want 2 unique TTPs", s.TTPRepertoire)
	}
	if len(s.Capability) < 2 {
		t.Errorf("capability set = %v, want >= 2", s.Capability)
	}
	if s.Experience < 0.04 {
		t.Errorf("experience = %.3f, want >= 0.05 (one success)", s.Experience)
	}
	if s.BeliefState["host-a"] <= 0 || s.BeliefState["host-b"] <= 0 {
		t.Errorf("belief state = %v", s.BeliefState)
	}
}

// TestUpdateExperienceClamp: 经验增减 + 上下限。
func TestUpdateExperienceClamp(t *testing.T) {
	e := NewEngine()
	s := NewState("actor-1")

	// 失败 -0.03 × 40 → 到 0 (clamp 下限)。
	for i := 0; i < 40; i++ {
		s = e.Update(s, []Evidence{mkEv("T1110", "", "h", "failure", 0.5)})
	}
	if s.Experience != 0 {
		t.Errorf("experience clamp floor = %.3f, want 0", s.Experience)
	}
	// 成功 +0.05 × 30 → 到 1 (clamp 上限)。
	for i := 0; i < 30; i++ {
		s = e.Update(s, []Evidence{mkEv("T1110", "", "h", "success", 0.5)})
	}
	if s.Experience != 1 {
		t.Errorf("experience clamp ceil = %.3f, want 1", s.Experience)
	}
}

// TestUpdateImmutability: Update 返回新状态 (旧状态不被修改)。
func TestUpdateImmutability(t *testing.T) {
	e := NewEngine()
	s := NewState("actor-1")
	before := s

	s2 := e.Update(s, []Evidence{mkEv("T1595", "", "host-a", "", 0.7)})

	if s.Intent != IntentUnknown || s.TargetKnowledge != 0 || len(s.TTPRepertoire) != 0 {
		t.Errorf("original state must not mutate: %+v", s)
	}
	if s2.Intent != IntentRecon {
		t.Errorf("returned state = %s, want recon", s2.Intent)
	}
	if before.UpdatedAt.IsZero() {
		t.Error("initial UpdatedAt must be set")
	}
}
