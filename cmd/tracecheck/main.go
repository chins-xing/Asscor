//go:build tracecheck

// Package main reproduces the four-round closed-loop trace and the weight
// sensitivity tables from the ACL paper (draft v0.3, §Trace / §Sensitivity /
// §Performance) against the reference implementation, to verify the paper's
// numbers.
package main

import (
	"fmt"
	"math"
	"time"

	"github.com/asscor/asscor/internal/attackerstate"
	"github.com/asscor/asscor/internal/defensecycle"
	"github.com/asscor/asscor/internal/engagement"
	"github.com/asscor/asscor/internal/predictor"
)

func mk(ttp, intent, target, outcome string, conf float64) attackerstate.Evidence {
	return attackerstate.Evidence{
		Source: "decoy", SourceType: "trace", At: time.Now(),
		TTP: ttp, Intent: attackerstate.Intent(intent), Target: target,
		Outcome: outcome, Confidence: conf,
	}
}

func show(label string, r defensecycle.CycleResult) {
	fmt.Printf("== %s: intent=%s E=%.3f K=%.3f S=%.3f strategy=%s\n",
		label, r.State.Intent, r.State.Experience, r.State.TargetKnowledge, r.Sharpness, r.Strategy)
	for _, a := range predictor.AllActions() {
		fmt.Printf("   %-12s P=%.4f\n", a, r.Distribution.Probabilities[a])
	}
	fmt.Print("   interventions:")
	for _, i := range r.Interventions {
		fmt.Printf(" %s(U=%.3f)", i.ID, i.Utility)
	}
	fmt.Println()
}

// scoreWithInt reproduces Eq. (score) with a configurable intent-continuity
// weight wint (the reference Engine hard-codes 3.0).
func scoreWithInt(s attackerstate.AttackerState, target predictor.TargetState, wint float64) map[predictor.Action]float64 {
	base := map[predictor.Action]float64{
		predictor.ActionRecon: 1.0, predictor.ActionCredential: 1.2, predictor.ActionLateral: 1.1,
		predictor.ActionDataTheft: 0.9, predictor.ActionWebAttack: 1.0, predictor.ActionMaintain: 0.5,
	}
	intentOf := map[predictor.Action]attackerstate.Intent{
		predictor.ActionRecon: attackerstate.IntentRecon, predictor.ActionCredential: attackerstate.IntentCredential,
		predictor.ActionLateral: attackerstate.IntentLateral, predictor.ActionDataTheft: attackerstate.IntentDataTheft,
		predictor.ActionWebAttack: attackerstate.IntentWebAttack,
	}
	vuln := (100.0-target.SSAMScore)/100.0 + target.Exposure
	out := make(map[predictor.Action]float64)
	for _, a := range predictor.AllActions() {
		sc := base[a]
		if intentOf[a] == s.Intent {
			sc += wint
		}
		switch a {
		case predictor.ActionLateral, predictor.ActionDataTheft:
			sc += s.Experience
		case predictor.ActionRecon:
			sc -= s.Experience * 0.5
		}
		switch a {
		case predictor.ActionCredential, predictor.ActionLateral, predictor.ActionDataTheft:
			sc += s.TargetKnowledge
		}
		switch a {
		case predictor.ActionCredential, predictor.ActionWebAttack:
			sc += s.AIDependence
		case predictor.ActionRecon:
			sc -= s.AIDependence * 0.5
		}
		switch a {
		case predictor.ActionCredential, predictor.ActionLateral, predictor.ActionDataTheft, predictor.ActionWebAttack:
			sc += vuln * 0.8
		}
		if sc < 0 {
			sc = 0
		}
		out[a] = sc
	}
	return out
}

// softmax reproduces Eq. (softmax) with temperature T.
func softmax(scores map[predictor.Action]float64, T float64) map[predictor.Action]float64 {
	if T <= 0 {
		T = 1.0
	}
	maxS := 0.0
	for _, s := range scores {
		if s > maxS {
			maxS = s
		}
	}
	exp := make(map[predictor.Action]float64)
	sum := 0.0
	for a, s := range scores {
		v := math.Exp((s - maxS) / T)
		exp[a] = v
		sum += v
	}
	out := make(map[predictor.Action]float64)
	for a, v := range exp {
		out[a] = v / sum
	}
	return out
}

// entropySharpness reproduces Eq. (sharpness).
func entropySharpness(p map[predictor.Action]float64) float64 {
	n := float64(len(p))
	if n <= 1 {
		return 1.0
	}
	H := 0.0
	for _, v := range p {
		if v > 0 {
			H -= v * math.Log(v)
		}
	}
	c := 1.0 - H/math.Log(n)
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

func main() {
	se := attackerstate.NewEngine()
	pr := predictor.NewEngine()
	pl := engagement.NewPlanner(engagement.DefaultParams())
	c := defensecycle.NewController(se, pr, pl)
	s := attackerstate.NewState("actor-1")
	target := predictor.TargetState{ID: "host-a", SSAMScore: 55, Exposure: 0.6}

	r1 := c.Step(s, nil, target)
	show("Round 1 (none)", r1)
	s = r1.State

	r2 := c.Step(s, []attackerstate.Evidence{mk("T1595", "", "host-a", "", 0.6)}, target)
	show("Round 2 (T1595 scan)", r2)
	s = r2.State

	r3 := c.Step(s, []attackerstate.Evidence{mk("T1110", "", "host-a", "success", 0.85)}, target)
	show("Round 3 (T1110 brute force)", r3)
	s = r3.State

	r4 := c.Step(s, []attackerstate.Evidence{mk("T1003", "", "host-a", "success", 0.9)}, target)
	show("Round 4 (T1003 dumping)", r4)

	// Defensive fallback: unknown TTP → contain.
	rUnknown := c.Step(s, []attackerstate.Evidence{mk("T9999", "", "host-a", "", 0.9)}, target)
	show("Round 5 (T9999 unknown TTP)", rUnknown)

	// Sensitivity: intent-continuity weight (credential intent, E=0.05, K=0.145)
	fmt.Println("== w_int sensitivity (credential intent, E=0.05, K=0.145, target SSAM=55/exp=0.6)")
	st := attackerstate.NewState("x")
	st.Intent = attackerstate.IntentCredential
	st.Experience = 0.05
	st.TargetKnowledge = 0.145
	for _, w := range []float64{0.0, 1.5, 3.0, 4.5} {
		scores := scoreWithInt(st, target, w)
		p := softmax(scores, 1.0)
		sh := entropySharpness(p)
		fmt.Printf("   w_int=%.1f: P(credential)=%.4f S=%.4f strategy=%s\n", w, p[predictor.ActionCredential], sh, map[bool]string{true: "engage", false: "collect"}[sh >= 0.3])
	}

	// Sensitivity: temperature at round 2 scores (recon intent)
	fmt.Println("== T sensitivity (round 2 scores: recon 4.00, cred 2.10, lat 2.00, dt 1.80, web 1.84, maint 0.50)")
	scores2 := map[predictor.Action]float64{
		predictor.ActionRecon: 4.00, predictor.ActionCredential: 2.10, predictor.ActionLateral: 2.00,
		predictor.ActionDataTheft: 1.80, predictor.ActionWebAttack: 1.84, predictor.ActionMaintain: 0.50,
	}
	for _, T := range []float64{0.5, 1.0, 2.0} {
		p := softmax(scores2, T)
		sh := entropySharpness(p)
		fmt.Printf("   T=%.1f: P(recon)=%.3f H=%.3f S=%.3f\n", T, p[predictor.ActionRecon], -func() float64 {
			h := 0.0
			for _, v := range p {
				if v > 0 {
					h -= v * math.Log(v)
				}
			}
			return h
		}(), sh)
	}
}
