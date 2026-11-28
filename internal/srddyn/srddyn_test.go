package srddyn

import (
	"math"
	"testing"
)

func last(xs []State) State { return xs[len(xs)-1] }

func TestIndependentStateChangesTrajectory(t *testing.T) {
	p := DefaultParams()
	a := Simulate(State{S: 0.8, D: 0, H: 0.1}, 0.1, []float64{0.8}, p, 0.1, 100)
	b := Simulate(State{S: 0.8, D: 1.0, H: 0.1}, 0.1, []float64{0.8}, p, 0.1, 100)
	if math.Abs(last(a).S-last(b).S) < 1e-3 {
		t.Fatalf("debt did not change future posture: %v vs %v", last(a).S, last(b).S)
	}
}

func TestDebtHasMemoryAndDecays(t *testing.T) {
	p := DefaultParams()
	stress := Simulate(State{S: 0.7}, 1.0, nil, p, 0.1, 50)
	dAtRelease := last(stress).D
	if dAtRelease <= 0 {
		t.Fatalf("debt did not accumulate: %+v", last(stress))
	}
	relax := Simulate(last(stress), 0, nil, p, 0.1, 100)
	dLater := last(relax).D
	if dLater <= 0 {
		t.Fatalf("debt was hard-reset instead of decaying: %v", dLater)
	}
	if dLater >= dAtRelease {
		t.Fatalf("debt did not decay: %v -> %v", dAtRelease, dLater)
	}
}

func TestCollapseFeedbackChangesPosture(t *testing.T) {
	p := DefaultParams()
	base := p
	base.Eta = 0
	withFeedback := p
	withFeedback.Eta = 0.5
	x := State{S: 0.6, D: 0.8, H: 0.8}
	a := last(Simulate(x, 0, nil, base, 0.1, 200))
	b := last(Simulate(x, 0, nil, withFeedback, 0.1, 200))
	if math.Abs(a.S-b.S) < 1e-3 {
		t.Fatalf("collapse feedback did not affect posture: %v vs %v", a.S, b.S)
	}
}

func TestNeighborCouplingChangesContagion(t *testing.T) {
	p := DefaultParams()
	healthy := last(Simulate(State{S: 0.9}, 0, []float64{1.0, 1.0}, p, 0.1, 100))
	collapsed := last(Simulate(State{S: 0.9}, 0, []float64{0.0, 0.0}, p, 0.1, 100))
	if collapsed.C <= healthy.C {
		t.Fatalf("collapsed neighbors did not raise contagion: %v vs %v", collapsed.C, healthy.C)
	}
	if collapsed.S >= healthy.S {
		t.Fatalf("collapsed neighbors did not lower posture: %v vs %v", collapsed.S, healthy.S)
	}
}

func TestHysteresisStatePersistsAfterStress(t *testing.T) {
	p := DefaultParams()
	stressed := last(Simulate(State{S: 0.8}, 1.0, nil, p, 0.1, 100))
	if stressed.H < 0.5 {
		t.Fatalf("stress did not raise hysteresis state: %+v", stressed)
	}
	// Remove stress: s recovers, but h should still be nonzero for a while.
	relaxed := last(Simulate(stressed, 0, nil, p, 0.1, 20))
	if relaxed.H <= 0 {
		t.Fatalf("hysteresis vanished instantly: %+v", relaxed)
	}
}

func TestRK4FiniteAndBounded(t *testing.T) {
	p := DefaultParams()
	xs := Simulate(State{S: 0.5, D: 2, C: 2, H: 0.5}, 2, []float64{0.1}, p, 0.1, 500)
	x := last(xs)
	for name, v := range map[string]float64{"s": x.S, "d": x.D, "c": x.C, "h": x.H} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("%s non-finite: %v", name, v)
		}
	}
	if x.S < 0 || x.S > 1 || x.H < 0 || x.H > 1 || x.D < 0 || x.C < 0 {
		t.Fatalf("projection failed: %+v", x)
	}
}

func TestRK4TimestepConvergence(t *testing.T) {
	p := DefaultParams()
	a := last(Simulate(State{S: 0.7, D: 0.5}, 0.5, []float64{0.6}, p, 0.1, 200))
	b := last(Simulate(State{S: 0.7, D: 0.5}, 0.5, []float64{0.6}, p, 0.05, 400))
	if math.Abs(a.S-b.S) > 5e-3 || math.Abs(a.C-b.C) > 5e-3 {
		t.Fatalf("dt convergence too loose: %+v vs %+v", a, b)
	}
}
