package srddyn

import (
	"math"
	"testing"
)

func syntheticSteps(truth Params, n int, dt float64) []ObserveStep {
	steps := make([]ObserveStep, 0, n)
	x := State{S: 0.8, D: 0.2, C: 0.1, H: 0.2}
	for i := 0; i < n; i++ {
		u := 0.2 + 0.1*math.Sin(float64(i)*0.3)
		nb := []float64{0.7, 0.9}
		steps = append(steps, ObserveStep{U: u, Neighbors: nb, X: x})
		x = RK4Step(x, u, nb, truth, dt)
	}
	return steps
}

func TestRecoverParamsFromFullState(t *testing.T) {
	truth := DefaultParams()
	truth.Alpha = 0.20
	truth.Delta = 0.05
	truth.Lambda = 0.35
	steps := syntheticSteps(truth, 80, 0.1)

	initial := truth
	initial.Alpha = 0.10
	initial.Delta = 0.02
	initial.Lambda = 0.15

	got, err := RecoverParams(steps, 0.1, steps[0].X, initial, []string{"Alpha", "Delta", "Lambda"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"Alpha": truth.Alpha, "Delta": truth.Delta, "Lambda": truth.Lambda} {
		gotV := getParam(got, name)
		if math.Abs(gotV-want)/want > 0.20 {
			t.Errorf("%s recovered %v, want %v (±20%%)", name, gotV, want)
		}
	}
}

func TestRecoverParamsUnknownName(t *testing.T) {
	steps := syntheticSteps(DefaultParams(), 5, 0.1)
	if _, err := RecoverParams(steps, 0.1, steps[0].X, DefaultParams(), []string{"Bogus"}); err == nil {
		t.Fatal("unknown parameter must error")
	}
}
