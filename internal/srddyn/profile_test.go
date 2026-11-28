package srddyn

import (
	"math"
	"testing"
)

func profileSteps(truth Params) []ObserveStep {
	x := State{S: 0.8, D: 0.2, C: 0.1, H: 0.2}
	steps := make([]ObserveStep, 0, 240)
	for i := 0; i < 240; i++ {
		u := 0.0
		if i%20 < 5 {
			u = 1.0 + float64(i%3)*0.2
		}
		nb := []float64{0.9, 0.9}
		if i%40 < 20 {
			nb = []float64{0.2, 0.4}
		}
		steps = append(steps, ObserveStep{U: u, Neighbors: nb, X: x})
		x = RK4Step(x, u, nb, truth, 0.1)
	}
	return steps
}

func TestProfileLikelihoodDeltaMinimum(t *testing.T) {
	truth := DefaultParams()
	truth.Alpha = 0.20
	truth.Delta = 0.05
	truth.Lambda = 0.35
	steps := profileSteps(truth)

	grid := make([]float64, 0, 20)
	for i := 1; i <= 20; i++ {
		grid = append(grid, float64(i)*0.01)
	}
	pts, err := ProfileLikelihoodSObserved(steps, 0.1, steps[0].X, truth, "Delta", grid, []string{"Alpha", "Lambda"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != len(grid) {
		t.Fatalf("profile points = %d, want %d", len(pts), len(grid))
	}
	minSSE := math.Inf(1)
	minVal := 0.0
	for _, p := range pts {
		if math.IsNaN(p.SSE) || math.IsInf(p.SSE, 0) {
			t.Fatalf("non-finite SSE at Delta=%v", p.Value)
		}
		if p.SSE < minSSE {
			minSSE = p.SSE
			minVal = p.Value
		}
	}
	t.Logf("Delta profile min SSE=%g at Delta=%v (truth=0.05)", minSSE, minVal)
	if math.Abs(minVal-0.05) > 0.02 {
		t.Fatalf("Delta profile minimum at %v, want near 0.05", minVal)
	}
	// NOTE: exact initial hidden state + rich excitation makes Delta
	// identifiable here; the earlier coordinate-descent failure was a local
	// minimum, not proof of non-identifiability.
}
