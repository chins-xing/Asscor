package srddyn

import (
	"math"
	"testing"
)

func TestApplyEventJump(t *testing.T) {
	p := DefaultParams()
	x := State{S: 0.9, D: 0.1, C: 0, H: 0}
	y := ApplyEvent(x, 1.0, p)
	if y.S >= x.S {
		t.Fatalf("event did not lower posture: %v -> %v", x.S, y.S)
	}
	if y.D <= x.D {
		t.Fatalf("event did not raise debt: %v -> %v", x.D, y.D)
	}
	if y.S < 0 || y.S > 1 || y.D < 0 {
		t.Fatalf("event violated projection: %+v", y)
	}
}

func TestSobolIndicesAdditive(t *testing.T) {
	base := DefaultParams()
	names := []string{"Alpha", "Delta"}
	ranges := map[string][2]float64{"Alpha": {0, 1}, "Delta": {0, 1}}
	eval := func(p Params) float64 { return p.Alpha + 2*p.Delta }
	first, total, err := SobolIndices(eval, base, names, ranges, 4000, 42)
	if err != nil {
		t.Fatal(err)
	}
	// Var(alpha)=1/12, Var(2*delta)=4/12 => first-order 0.2 / 0.8.
	if math.Abs(first["Alpha"]-0.2) > 0.15 {
		t.Errorf("S_Alpha = %v, want ~0.2", first["Alpha"])
	}
	if math.Abs(first["Delta"]-0.8) > 0.15 {
		t.Errorf("S_Delta = %v, want ~0.8", first["Delta"])
	}
	if total["Alpha"] < first["Alpha"]-0.05 || total["Delta"] < first["Delta"]-0.05 {
		t.Errorf("total indices below first-order: %+v %+v", total, first)
	}
}

func TestProperScoringMetrics(t *testing.T) {
	if got := CRPSNormal(0, 1, 0); math.Abs(got-0.2337) > 1e-3 {
		t.Errorf("CRPS = %v, want ~0.2337", got)
	}
	if got := Brier(0.7, true); math.Abs(got-0.09) > 1e-9 {
		t.Errorf("Brier = %v, want 0.09", got)
	}
	if got := AUC([]float64{0.1, 0.4, 0.35, 0.8}, []bool{false, false, true, true}); math.Abs(got-0.75) > 1e-9 {
		t.Errorf("AUC = %v, want 0.75", got)
	}
	if got := RMSE([]float64{1, 2}, []float64{1, 4}); math.Abs(got-math.Sqrt2) > 1e-9 {
		t.Errorf("RMSE = %v", got)
	}
}

func TestForecastBeatsPersistence(t *testing.T) {
	p := DefaultParams()
	initial := State{S: 0.8, D: 0.4, C: 0.1, H: 0.3}
	steps := 20
	truth := Simulate(initial, 0.2, []float64{0.5}, p, 0.1, steps)

	// Exact initial state/params: the forecast should track truth, while
	// persistence (last observed s) cannot.
	f := NewFilter(initial, p, 0.1, 0, 0, 0)
	pred, _ := f.Forecast(steps, 0.2, []float64{0.5})
	truthS := make([]float64, 0, len(truth)-1)
	persistence := make([]float64, 0, len(truth)-1)
	for i := 1; i < len(truth); i++ {
		truthS = append(truthS, truth[i].S)
		persistence = append(persistence, truth[0].S)
	}
	forecastRMSE := RMSE(pred, truthS)
	persistRMSE := RMSE(persistence, truthS)
	if forecastRMSE >= persistRMSE {
		t.Fatalf("forecast RMSE %v not better than persistence %v", forecastRMSE, persistRMSE)
	}
}
