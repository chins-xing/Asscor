package srddyn

import (
	"math"
	"testing"
)

func TestFilterCovarianceShrinksAndTracksObservation(t *testing.T) {
	p := DefaultParams()
	p.Rho = 0 // constant true posture for a deterministic test
	f := NewFilter(State{S: 0.7}, p, 0.1, 1e-4, 1e-3, 0.2)
	before := f.P[0][0]
	for i := 0; i < 200; i++ {
		f.Predict(0, nil)
		obs := 0.7 + 0.05*math.Sin(float64(i)*0.7)
		f.Update(obs)
	}
	if f.P[0][0] >= before {
		t.Fatalf("posterior variance did not shrink: %v -> %v", before, f.P[0][0])
	}
	if math.Abs(f.X.S-0.7) > 0.03 {
		t.Fatalf("filtered s = %v, want near 0.7", f.X.S)
	}
	if c := f.Confidence(1.0); c <= 0 || c >= 1 {
		t.Fatalf("confidence out of range: %v", c)
	}
}

func TestFilterFiniteUnderNoise(t *testing.T) {
	p := DefaultParams()
	f := NewFilter(State{S: 0.5, D: 0.5, C: 0.5, H: 0.5}, p, 0.1, 1e-3, 1e-2, 0.2)
	for i := 0; i < 100; i++ {
		f.Predict(0.2, []float64{0.4})
		f.Update(0.5 + 0.2*math.Sin(float64(i)))
	}
	for name, v := range map[string]float64{
		"s": f.X.S, "d": f.X.D, "c": f.X.C, "h": f.X.H,
		"p00": f.P[0][0], "p11": f.P[1][1],
	} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("%s non-finite: %v", name, v)
		}
	}
}
