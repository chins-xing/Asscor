package srddyn

import (
	"math"
	"testing"
)

func TestFisherInformationSOnly(t *testing.T) {
	truth := DefaultParams()
	steps := syntheticSteps(truth, 60, 0.1)
	names := []string{"Alpha", "Delta", "Lambda"}
	I, err := FisherInformation(steps, 0.1, steps[0].X, truth, names, 1e-3)
	if err != nil {
		t.Fatal(err)
	}
	if len(I) != len(names) {
		t.Fatalf("matrix dimension = %d", len(I))
	}
	for i := range I {
		if I[i][i] <= 0 || math.IsNaN(I[i][i]) || math.IsInf(I[i][i], 0) {
			t.Fatalf("I[%d][%d] = %v", i, i, I[i][i])
		}
		for j := range I[i] {
			if math.Abs(I[i][j]-I[j][i]) > 1e-6*math.Max(1, math.Abs(I[i][j])) {
				t.Fatalf("matrix not symmetric at %d,%d: %v vs %v", i, j, I[i][j], I[j][i])
			}
		}
	}
}

func TestFisherUnknownParameter(t *testing.T) {
	steps := syntheticSteps(DefaultParams(), 5, 0.1)
	if _, err := FisherInformation(steps, 0.1, steps[0].X, DefaultParams(), []string{"Bogus"}, 1); err == nil {
		t.Fatal("unknown parameter must error")
	}
}
