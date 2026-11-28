package srddyn

import "math"

// Forecast propagates the current filter state without observations.
// It returns the predictive mean of s and its standard deviation per step.
func (f *Filter) Forecast(steps int, u float64, neighbors []float64) (mean, std []float64) {
	if steps <= 0 {
		return nil, nil
	}
	x := f.X
	P := f.P
	for i := 0; i < steps; i++ {
		F := numericalJacobian(x, u, neighbors, f.Params, f.DT)
		x = RK4Step(x, u, neighbors, f.Params, f.DT)
		var FP Matrix4
		for r := 0; r < 4; r++ {
			for c := 0; c < 4; c++ {
				var sum float64
				for k := 0; k < 4; k++ {
					sum += F[r][k] * P[k][c]
				}
				FP[r][c] = sum
			}
		}
		var next Matrix4
		for r := 0; r < 4; r++ {
			for c := 0; c < 4; c++ {
				var sum float64
				for k := 0; k < 4; k++ {
					sum += FP[r][k] * F[c][k]
				}
				next[r][c] = sum
			}
			next[r][r] += f.Q
		}
		P = next
		mean = append(mean, x.S)
		std = append(std, math.Sqrt(math.Max(0, P[0][0]+f.R)))
	}
	return mean, std
}
