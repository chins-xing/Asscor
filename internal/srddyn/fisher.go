package srddyn

import (
	"fmt"
	"math"
)

// FisherInformation computes the observed-information matrix for the named
// parameters, using s-only observations and a scalar observation variance.
// It is a numerical prototype: sensitivities are central-ish finite
// differences of the s trajectory.
func FisherInformation(steps []ObserveStep, dt float64, initial State, p Params, names []string, obsVar float64) ([][]float64, error) {
	if len(steps) < 2 {
		return nil, fmt.Errorf("need at least 2 observation steps")
	}
	if dt <= 0 {
		return nil, fmt.Errorf("dt must be positive")
	}
	if obsVar <= 0 {
		obsVar = 1
	}
	probe := p
	for _, name := range names {
		if !setParam(&probe, name, getParam(probe, name)) {
			return nil, fmt.Errorf("unknown parameter %q", name)
		}
	}

	base := sTrajectory(steps, dt, initial, p)
	sens := make([][]float64, len(names))
	for j, name := range names {
		v := getParam(p, name)
		eps := 1e-5 * math.Max(1, math.Abs(v))
		pert := p
		if !setParam(&pert, name, v+eps) {
			return nil, fmt.Errorf("unknown parameter %q", name)
		}
		tr := sTrajectory(steps, dt, initial, pert)
		s := make([]float64, len(tr))
		for i := range tr {
			s[i] = (tr[i] - base[i]) / eps
		}
		sens[j] = s
	}

	out := make([][]float64, len(names))
	for i := range out {
		out[i] = make([]float64, len(names))
		for k := range out[i] {
			var sum float64
			for t := range base {
				sum += sens[i][t] * sens[k][t] / obsVar
			}
			out[i][k] = sum
		}
	}
	return out, nil
}

func sTrajectory(steps []ObserveStep, dt float64, initial State, p Params) []float64 {
	x := project(initial)
	out := make([]float64, 0, len(steps))
	for i := 0; i < len(steps); i++ {
		out = append(out, x.S)
		if i < len(steps)-1 {
			x = RK4Step(x, steps[i].U, steps[i].Neighbors, p, dt)
		}
	}
	return out
}
