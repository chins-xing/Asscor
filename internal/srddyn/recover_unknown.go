package srddyn

import (
	"fmt"
	"math"
)

// Recovered is the result of joint initial-state + parameter recovery.
type Recovered struct {
	Initial State
	Params  Params
	SSE     float64
}

// RecoverSObservedUnknownInitial jointly estimates the hidden initial state
// (D0/C0/H0; S0 must be observed) and the named parameters from s-only data.
// It is a coordinate-descent prototype; no claim of global identifiability.
func RecoverSObservedUnknownInitial(steps []ObserveStep, dt float64, initialGuess State, p0 Params, names []string) (Recovered, error) {
	if len(steps) < 3 {
		return Recovered{}, fmt.Errorf("need at least 3 observation steps")
	}
	if dt <= 0 {
		return Recovered{}, fmt.Errorf("dt must be positive")
	}
	probe := p0
	for _, n := range names {
		if !setParam(&probe, n, getParam(probe, n)) {
			return Recovered{}, fmt.Errorf("unknown parameter %q", n)
		}
	}
	bestX := project(initialGuess)
	bestP := p0
	bestSSE := objectiveS(steps, dt, bestX, bestP)

	deltas := []float64{-0.2, -0.1, -0.05, 0.05, 0.1, 0.2}
	for iter := 0; iter < 12; iter++ {
		improved := false
		for _, field := range []string{"D", "C", "H"} {
			baseX := bestX
			for _, d := range deltas {
				candX := baseX
				switch field {
				case "D":
					candX.D += d
				case "C":
					candX.C += d
				case "H":
					candX.H += d
				}
				candX = project(candX)
				fitted, err := recoverWith(steps, dt, candX, bestP, names, objectiveS)
				if err != nil {
					return Recovered{}, err
				}
				sse := objectiveS(steps, dt, candX, fitted)
				if sse < bestSSE {
					bestSSE, bestX, bestP = sse, candX, fitted
					improved = true
				}
			}
		}
		// Parameter-only refresh at the current initial state.
		fitted, err := recoverWith(steps, dt, bestX, bestP, names, objectiveS)
		if err != nil {
			return Recovered{}, err
		}
		sse := objectiveS(steps, dt, bestX, fitted)
		if sse < bestSSE-1e-12 {
			bestSSE, bestP = sse, fitted
			improved = true
		}
		if !improved {
			break
		}
	}
	if math.IsNaN(bestSSE) || math.IsInf(bestSSE, 0) {
		return Recovered{}, fmt.Errorf("recovery produced non-finite SSE")
	}
	return Recovered{Initial: bestX, Params: bestP, SSE: bestSSE}, nil
}
