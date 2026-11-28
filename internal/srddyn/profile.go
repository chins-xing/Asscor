package srddyn

import (
	"fmt"
	"math"
)

// ProfilePoint is one fixed-value slice of a profile likelihood.
type ProfilePoint struct {
	Value  float64
	SSE    float64
	Fitted Params
}

// ProfileLikelihoodSObserved fixes one parameter on a grid and re-fits the
// other named parameters against s-only observations. It is a numerical
// diagnostic, not a full confidence-interval calculator (no chi-square
// calibration yet).
func ProfileLikelihoodSObserved(steps []ObserveStep, dt float64, initial State, base Params, fixedName string, grid []float64, fitNames []string) ([]ProfilePoint, error) {
	if len(grid) == 0 {
		return nil, fmt.Errorf("empty grid")
	}
	if fixedName == "" {
		return nil, fmt.Errorf("fixed parameter name required")
	}
	probe := base
	if !setParam(&probe, fixedName, getParam(probe, fixedName)) {
		return nil, fmt.Errorf("unknown parameter %q", fixedName)
	}
	for _, n := range fitNames {
		if n == fixedName {
			return nil, fmt.Errorf("%q cannot be both fixed and fitted", n)
		}
		if !setParam(&probe, n, getParam(probe, n)) {
			return nil, fmt.Errorf("unknown parameter %q", n)
		}
	}
	out := make([]ProfilePoint, 0, len(grid))
	for _, v := range grid {
		if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		p := base
		if !setParam(&p, fixedName, v) {
			return nil, fmt.Errorf("unknown parameter %q", fixedName)
		}
		fitted, err := recoverWith(steps, dt, initial, p, fitNames, objectiveS)
		if err != nil {
			return nil, err
		}
		out = append(out, ProfilePoint{Value: v, SSE: objectiveS(steps, dt, initial, fitted), Fitted: fitted})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid grid points")
	}
	return out, nil
}
