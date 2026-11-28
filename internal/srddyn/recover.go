package srddyn

import (
	"fmt"
	"math"
)

// ObserveStep is one synthetic observation used for parameter recovery.
// Neighbors is the neighbors' posture at that step.
type ObserveStep struct {
	U         float64
	Neighbors []float64
	X         State
}

// RecoverParams does a small coordinate-descent fit over the named scalar
// parameters. It is a validation prototype, not a production calibrator:
// observations are full-state (oracle) so identifiability is not hidden by
// partial observation.
func RecoverParams(steps []ObserveStep, dt float64, initial State, p0 Params, names []string) (Params, error) {
	return recoverWith(steps, dt, initial, p0, names, func(steps []ObserveStep, dt float64, initial State, p Params) float64 {
		return objective(steps, dt, initial, p)
	})
}

// RecoverParamsSObserved fits using only s observations (the hidden initial
// state is assumed known). It is the next step after full-state recovery, but
// still not a general partial-observation proof: D/C/H at t0 are oracle inputs.
func RecoverParamsSObserved(steps []ObserveStep, dt float64, initial State, p0 Params, names []string) (Params, error) {
	return recoverWith(steps, dt, initial, p0, names, func(steps []ObserveStep, dt float64, initial State, p Params) float64 {
		return objectiveS(steps, dt, initial, p)
	})
}

func recoverWith(steps []ObserveStep, dt float64, initial State, p0 Params, names []string, objective func([]ObserveStep, float64, State, Params) float64) (Params, error) {
	if len(steps) < 3 {
		return p0, fmt.Errorf("need at least 3 observation steps")
	}
	if dt <= 0 {
		return p0, fmt.Errorf("dt must be positive")
	}
	probe := p0
	for _, name := range names {
		if !setParam(&probe, name, getParam(probe, name)) {
			return p0, fmt.Errorf("unknown parameter %q", name)
		}
	}
	p := p0
	best := objective(steps, dt, initial, p)
	for iter := 0; iter < 40; iter++ {
		improved := false
		for _, name := range names {
			base := p
			bestP := p
			for _, factor := range []float64{0.5, 0.8, 0.9, 1.1, 1.2, 2.0} {
				cand := base
				v := getParam(base, name) * factor
				if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
					continue
				}
				if !setParam(&cand, name, v) {
					return p, fmt.Errorf("unknown parameter %q", name)
				}
				if err := objective(steps, dt, initial, cand); err < best {
					best = err
					bestP = cand
					improved = true
				}
			}
			p = bestP
		}
		if !improved {
			break
		}
	}
	return p, nil
}

func objectiveS(steps []ObserveStep, dt float64, initial State, p Params) float64 {
	x := project(initial)
	var err float64
	for i := 0; i < len(steps)-1; i++ {
		x = RK4Step(x, steps[i].U, steps[i].Neighbors, p, dt)
		err += sq(x.S - steps[i+1].X.S)
	}
	return err
}

func objective(steps []ObserveStep, dt float64, initial State, p Params) float64 {
	x := project(initial)
	var err float64
	for i := 0; i < len(steps)-1; i++ {
		x = RK4Step(x, steps[i].U, steps[i].Neighbors, p, dt)
		obs := steps[i+1].X
		err += sq(x.S-obs.S) + sq(x.D-obs.D) + sq(x.C-obs.C) + sq(x.H-obs.H)
	}
	return err
}

func sq(v float64) float64 { return v * v }

func getParam(p Params, name string) float64 {
	switch name {
	case "Rho":
		return p.Rho
	case "Alpha":
		return p.Alpha
	case "Beta":
		return p.Beta
	case "Gamma":
		return p.Gamma
	case "Eta":
		return p.Eta
	case "Zeta":
		return p.Zeta
	case "Delta":
		return p.Delta
	case "Lambda":
		return p.Lambda
	case "Nu":
		return p.Nu
	case "Tau":
		return p.Tau
	case "Theta":
		return p.Theta
	case "Epsilon":
		return p.Epsilon
	}
	return 0
}

func setParam(p *Params, name string, v float64) bool {
	switch name {
	case "Rho":
		p.Rho = v
	case "Alpha":
		p.Alpha = v
	case "Beta":
		p.Beta = v
	case "Gamma":
		p.Gamma = v
	case "Eta":
		p.Eta = v
	case "Zeta":
		p.Zeta = v
	case "Delta":
		p.Delta = v
	case "Lambda":
		p.Lambda = v
	case "Nu":
		p.Nu = v
	case "Tau":
		p.Tau = v
	case "Theta":
		p.Theta = v
	case "Epsilon":
		p.Epsilon = v
	default:
		return false
	}
	return true
}
