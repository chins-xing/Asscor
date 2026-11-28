// Package srddyn is the SRD-DYN v0.0.1 dynamics prototype.
//
// It implements the state vector and continuous drift from the SRD-DYN
// specification (docs/1-current/whitepapers/SRD-DYN.md). It is deliberately
// small: no EKF, no parameter fitting yet; those are later acceptance items.
package srddyn

import "math"

// State is (s,d,c,h): posture, accumulated debt, contagion load, hysteresis.
type State struct {
	S float64
	D float64
	C float64
	H float64
}

// Params are the drift coefficients. All rates are per unit time.
type Params struct {
	Rho     float64 // recovery
	Alpha   float64 // debt pressure
	Beta    float64 // contagion pressure
	Gamma   float64 // event impact
	Eta     float64 // collapse positive feedback
	Zeta    float64 // event -> debt
	Delta   float64 // debt decay
	Lambda  float64 // neighbor injection
	Nu      float64 // contagion decay
	Tau     float64 // hysteresis time constant
	Theta   float64 // collapse midpoint
	Epsilon float64 // collapse steepness
}

// DefaultParams returns conservative reference values (no fitting claim).
func DefaultParams() Params {
	return Params{
		Rho: 0.05, Alpha: 0.10, Beta: 0.10, Gamma: 0.50,
		Eta: 0.20, Zeta: 0.10, Delta: 0.02, Lambda: 0.20,
		Nu: 0.10, Tau: 10, Theta: 0.5, Epsilon: 0.05,
	}
}

func sigmoid(x float64) float64 {
	if x > 40 {
		return 0
	}
	if x < -40 {
		return 1
	}
	return 1 / (1 + math.Exp(x))
}

// Derivative computes dx/dt for one host. neighbors are the neighbors' current
// posture values s_j; an empty slice means no coupling.
func Derivative(x State, u float64, neighbors []float64, p Params) State {
	var d State
	d.S = p.Rho*(1-x.S) - p.Alpha*x.D - p.Beta*x.C - p.Gamma*u - p.Eta*x.H*x.D
	d.D = (1-x.S)*u + p.Zeta*u - p.Delta*x.D
	injection := 0.0
	if len(neighbors) > 0 {
		for _, s := range neighbors {
			injection += 1 - clamp01(s)
		}
		injection /= float64(len(neighbors))
	}
	d.C = p.Lambda*injection - p.Nu*x.C
	d.H = (sigmoid((x.S-p.Theta)/p.Epsilon) - x.H) / p.Tau
	return d
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func project(x State) State {
	x.S = clamp01(x.S)
	if x.D < 0 {
		x.D = 0
	}
	if x.C < 0 {
		x.C = 0
	}
	x.H = clamp01(x.H)
	return x
}

// RK4Step advances one host by dt.
func RK4Step(x State, u float64, neighbors []float64, p Params, dt float64) State {
	k1 := Derivative(x, u, neighbors, p)
	k2 := Derivative(addScaled(x, k1, dt/2), u, neighbors, p)
	k3 := Derivative(addScaled(x, k2, dt/2), u, neighbors, p)
	k4 := Derivative(addScaled(x, k3, dt), u, neighbors, p)
	out := State{
		S: x.S + dt/6*(k1.S+2*k2.S+2*k3.S+k4.S),
		D: x.D + dt/6*(k1.D+2*k2.D+2*k3.D+k4.D),
		C: x.C + dt/6*(k1.C+2*k2.C+2*k3.C+k4.C),
		H: x.H + dt/6*(k1.H+2*k2.H+2*k3.H+k4.H),
	}
	return project(out)
}

func addScaled(x, dx State, scale float64) State {
	return State{
		S: x.S + scale*dx.S,
		D: x.D + scale*dx.D,
		C: x.C + scale*dx.C,
		H: x.H + scale*dx.H,
	}
}

// Simulate runs a single host with constant event intensity u for steps.
func Simulate(initial State, u float64, neighbors []float64, p Params, dt float64, steps int) []State {
	out := make([]State, 0, steps+1)
	x := project(initial)
	out = append(out, x)
	for i := 0; i < steps; i++ {
		x = RK4Step(x, u, neighbors, p, dt)
		out = append(out, x)
	}
	return out
}
