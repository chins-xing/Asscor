package srddyn

import "math"

// Matrix4 is a 4x4 covariance/transition matrix for (s,d,c,h).
type Matrix4 [4][4]float64

// Filter is a small EKF over State, observing only s (posture).
type Filter struct {
	X        State
	P        Matrix4
	Params   Params
	DT       float64
	Q        float64 // process noise (diagonal)
	R        float64 // observation noise variance
	lastU    float64
	lastNear []float64
}

// NewFilter creates an EKF with diagonal initial covariance.
func NewFilter(initial State, p Params, dt, q, r, initialVar float64) *Filter {
	if dt <= 0 {
		dt = 0.1
	}
	if initialVar <= 0 {
		initialVar = 0.1
	}
	var P Matrix4
	for i := 0; i < 4; i++ {
		P[i][i] = initialVar
	}
	return &Filter{X: project(initial), P: P, Params: p, DT: dt, Q: q, R: r}
}

func numericalJacobian(x State, u float64, neighbors []float64, p Params, dt float64) Matrix4 {
	const eps = 1e-6
	base := RK4Step(x, u, neighbors, p, dt)
	var J Matrix4
	for j := 0; j < 4; j++ {
		xp := x
		switch j {
		case 0:
			xp.S += eps
		case 1:
			xp.D += eps
		case 2:
			xp.C += eps
		case 3:
			xp.H += eps
		}
		fp := RK4Step(xp, u, neighbors, p, dt)
		J[0][j] = (fp.S - base.S) / eps
		J[1][j] = (fp.D - base.D) / eps
		J[2][j] = (fp.C - base.C) / eps
		J[3][j] = (fp.H - base.H) / eps
	}
	return J
}

func (f *Filter) Predict(u float64, neighbors []float64) {
	f.lastU = u
	f.lastNear = append([]float64(nil), neighbors...)
	F := numericalJacobian(f.X, u, neighbors, f.Params, f.DT)
	f.X = RK4Step(f.X, u, neighbors, f.Params, f.DT)
	// P = F P F^T + QI
	var FP Matrix4
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			var sum float64
			for k := 0; k < 4; k++ {
				sum += F[i][k] * f.P[k][j]
			}
			FP[i][j] = sum
		}
	}
	var P Matrix4
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			var sum float64
			for k := 0; k < 4; k++ {
				sum += FP[i][k] * F[j][k]
			}
			P[i][j] = sum
		}
		P[i][i] += f.Q
	}
	f.P = P
	f.normalize()
}

// Update applies one scalar observation of s.
func (f *Filter) Update(observedS float64) {
	s := f.P[0][0] + f.R
	if s <= 0 {
		return
	}
	var K [4]float64
	for i := 0; i < 4; i++ {
		K[i] = f.P[i][0] / s
	}
	innov := observedS - f.X.S
	f.X = project(State{
		S: f.X.S + K[0]*innov,
		D: f.X.D + K[1]*innov,
		C: f.X.C + K[2]*innov,
		H: f.X.H + K[3]*innov,
	})
	// P = (I - K H) P, H = [1,0,0,0]
	var P Matrix4
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			P[i][j] = f.P[i][j] - K[i]*f.P[0][j]
		}
	}
	f.P = P
	f.normalize()
}

// Confidence is 1 - tr(P)/(tr(P)+kappa), from the SRD-DYN spec.
func (f *Filter) Confidence(kappa float64) float64 {
	if kappa <= 0 {
		kappa = 1
	}
	tr := f.P[0][0] + f.P[1][1] + f.P[2][2] + f.P[3][3]
	return 1 - tr/(tr+kappa)
}

func (f *Filter) normalize() {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if math.IsNaN(f.P[i][j]) || math.IsInf(f.P[i][j], 0) {
				f.P[i][j] = 0
			}
		}
	}
	// symmetrize and keep diagonal non-negative
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			avg := (f.P[i][j] + f.P[j][i]) / 2
			f.P[i][j] = avg
			f.P[j][i] = avg
		}
		if f.P[i][i] < 0 {
			f.P[i][i] = 0
		}
	}
}
