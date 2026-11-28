package srddyn

// ApplyEvent applies one failure/attack impulse: posture drops and debt rises.
func ApplyEvent(x State, weight float64, p Params) State {
	if weight < 0 {
		weight = 0
	}
	x.S -= p.Gamma * weight
	x.D += p.Zeta * weight
	return project(x)
}

// SimulateEvents runs drift and applies scheduled events at step indices.
func SimulateEvents(initial State, events map[int]float64, u float64, neighbors []float64, p Params, dt float64, steps int) []State {
	x := project(initial)
	out := make([]State, 0, steps+1)
	out = append(out, x)
	for i := 0; i < steps; i++ {
		x = RK4Step(x, u, neighbors, p, dt)
		if w, ok := events[i]; ok {
			x = ApplyEvent(x, w, p)
		}
		out = append(out, x)
	}
	return out
}
