package srddyn

import (
	"math"
	"sort"
)

// CRPSNormal is the closed-form CRPS for a normal predictive distribution.
func CRPSNormal(mean, sigma, y float64) float64 {
	if sigma <= 0 {
		return math.Abs(y - mean)
	}
	z := (y - mean) / sigma
	phi := math.Exp(-0.5*z*z) / math.Sqrt(2*math.Pi)
	Phi := 0.5 * (1 + math.Erf(z/math.Sqrt2))
	return sigma * (z*(2*Phi-1) + 2*phi - 1/math.Sqrt(math.Pi))
}

// Brier is the squared error of a probability forecast.
func Brier(prob float64, outcome bool) float64 {
	y := 0.0
	if outcome {
		y = 1
	}
	return (prob - y) * (prob - y)
}

// AUC computes the ROC AUC for scores and binary labels (1=positive).
func AUC(scores []float64, labels []bool) float64 {
	type pair struct {
		s float64
		y bool
	}
	ps := make([]pair, 0, len(scores))
	pos, neg := 0, 0
	for i := range scores {
		ps = append(ps, pair{scores[i], labels[i]})
		if labels[i] {
			pos++
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		return 0
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].s < ps[j].s })
	// Average ranks handle ties.
	var rankSum float64
	for i := 0; i < len(ps); {
		j := i
		for j < len(ps) && ps[j].s == ps[i].s {
			j++
		}
		avgRank := (float64(i+1) + float64(j)) / 2
		for k := i; k < j; k++ {
			if ps[k].y {
				rankSum += avgRank
			}
		}
		i = j
	}
	return (rankSum - float64(pos)*(float64(pos)+1)/2) / (float64(pos) * float64(neg))
}

// RMSE over equal-length sequences.
func RMSE(pred, truth []float64) float64 {
	if len(pred) == 0 || len(pred) != len(truth) {
		return math.NaN()
	}
	var s float64
	for i := range pred {
		d := pred[i] - truth[i]
		s += d * d
	}
	return math.Sqrt(s / float64(len(pred)))
}
