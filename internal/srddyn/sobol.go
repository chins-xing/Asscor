package srddyn

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// SobolIndices estimates first-order and total Sobol indices for the named
// parameters of a scalar output function, using Saltelli A/B/AB sampling.
// It is a validation prototype (finite N); no confidence intervals yet.
func SobolIndices(eval func(Params) float64, base Params, names []string, ranges map[string][2]float64, n int, seed int64) (first, total map[string]float64, err error) {
	return sobolOnce(eval, base, names, ranges, n, seed)
}

func sobolOnce(eval func(Params) float64, base Params, names []string, ranges map[string][2]float64, n int, seed int64) (first, total map[string]float64, err error) {
	if n < 100 {
		return nil, nil, fmt.Errorf("n must be >= 100")
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("no parameters")
	}
	probe := base
	for _, name := range names {
		if !setParam(&probe, name, getParam(probe, name)) {
			return nil, nil, fmt.Errorf("unknown parameter %q", name)
		}
		r, ok := ranges[name]
		if !ok || r[1] <= r[0] {
			return nil, nil, fmt.Errorf("invalid range for %q", name)
		}
	}

	rng := rand.New(rand.NewSource(seed))
	k := len(names)
	A := make([][]float64, n)
	B := make([][]float64, n)
	for i := 0; i < n; i++ {
		A[i] = make([]float64, k)
		B[i] = make([]float64, k)
		for j, name := range names {
			r := ranges[name]
			A[i][j] = r[0] + rng.Float64()*(r[1]-r[0])
			B[i][j] = r[0] + rng.Float64()*(r[1]-r[0])
		}
	}

	yA := make([]float64, n)
	yB := make([]float64, n)
	for i := 0; i < n; i++ {
		yA[i] = eval(paramsFromRow(base, names, A[i]))
		yB[i] = eval(paramsFromRow(base, names, B[i]))
	}
	varY := variance(append(append([]float64{}, yA...), yB...))
	if varY <= 0 {
		return nil, nil, fmt.Errorf("output variance is zero")
	}

	first = make(map[string]float64, k)
	total = make(map[string]float64, k)
	for j, name := range names {
		yAB := make([]float64, n)
		for i := 0; i < n; i++ {
			row := append([]float64{}, A[i]...)
			row[j] = B[i][j]
			yAB[i] = eval(paramsFromRow(base, names, row))
		}
		var s1, st float64
		for i := 0; i < n; i++ {
			s1 += yB[i] * (yAB[i] - yA[i])
			st += (yA[i] - yAB[i]) * (yA[i] - yAB[i])
		}
		first[name] = (s1 / float64(n)) / varY
		total[name] = (0.5 * st / float64(n)) / varY
	}
	return first, total, nil
}

func paramsFromRow(base Params, names []string, row []float64) Params {
	p := base
	for j, name := range names {
		_ = setParam(&p, name, row[j])
	}
	return p
}

func variance(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var mean float64
	for _, v := range xs {
		mean += v
	}
	mean /= float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - mean) * (x - mean)
	}
	return v / float64(len(xs)-1)
}

// clampIndices is kept for future CI work; Saltelli estimates can be slightly
// negative/above 1 with finite N.
func clampIndices(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	return v
}

// SobolResult carries point estimates and percentile bootstrap intervals.
type SobolResult struct {
	First   map[string]float64
	Total   map[string]float64
	FirstCI map[string][2]float64
	TotalCI map[string][2]float64
}

// SobolIndicesCI runs independent Saltelli replicates and returns 5/95
// percentile bootstrap intervals (finite-sample prototype, not a proof).
func SobolIndicesCI(eval func(Params) float64, base Params, names []string, ranges map[string][2]float64, n int, seed int64, replicates int) (SobolResult, error) {
	if replicates < 5 {
		replicates = 5
	}
	type sample struct {
		first, total map[string]float64
	}
	samples := make([]sample, 0, replicates)
	for r := 0; r < replicates; r++ {
		f, t, err := sobolOnce(eval, base, names, ranges, n, seed+int64(r))
		if err != nil {
			return SobolResult{}, err
		}
		samples = append(samples, sample{first: f, total: t})
	}
	res := SobolResult{
		First:   samples[0].first,
		Total:   samples[0].total,
		FirstCI: make(map[string][2]float64, len(names)),
		TotalCI: make(map[string][2]float64, len(names)),
	}
	for _, name := range names {
		fs := make([]float64, 0, len(samples))
		ts := make([]float64, 0, len(samples))
		for _, s := range samples {
			fs = append(fs, s.first[name])
			ts = append(ts, s.total[name])
		}
		res.FirstCI[name] = percentile95(fs)
		res.TotalCI[name] = percentile95(ts)
	}
	return res, nil
}

func percentile95(xs []float64) [2]float64 {
	if len(xs) == 0 {
		return [2]float64{}
	}
	sort.Float64s(xs)
	lo := xs[int(0.05*float64(len(xs)-1))]
	hi := xs[int(0.95*float64(len(xs)-1))]
	return [2]float64{lo, hi}
}
