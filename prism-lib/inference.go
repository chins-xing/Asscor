package prism

import "math"

// ----------------------------------------------------------
// Inference Layer — State Inference & Prediction
// ----------------------------------------------------------

// MarkovDefaultTransition returns the default state transition matrix (daily step)
// based on expert priors (white paper §14.8):
//
//	    Stable   Degraded  Untrusted  Collapse
//	Stable     0.95   0.04      0.01      0.00
//	Degraded   0.02   0.90      0.07      0.01
//	Untrusted  0.00   0.03      0.85      0.12
//	Collapse   0.00   0.00      0.05      0.95
func MarkovDefaultTransition() [4][4]float64 {
	return [4][4]float64{
		{0.95, 0.04, 0.01, 0.00}, // Stable
		{0.02, 0.90, 0.07, 0.01}, // Degraded
		{0.00, 0.03, 0.85, 0.12}, // Untrusted
		{0.00, 0.00, 0.05, 0.95}, // Collapse
	}
}

// matMulVec4 multiplies a 4x4 matrix by a 4-element row vector.
// Result: result[j] = Σ_i vector[i] * matrix[i][j]
func matMulVec4(vec [4]float64, mat [4][4]float64) [4]float64 {
	var out [4]float64
	for j := 0; j < 4; j++ {
		sum := 0.0
		for i := 0; i < 4; i++ {
			sum += vec[i] * mat[i][j]
		}
		out[j] = sum
	}
	return out
}

// matPow computes matrix^steps via exponentiation by squaring.
func matPow(mat [4][4]float64, steps int) [4][4]float64 {
	// Identity matrix
	result := [4][4]float64{
		{1, 0, 0, 0},
		{0, 1, 0, 0},
		{0, 0, 1, 0},
		{0, 0, 0, 1},
	}
	base := mat
	n := steps
	for n > 0 {
		if n&1 == 1 {
			// result = result * base
			var next [4][4]float64
			for i := 0; i < 4; i++ {
				for j := 0; j < 4; j++ {
					sum := 0.0
					for k := 0; k < 4; k++ {
						sum += result[i][k] * base[k][j]
					}
					next[i][j] = sum
				}
			}
			result = next
		}
		// base = base * base
		var sq [4][4]float64
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				sum := 0.0
				for k := 0; k < 4; k++ {
					sum += base[i][k] * base[k][j]
				}
				sq[i][j] = sum
			}
		}
		base = sq
		n >>= 1
	}
	return result
}

// MarkovChainModel is the default inference model using a discrete-time Markov chain.
type MarkovChainModel struct {
	transition [4][4]float64
	name       string
}

// NewMarkovChainModel creates a MarkovChainModel with the given transition matrix.
// If transition is nil, the default expert-prior matrix is used.
func NewMarkovChainModel(transition [4][4]float64) *MarkovChainModel {
	if isZeroMatrix(transition) {
		transition = MarkovDefaultTransition()
	}
	return &MarkovChainModel{
		transition: transition,
		name:       "MarkovChain",
	}
}

// DefaultInferenceModel returns a MarkovChainModel with default priors.
func DefaultInferenceModel() InferenceModel {
	return NewMarkovChainModel(MarkovDefaultTransition())
}

func (m *MarkovChainModel) Name() string { return m.name }

// ----------------------------------------------------------
// Bayesian Inference Model
// ----------------------------------------------------------

// BayesModel uses Bayesian belief update with conditional probability tables.
// Instead of fixed transition probabilities, it incorporates evidence (observed
// check failures, external threat scores) to update the posterior state belief.
type BayesModel struct {
	name string
	// CPT[state][evidence][nextState] — conditional P(nextState | state, evidence)
	cpt [4][2][4]float64
}

// NewBayesModel creates a Bayesian inference model. The CPT is derived from
// the Markov transition matrix: strong evidence (failure=1) shifts probabilities
// toward degraded states; weak evidence (failure=0) shifts toward stable states.
func NewBayesModel() *BayesModel {
	// Base transition from Markov priors
	base := MarkovDefaultTransition()

	var cpt [4][2][4]float64
	for state := 0; state < 4; state++ {
		// evidence=0 (good news): shift toward stable
		for j := 0; j < 4; j++ {
			if j <= state {
				cpt[state][0][j] = base[state][j] * 1.2
			} else {
				cpt[state][0][j] = base[state][j] * 0.5
			}
		}

		// evidence=1 (bad news): shift toward degraded
		for j := 0; j < 4; j++ {
			if j >= state {
				cpt[state][1][j] = base[state][j] * 1.3
			} else {
				cpt[state][1][j] = base[state][j] * 0.3
			}
		}
	}

	// Normalize each row
	for state := 0; state < 4; state++ {
		for ev := 0; ev < 2; ev++ {
			sum := 0.0
			for j := 0; j < 4; j++ {
				sum += cpt[state][ev][j]
			}
			if sum > 0 {
				for j := 0; j < 4; j++ {
					cpt[state][ev][j] /= sum
				}
			}
		}
	}

	return &BayesModel{name: "BayesNet", cpt: cpt}
}

func (b *BayesModel) Name() string { return b.name }

func (b *BayesModel) Predict(current [4]float64, steps int) (future [4]float64, confidence float64) {
	if steps <= 0 {
		return current, 1.0
	}

	// Evidence score from current state: higher Collapse/Untrusted probability → more bad-news evidence
	evidenceWeight := current[2]*0.5 + current[3]*0.8

	// Blend transitions based on evidence: interleave good-news and bad-news transitions
	posterior := current
	for k := 0; k < steps; k++ {
		var next [4]float64
		for i := 0; i < 4; i++ {
			good := matMulVec4SingleState(i, b.cpt[i][0])
			bad := matMulVec4SingleState(i, b.cpt[i][1])
			for j := 0; j < 4; j++ {
				blended := (1.0-evidenceWeight)*good[j] + evidenceWeight*bad[j]
				next[j] += posterior[i] * blended
			}
		}
		posterior = next
	}

	// Confidence: posterior entropy reduction vs prior entropy
	priorEntropy := 0.0
	for _, p := range current {
		if p > 1e-12 {
			priorEntropy -= p * math.Log2(p)
		}
	}
	posteriorEntropy := 0.0
	for _, p := range posterior {
		if p > 1e-12 {
			posteriorEntropy -= p * math.Log2(p)
		}
	}
	maxEntropy := math.Log2(4.0)

	entropyGain := (priorEntropy - posteriorEntropy) / maxEntropy
	horizonDecay := 1.0 / (1.0 + float64(steps)*0.02)

	confidence = math.Max(0.0, math.Min(1.0, (entropyGain+1.0)/2.0*horizonDecay))
	return posterior, confidence
}

func matMulVec4SingleState(state int, row [4]float64) [4]float64 {
	return row
}

// Predict projects the state vector forward by k steps using matrix exponentiation.
func (m *MarkovChainModel) Predict(current [4]float64, steps int) (future [4]float64, confidence float64) {
	if steps <= 0 {
		return current, 1.0
	}

	matK := matPow(m.transition, steps)

	// S_{t+k} = S_t × T^k
	future = matMulVec4(current, matK)

	// Confidence: entropy-based. Lower entropy → higher confidence.
	// Also degrades with prediction horizon.
	entropy := 0.0
	for _, p := range future {
		if p > 1e-12 {
			entropy -= p * math.Log2(p)
		}
	}
	maxEntropy := math.Log2(4.0) // log2(4) = 2
	entropyConf := 1.0 - entropy/maxEntropy

	// Horizon decay: longer predictions are less confident
	horizonDecay := 1.0 / (1.0 + float64(steps)*0.02)

	// Input concentration: more concentrated current state → higher confidence
	concentration := 0.0
	for _, p := range current {
		concentration += p * p
	}
	concentration = math.Sqrt(concentration) // [0.5, 1.0] range for normalized vectors

	confidence = entropyConf * horizonDecay * concentration

	// Clamp
	confidence = math.Max(0.0, math.Min(1.0, confidence))

	return future, confidence
}

// isZeroMatrix checks if all elements are zero.
func isZeroMatrix(m [4][4]float64) bool {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if m[i][j] != 0 {
				return false
			}
		}
	}
	return true
}

// determineTrend classifies the risk trajectory from current to future state vectors.
func determineTrend(current, future [4]float64) string {
	// Priority 1: if collapse probability is already high and staying high → collapsing
	if current[3] > 0.3 && future[3] > 0.3 {
		return "collapsing"
	}
	// Priority 2: if collapse is growing rapidly
	if future[3]-current[3] > 0.1 {
		return "collapsing"
	}

	// Priority 3: weighted score comparison
	weights := [4]float64{3, 2, 1, 0}
	nowScore := 0.0
	futureScore := 0.0
	for i := 0; i < 4; i++ {
		nowScore += current[i] * weights[i]
		futureScore += future[i] * weights[i]
	}

	delta := futureScore - nowScore
	const epsilon = 0.03

	if delta > epsilon {
		return "improving"
	}
	if delta < -epsilon {
		return "degrading"
	}
	return "stable"
}

// PredictFuture runs the full inference pipeline.
//
// Parameters:
//   - semantic: current semantic state from Semantic Layer
//   - model:    inference model (nil → default Markov chain)
//   - cfg:      Prism configuration (uses HorizonDays)
//
// Returns: FutureRiskReport with predicted state distribution. Returns nil if semantic is nil.
func PredictFuture(semantic *SemanticRiskReport, model InferenceModel, cfg PrismConfig) *FutureRiskReport {
	if semantic == nil {
		return nil
	}

	if model == nil {
		model = DefaultInferenceModel()
	}

	steps := cfg.HorizonDays
	if steps <= 0 {
		steps = 7
	}

	future, confidence := model.Predict(semantic.StateVector, steps)

	trend := determineTrend(semantic.StateVector, future)
	collapseRisk := future[2] + future[3] // UntrustedProbm + CollapseProb

	return &FutureRiskReport{
		HostID:        semantic.HostID,
		HorizonDays:   steps,
		StableProb:    math.Round(future[0]*10000) / 10000,
		DegradedProb:  math.Round(future[1]*10000) / 10000,
		UntrustedProb: math.Round(future[2]*10000) / 10000,
		CollapseProb:  math.Round(future[3]*10000) / 10000,
		Confidence:    math.Round(confidence*10000) / 10000,
		Trend:         trend,
		CollapseRisk:  math.Round(collapseRisk*10000) / 10000,
	}
}

// PredictFutureBatch runs inference on multiple semantic reports in batch.
func PredictFutureBatch(reports []*SemanticRiskReport, model InferenceModel, cfg PrismConfig) []*FutureRiskReport {
	results := make([]*FutureRiskReport, 0, len(reports))
	for _, r := range reports {
		if r == nil {
			continue
		}
		results = append(results, PredictFuture(r, model, cfg))
	}
	return results
}