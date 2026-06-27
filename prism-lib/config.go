package prism

func DefaultConfig() PrismConfig {
	return PrismConfig{
		// Core Layer
		DebtAlpha:    1.2,
		PropCap:      0.25,
		DebtCap:      0.30,
		DebtNormDays: 1500.0,
		PathDecay:    0.80,
		MaxPathDepth: 5,
		ScoreFloor:   0.15,
		CollapseBeta: 1.5,

		// Semantic Layer
		StableThreshold:    0.90,
		DegradedThreshold:  0.70,
		UntrustedThreshold: 0.50,

		// Inference Layer
		HorizonDays: 7,
	}
}
