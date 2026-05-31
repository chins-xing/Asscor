package prism

func DefaultConfig() PrismConfig {
	return PrismConfig{
		DebtAlpha:     1.2,
		PropCap:       0.25,
		DebtCap:       0.30,
		DebtNormDays:  1500.0,
		PathDecay:     0.80,
		MaxPathDepth:  5,
		ScoreFloor:    0.40,
	}
}
