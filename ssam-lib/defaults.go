package ssam

var DefaultWeights = []WeightConfig{
	{Domain: "attack_surface", Weight: 35},
	{Domain: "business_continuity", Weight: 25},
	{Domain: "operation_trust", Weight: 25},
	{Domain: "resilience", Weight: 15},
}

var DefaultEdgeFactors = []EdgeFactorConfig{
	{ID: "EF-002FA", Name: "2FA Missing", Factor: 0.85, TriggerCheck: "EF-001"},
	{ID: "EF-SYNCOOKIE", Name: "SYN Cookie Disabled", Factor: 0.75, TriggerCheck: "RS-005"},
	{ID: "EF-SELINUX", Name: "SELinux Disabled", Factor: 0.80, TriggerCheck: "OT-005"},
	{ID: "EF-APPARMOR", Name: "AppArmor Disabled", Factor: 0.82, TriggerCheck: "OT-005"},
	{ID: "EF-NO-SIEM", Name: "SIEM Integration Missing", Factor: 0.90, TriggerCheck: "RS-007"},
	{ID: "EF-NO-IDS", Name: "IDS/IPS Missing", Factor: 0.88, TriggerCheck: "RS-006"},
	{ID: "EF-3FA", Name: "3FA Not Met", Factor: 0.82, TriggerCheck: "EF-002", CascadeTo: "EF-002FA", CascadeValue: 0.82, CascadeOnly: true},
}

var DefaultScoringConfig = ScoringConfig{
	Weights:     DefaultWeights,
	EdgeFactors: DefaultEdgeFactors,
	FormulaID:   "ssam_v2.0",
}
