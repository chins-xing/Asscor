package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// EdgeFactorModelConfig is the pure parse result of the [edge_factors.model]
// section (design EDGE_FACTOR_COUPLING_DESIGN_2026-09-08 §4). Parsing carries
// no side effects: it neither registers domains nor assembles engine state
// (audit F6 — the config package stays a pure parser). Task 4 maps this struct
// onto edgefactor.Params.
type EdgeFactorModelConfig struct {
	// Model selects the synthesis model: legacy | vector | graph | chain.
	// The zero value ("" ) means the section was absent ⇒ the caller keeps
	// the legacy multiplicative behavior.
	Model string
	// PFloor is the penalty floor in (0,1): P_d → PFloor as the loss grows.
	PFloor float64
	// Lambda is the per-domain saturation rate λ_d (> 0), keyed by domain id.
	Lambda map[string]float64
	// Vectors is factor id → (domain id → non-negative weight).
	Vectors map[string]map[string]float64
	// Coupling is from-factor → (to-factor → non-negative coupling c_ij).
	Coupling map[string]map[string]float64
	// ChainWindowSeconds is the temporal window of the chain model (> 0 when
	// model = chain).
	ChainWindowSeconds int
	// TriggerMap is factor id → the security check id whose failure triggers
	// it (replaces the hard-coded mapping in the adapter).
	TriggerMap map[string]string
}

// edgeFactorDomainOrder is the canonical domain order of a vector.<factor>
// entry. The config package deliberately keeps its own copy — matching the
// order used by ranges.go and internal/edgefactor.DefaultDomains() — instead
// of importing internal/edgefactor, so parsing stays free of any dependency
// on the synthesis layer (audit F6).
var edgeFactorDomainOrder = []string{
	"attack_surface",
	"business_continuity",
	"operation_trust",
	"resilience",
	"kernel_security",
}

var validEdgeFactorModels = map[string]bool{"legacy": true, "vector": true, "graph": true, "chain": true}

// ParseEdgeFactorModel parses the [edge_factors.model] section.
//
// It performs format and range checks only (non-negative values, finite
// numbers, chain needs a window, unknown keys/models rejected). The two
// structural rules — Σ_d v_i[d] ≤ 1 and "a declared vector must cover every
// requested domain" — belong to edgefactor.Validate and are deliberately NOT
// re-implemented here, so the rule set has a single home.
//
// present=false means the section is absent: the caller keeps the legacy
// behavior (design §4 rule 1). It is never an error, and no default model is
// substituted.
func ParseEdgeFactorModel(sections map[string]map[string]string) (EdgeFactorModelConfig, bool, error) {
	kv, ok := sections["edge_factors.model"]
	if !ok {
		return EdgeFactorModelConfig{}, false, nil
	}
	cfg := EdgeFactorModelConfig{
		Lambda:     map[string]float64{},
		Vectors:    map[string]map[string]float64{},
		Coupling:   map[string]map[string]float64{},
		TriggerMap: map[string]string{},
	}
	for key, raw := range kv {
		value := strings.TrimSpace(raw)
		switch {
		case key == "model":
			if !validEdgeFactorModels[value] {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: unknown edge factor model %q", value)
			}
			cfg.Model = value
		case key == "p_floor":
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f <= 0 || f >= 1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: edge factor p_floor %q must be in (0,1)", value)
			}
			cfg.PFloor = f
		case strings.HasPrefix(key, "lambda."):
			domain := strings.TrimPrefix(key, "lambda.")
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: lambda.%s %q must be > 0", domain, value)
			}
			cfg.Lambda[domain] = f
		case strings.HasPrefix(key, "vector."):
			factor := strings.TrimPrefix(key, "vector.")
			parts := strings.Split(value, ",")
			if len(parts) != len(edgeFactorDomainOrder) {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: vector.%s needs %d comma-separated values, got %d", factor, len(edgeFactorDomainOrder), len(parts))
			}
			vec := make(map[string]float64, len(parts))
			for i, part := range parts {
				raw := strings.TrimSpace(part)
				f, err := parseEdgeFactorNumber(fmt.Sprintf("vector.%s[%d]", factor, i), raw)
				if err != nil {
					return EdgeFactorModelConfig{}, false, err
				}
				if f < 0 {
					return EdgeFactorModelConfig{}, false, fmt.Errorf("config: vector.%s[%d] = %q must be a non-negative number", factor, i, raw)
				}
				vec[edgeFactorDomainOrder[i]] = f
			}
			cfg.Vectors[factor] = vec
		case strings.HasPrefix(key, "coupling."):
			rest := strings.TrimPrefix(key, "coupling.")
			idx := strings.LastIndex(rest, ".")
			if idx <= 0 || idx == len(rest)-1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: coupling key %q must be coupling.<from>.<to>", key)
			}
			from, to := rest[:idx], rest[idx+1:]
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f < 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: coupling.%s.%s %q must be >= 0", from, to, value)
			}
			if cfg.Coupling[from] == nil {
				cfg.Coupling[from] = map[string]float64{}
			}
			cfg.Coupling[from][to] = f
		case key == "chain.window_seconds":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: chain.window_seconds %q must be > 0", value)
			}
			cfg.ChainWindowSeconds = n
		case strings.HasPrefix(key, "trigger."):
			cfg.TriggerMap[strings.TrimPrefix(key, "trigger.")] = value
		default:
			return EdgeFactorModelConfig{}, false, fmt.Errorf("config: unknown [edge_factors.model] key %q", key)
		}
	}
	if cfg.Model == "" {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] present without a model key")
	}
	if cfg.Model == "chain" && cfg.ChainWindowSeconds <= 0 {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: model=chain requires chain.window_seconds")
	}
	return cfg, true, nil
}

// parseEdgeFactorNumber parses one numeric entry of the section and rejects
// non-finite results. strconv.ParseFloat accepts "NaN"/"Inf"/"-Inf", and a
// non-finite value would silently poison the penalty formula — it is neither
// bounded nor monotone, so it defeats P1/P2 of the design. This mirrors
// edgefactor.Validate's finiteness rule at the parse boundary (fail-fast).
// The error names the key and echoes the raw value.
func parseEdgeFactorNumber(key, raw string) (float64, error) {
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("config: [edge_factors.model] %s = %q is not a number", key, raw)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("config: [edge_factors.model] %s = %q must be a finite number", key, raw)
	}
	return f, nil
}
