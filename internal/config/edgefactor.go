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
	// The zero value ("") means the section was absent ⇒ the caller keeps
	// the legacy multiplicative behavior.
	Model string
	// PFloor is the penalty floor in (0,1): P_d → PFloor as the loss grows.
	PFloor float64
	// Lambda is the per-domain saturation rate λ_d (> 0), keyed by lowercase
	// domain id.
	Lambda map[string]float64
	// Vectors is factor id → (domain id → non-negative weight). Factor ids are
	// canonical UPPERCASE, matching the engine's FactorID spelling.
	Vectors map[string]map[string]float64
	// Coupling is from-factor → (to-factor → non-negative coupling c_ij); both
	// sides are canonical UPPERCASE factor ids.
	Coupling map[string]map[string]float64
	// ChainWindowSeconds is the temporal window of the chain model (> 0 when
	// model = chain).
	ChainWindowSeconds int
	// TriggerMap is factor id → the security check id whose failure triggers
	// it (replaces the hard-coded mapping in the adapter). Both sides are
	// canonical UPPERCASE.
	TriggerMap map[string]string
}

// edgeFactorDomainOrder is the canonical domain order of a vector.<factor>
// entry: a fixed-size array, so the mapping cannot be resized at run time. The
// config package deliberately keeps its own copy — matching the order used by
// ranges.go and internal/edgefactor.DefaultDomains() — instead of importing
// internal/edgefactor, so parsing stays free of any dependency on the
// synthesis layer (audit F6).
var edgeFactorDomainOrder = [5]string{
	"attack_surface",
	"business_continuity",
	"operation_trust",
	"resilience",
	"kernel_security",
}

// edgeFactorModelOnlyKeys / edgeFactorModelOnlyPrefixes list the keys that are
// only meaningful inside [edge_factors.model]. Written into the legacy
// [edge_factors] section they would be dropped silently by its float-only
// whitelist, so Parse rejects them explicitly (see isEdgeFactorModelSectionKey).
var edgeFactorModelOnlyKeys = map[string]bool{
	"model":   true,
	"p_floor": true,
}

var edgeFactorModelOnlyPrefixes = [5]string{"lambda.", "vector.", "coupling.", "chain.", "trigger."}

// isEdgeFactorModelSectionKey reports whether key belongs to
// [edge_factors.model] rather than the legacy [edge_factors] section.
func isEdgeFactorModelSectionKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if edgeFactorModelOnlyKeys[k] {
		return true
	}
	for _, p := range edgeFactorModelOnlyPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
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
// Identity keys are normalized: factor ids (in Vectors, Coupling and
// TriggerMap) and the trigger check id are stored UPPER-CASED, because
// parseSections lower-cases every config key while the synthesis layer looks
// factor ids up by the engine's canonical uppercase FactorID. Without
// normalization a configured `vector.EF-SELINUX` would land as "ef-selinux",
// miss that lookup, and silently degrade to the all-domains fallback — a
// degradation edgefactor.Validate cannot catch, since it only validates vectors
// that were declared. Domain names stay lower-case, and error messages echo the
// operator's original spelling so the offending line is easy to find.
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
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] unknown model %q (want legacy|vector|graph|chain)", value)
			}
			cfg.Model = value
		case key == "p_floor":
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f <= 0 || f >= 1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] p_floor = %q must be in (0,1)", value)
			}
			cfg.PFloor = f
		case strings.HasPrefix(key, "lambda."):
			domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(key, "lambda.")))
			if domain == "" {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %q has an empty domain name", key)
			}
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %s = %q must be > 0", key, value)
			}
			cfg.Lambda[domain] = f
		case strings.HasPrefix(key, "vector."):
			factor := canonicalFactorID(strings.TrimPrefix(key, "vector."))
			if factor == "" {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %q has an empty factor id", key)
			}
			parts := strings.Split(value, ",")
			if len(parts) != len(edgeFactorDomainOrder) {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %s needs %d comma-separated values in the order attack_surface,business_continuity,operation_trust,resilience,kernel_security, got %d", key, len(edgeFactorDomainOrder), len(parts))
			}
			vec := make(map[string]float64, len(parts))
			for i, part := range parts {
				raw := strings.TrimSpace(part)
				f, err := parseEdgeFactorNumber(fmt.Sprintf("%s[%d]", key, i), raw)
				if err != nil {
					return EdgeFactorModelConfig{}, false, err
				}
				if f < 0 {
					return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %s[%d] = %q must be a non-negative number", key, i, raw)
				}
				vec[edgeFactorDomainOrder[i]] = f
			}
			cfg.Vectors[factor] = vec
		case strings.HasPrefix(key, "coupling."):
			rest := strings.TrimPrefix(key, "coupling.")
			idx := strings.LastIndex(rest, ".")
			if idx <= 0 || idx == len(rest)-1 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] coupling key %q must be coupling.<from>.<to>", key)
			}
			from, to := canonicalFactorID(rest[:idx]), canonicalFactorID(rest[idx+1:])
			if from == "" || to == "" {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] coupling key %q has an empty factor id", key)
			}
			f, err := parseEdgeFactorNumber(key, value)
			if err != nil {
				return EdgeFactorModelConfig{}, false, err
			}
			if f < 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %s = %q must be >= 0", key, value)
			}
			if cfg.Coupling[from] == nil {
				cfg.Coupling[from] = map[string]float64{}
			}
			cfg.Coupling[from][to] = f
		case key == "chain.window_seconds":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] chain.window_seconds = %q must be a positive integer", value)
			}
			cfg.ChainWindowSeconds = n
		case strings.HasPrefix(key, "trigger."):
			factor := canonicalFactorID(strings.TrimPrefix(key, "trigger."))
			if factor == "" {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %q has an empty factor id", key)
			}
			check := strings.ToUpper(value)
			if check == "" {
				return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] %s has an empty trigger check id", key)
			}
			cfg.TriggerMap[factor] = check
		default:
			return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] unknown key %q", key)
		}
	}
	if cfg.Model == "" {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] present without a model key")
	}
	if cfg.Model == "chain" && cfg.ChainWindowSeconds <= 0 {
		return EdgeFactorModelConfig{}, false, fmt.Errorf("config: [edge_factors.model] model=chain requires chain.window_seconds")
	}
	return cfg, true, nil
}

// canonicalFactorID normalizes a factor id to its canonical uppercase spelling
// (the engine's FactorID convention: EF-SELINUX, EF-NO-IDS, EF-3FA).
func canonicalFactorID(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

// edgeFactor3FAID is the cascade factor id that ConfigToEdgeFactors always
// produces although it carries no weight in either [edge_factors] or
// [edge_factors.custom] — it is the only factor that exists without a penalty
// value, and it is the reason the default trigger table has seven entries.
const edgeFactor3FAID = "EF-3FA"

// DefaultEdgeFactorTriggerMap returns the factory default mapping
// factor id → the security check id whose failure triggers that factor.
//
// This is the single source of the table that used to be hard-coded twice:
// once in internal/engine/ssam (adapter.go, for the plugin path) and once in
// internal/engine/assessor.go (evaluateEdgeFactorChain, for the legacy path).
// Both paths consume it now, so a configured [edge_factors.model] trigger.<factor>
// override lands on both of them. It lives in internal/config because that
// package is imported by both paths and because the table is, by nature, a set
// of configuration defaults.
//
// Seven entries: the six built-in factors plus EF-3FA. EF-3FA is special — it
// has no weight anywhere in the configuration (its 0.82 penalty is a fixed
// cascade onto EF-002FA), yet its trigger check must still be configurable;
// the legacy path expresses that cascade with its own branch and derives the
// branch label from this table.
//
// The caller must treat the result as the *base* of a resolution and overlay the
// operator's explicit overrides on it (see ResolveEdgeFactorTriggerMap) rather
// than using it directly. A fresh map is returned on every call, so mutating the
// result is safe.
func DefaultEdgeFactorTriggerMap() map[string]string {
	return map[string]string{
		"EF-002FA":      "EF-001",
		"EF-SYNCOOKIE":  "RS-005",
		"EF-SELINUX":    "OT-005",
		"EF-APPARMOR":   "OT-005",
		"EF-NO-SIEM":    "RS-007",
		"EF-NO-IDS":     "RS-006",
		edgeFactor3FAID: "EF-002",
	}
}

// ResolveEdgeFactorTriggerMap returns DefaultEdgeFactorTriggerMap overlaid with
// the operator's explicit [edge_factors.model] trigger.<factor> entries.
//
// This is the one resolution both the legacy path (internal/engine) and the
// plugin path (internal/engine/ssam) use, so "the same configuration" cannot
// mean two different mappings depending on which engine a deployment assembled.
// A nil cfg yields the plain default table.
//
// A blank override value never replaces a default: writing `trigger.EF-SELINUX =`
// would leave the factor without a trigger check (it could never activate), which
// is silent failure rather than "no override". ParseEdgeFactorModel already
// rejects such a line, and this is the second line of defense for hand-built
// *Config values (same ruling as the ssam assembly path).
func ResolveEdgeFactorTriggerMap(cfg *Config) map[string]string {
	resolved := DefaultEdgeFactorTriggerMap()
	if cfg == nil {
		return resolved
	}
	for id, check := range cfg.EdgeFactorModel.TriggerMap {
		if strings.TrimSpace(check) == "" {
			continue
		}
		resolved[id] = check
	}
	return resolved
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
