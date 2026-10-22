package config

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chins-xing/asscor/internal/model"
)

// ConfidenceAlgorithmWeightedEvidence is the ONLY implemented confidence
// aggregation algorithm. The design §3.3 promise of an algorithm registry
// (RegisterAlgorithm/Aggregator) and a beta_bayes aggregator was never
// implemented; see audit I-10. Any other value in [confidence] algorithm is
// rejected at parse time.
const ConfidenceAlgorithmWeightedEvidence = "weighted_evidence"

// ConfidenceConfig is the kernel-side configuration of the intelligence
// confidence model (design CONFIDENCE_MODEL_DESIGN_2026-09-08 §3). It is
// parsed from the [confidence] and [confidence.check]/[confidence.source]/
// [confidence.domain] sections of config.ini. The scoring side (engine)
// resolves each CheckResult to a Confidence value and derives the library
// ConfidencePolicy from this struct.
type ConfidenceConfig struct {
	// Enabled turns confidence-aware scoring on. Default false → every check
	// scores at full weight (legacy behavior).
	Enabled bool
	// Algorithm is RESERVED: no algorithm registry exists. The only
	// implemented aggregation is weighted_evidence (the field is parsed for
	// forward compatibility, and any other value is rejected at parse time so
	// an operator cannot believe they switched algorithms). beta_bayes and the
	// RegisterAlgorithm/Aggregator API from design §3.3 were never implemented
	// (audit I-10).
	Algorithm string
	// AcceptByLowerBound makes the acceptability decision use the 95%
	// interval lower bound instead of the point estimate (conservative).
	AcceptByLowerBound bool
	// Default is the confidence for a check/result that matches no rule.
	// 0 or unset → 1.0.
	Default float64
	// Floor is the minimum accepted confidence (clamp-up).
	Floor float64
	// PriorStrength is RESERVED (no consumer): it belongs to the unimplemented
	// beta_bayes aggregator. It is parsed and range-validated (0 = unset;
	// non-numeric/negative fail) but never reaches the weighted_evidence
	// formulas (audit I-10).
	PriorStrength float64

	// ByCheckID maps an exact check/rule id to a confidence.
	ByCheckID map[string]float64
	// BySource maps a confidence source key (builtin/user/root/extension/
	// adapter/cti/spc/... or an external tool id like nuclei) to a confidence.
	BySource map[string]float64
	// ByDomain maps a domain id to a domain-level fallback confidence.
	ByDomain map[string]float64
	// CheckPatterns are regex selectors evaluated after exact-id misses:
	// pattern (compiled) → confidence. Evaluated in BYTE-LEXICOGRAPHIC KEY
	// ORDER (the parse structure is a map, so declaration order is not
	// preserved); the first match wins (design §3.3 rule DSL subset, audit I-5).
	CheckPatterns []ConfidencePatternRule
}

// ConfidencePatternRule is one declarative regex rule for confidence.
type ConfidencePatternRule struct {
	Pattern    *regexp.Regexp
	Confidence float64
}

// DefaultConfidenceConfig returns the factory configuration: disabled by
// default (legacy behavior), but WITH a source prior table so that flipping
// enabled=true is not a no-op (audit I-2; design §3.4 "source defaults + config
// overrides", "not a pure opt-in of all 1.0").
//
// The three values are the design §3.1 examples (builtin=1.0, user=0.90,
// adapter=0.80). They are PRIORS, NOT experimentally calibrated values: the
// §3.4 "calibrate during implementation" promise (I-3) has not been delivered,
// so no external claim of calibration may rest on them. Every other source key
// falls through to Default / [confidence.domain].
func DefaultConfidenceConfig() ConfidenceConfig {
	return ConfidenceConfig{
		Enabled:            false,
		Algorithm:          "weighted_evidence",
		AcceptByLowerBound: false,
		Default:            1.0,
		Floor:              0.05,
		PriorStrength:      2.0,
		ByCheckID:          map[string]float64{},
		// Source priors, overridable from [confidence.source] (values there
		// win because parsing overlays this table). Enabled=false keeps the
		// effective confidence at 1.0 for every entry → bit-identical legacy
		// scores.
		BySource: map[string]float64{
			"builtin": 1.0,  // compiled-in platform checks (fully trusted)
			"user":    0.90, // configuration-defined checks (CU-*)
			"adapter": 0.80, // third-party adapter findings whose source is the generic class
		},
		ByDomain: map[string]float64{},
	}
}

// parseConfidenceSections populates cfg.Confidence from the config sections.
// Recognized sections:
//
//	[confidence]  enabled / algorithm / accept_by_lower_bound / default /
//	              floor / prior_strength
//	[confidence.check]    <check_id> = <conf>       (exact)
//	[confidence.checkrx]  <regex> = <conf>          (first match in
//	                                                 byte-lexicographic key order)
//	[confidence.source]   <source_key> = <conf>
//	[confidence.domain]   <domain> = <conf>
//
// Values are validated fail-fast (audit I-9): a non-numeric, non-finite or
// out-of-range explicit entry returns an error naming section/key/value,
// instead of being silently dropped (which used to fall back to default, often
// 1.0). The ONLY allowed sentinel is 0 = "unset/clear": in the rule tables it
// removes the entry (including a factory prior), and in the scalars it means
// "unspecified" (Resolve then falls back to 1.0; floor 0 behaves as absent).
func (cfg *Config) parseConfidenceSections(sections map[string]map[string]string) error {
	cc := cfg.Confidence

	// [confidence]
	if sec, ok := sections["confidence"]; ok {
		if v, ok := sec["enabled"]; ok {
			b, err := parseConfidenceBool(v)
			if err != nil {
				return confidenceValueError("confidence", "enabled", v, err)
			}
			cc.Enabled = b
		}
		if v, ok := sec["algorithm"]; ok {
			a := strings.TrimSpace(v)
			switch {
			case a == "":
				// Explicit empty = unset → keep the factory weighted_evidence.
			case a == ConfidenceAlgorithmWeightedEvidence:
				cc.Algorithm = a
			default:
				// Fail-fast: a wrong id must never look like a switched
				// algorithm (beta_bayes and the registration API are not
				// implemented — audit I-10).
				return confidenceValueError("confidence", "algorithm", v,
					fmt.Errorf("unsupported algorithm %q: only %q is implemented (beta_bayes and the registration API do not exist)",
						a, ConfidenceAlgorithmWeightedEvidence))
			}
		}
		if v, ok := sec["accept_by_lower_bound"]; ok {
			b, err := parseConfidenceBool(v)
			if err != nil {
				return confidenceValueError("confidence", "accept_by_lower_bound", v, err)
			}
			cc.AcceptByLowerBound = b
		}
		if v, ok := sec["default"]; ok {
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence", "default", v, err)
			}
			// 0 = unset/clear → keep the factory default (1.0). Assigning 0
			// would also trip validateRanges (default ∈ (0,1]) when enabled.
			if f != 0 {
				cc.Default = f
			}
		}
		if v, ok := sec["floor"]; ok {
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence", "floor", v, err)
			}
			if f == 1 {
				return confidenceValueError("confidence", "floor", v,
					fmt.Errorf("must be < 1: floor is a clamp-up minimum, 1 would neutralize confidence"))
			}
			// 0 = unset/clear → keep the factory floor (0.05).
			if f != 0 {
				cc.Floor = f
			}
		}
		if v, ok := sec["prior_strength"]; ok {
			f, err := parseNonNegativeFloat(v)
			if err != nil {
				return confidenceValueError("confidence", "prior_strength", v, err)
			}
			// 0 = unset/clear → keep the factory value (2.0). Reserved anyway.
			if f != 0 {
				cc.PriorStrength = f
			}
		}
	}

	// [confidence.check]
	if sec := sections["confidence.check"]; sec != nil {
		for _, k := range sortedConfidenceKeys(sec) {
			v := sec[k]
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence.check", k, v, err)
			}
			if f == 0 {
				delete(cc.ByCheckID, k) // 0 = clear
				continue
			}
			cc.ByCheckID[k] = f
		}
	}
	// [confidence.checkrx]
	if sec := sections["confidence.checkrx"]; sec != nil {
		// Deterministic tie-break (audit I-5): sections are parsed into a map,
		// so declaration order is already lost; iterating the map directly made
		// the "first match wins" order random per parse (same INI could resolve
		// 0.1 or 0.9 after a hot reload). Sort keys BYTE-LEXICOGRAPHICALLY so
		// overlapping regexes always evaluate in the same order. Byte order was
		// chosen over re-plumbing the parser to keep declaration order: it is
		// deterministic across processes and platforms, and requires no change
		// to the shared section parser used by every other config block.
		for _, k := range sortedConfidenceKeys(sec) {
			v := sec[k]
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence.checkrx", k, v, err)
			}
			re, rerr := regexp.Compile(k)
			if rerr != nil {
				return fmt.Errorf("confidence: [confidence.checkrx] %q: invalid regex: %w", k, rerr)
			}
			if f == 0 {
				continue // 0 = clear
			}
			cc.CheckPatterns = append(cc.CheckPatterns, ConfidencePatternRule{Pattern: re, Confidence: f})
		}
	}
	// [confidence.source]
	if sec := sections["confidence.source"]; sec != nil {
		for _, k := range sortedConfidenceKeys(sec) {
			v := sec[k]
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence.source", k, v, err)
			}
			if f == 0 {
				delete(cc.BySource, k) // 0 = clear (also removes a factory prior)
				continue
			}
			cc.BySource[k] = f
		}
	}
	// [confidence.domain]
	if sec := sections["confidence.domain"]; sec != nil {
		for _, k := range sortedConfidenceKeys(sec) {
			v := sec[k]
			f, err := parseUnitFloat(v)
			if err != nil {
				return confidenceValueError("confidence.domain", k, v, err)
			}
			if f == 0 {
				delete(cc.ByDomain, k) // 0 = clear
				continue
			}
			cc.ByDomain[k] = f
		}
	}

	cfg.Confidence = cc
	return nil
}

// confidenceValueError wraps a validation failure with section/key/value so an
// operator can locate the offending line without guessing (audit I-9).
func confidenceValueError(section, key, value string, err error) error {
	return fmt.Errorf("confidence: [%s] %s = %q: %w", section, key, value, err)
}

// sortedConfidenceKeys returns the map keys in byte-lexicographic order. Used
// for deterministic pattern evaluation (I-5) and stable error messages.
func sortedConfidenceKeys(sec map[string]string) []string {
	keys := make([]string, 0, len(sec))
	for k := range sec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseUnitFloat parses an explicit confidence scalar. 0 is the documented
// "unset/clear" sentinel; anything else must be a finite number in [0,1].
func parseUnitFloat(v string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("must be a finite number")
	}
	if f < 0 || f > 1 {
		return 0, fmt.Errorf("must be in [0,1] (0 = unset)")
	}
	return f, nil
}

// parseNonNegativeFloat parses a reserved numeric parameter (prior_strength):
// 0 = unset; negative, NaN and Inf are rejected.
func parseNonNegativeFloat(v string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("must be a finite number")
	}
	if f < 0 {
		return 0, fmt.Errorf("must be >= 0 (0 = unset)")
	}
	return f, nil
}

// parseConfidenceBool accepts only the documented spellings. Unknown text is a
// hard error (audit I-9) instead of the old silent "false".
func parseConfidenceBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("not a boolean: want true/false/yes/no/1/0")
	}
}

// Resolve applies the configured rule table to one check identified by
// (checkID, sourceKey, domain).
func (cc ConfidenceConfig) Resolve(checkID, sourceKey, domain string) float64 {
	if !cc.Enabled {
		return 1.0
	}
	foldID := strings.ToLower(checkID)
	if v, ok := cc.ByCheckID[foldID]; ok {
		return v
	}
	for _, pr := range cc.CheckPatterns {
		if pr.Pattern.MatchString(foldID) {
			return pr.Confidence
		}
	}
	if v, ok := cc.BySource[strings.ToLower(sourceKey)]; ok {
		return v
	}
	if v, ok := cc.ByDomain[strings.ToLower(domain)]; ok {
		return v
	}
	d := cc.Default
	if d <= 0 || d > 1 {
		d = 1.0
	}
	return d
}

// ResolveChecks fills Checks[].Confidence from the rule table (design §3).
// Results that already carry an explicit confidence (e.g. agent-set or SRD
// upstream) are preserved. sourceKey comes from CheckResult.Source, with the
// empty legacy value mapped to "builtin".
func (cfg *Config) ResolveChecks(checks []model.CheckResult) {
	if cfg == nil || !cfg.Confidence.Enabled {
		return
	}
	for i := range checks {
		c := &checks[i]
		if c.Confidence > 0 {
			continue // already resolved upstream
		}
		src := string(c.Source)
		if src == "" {
			src = "builtin"
		}
		c.Confidence = cfg.Confidence.Resolve(c.CheckID, src, c.Domain)
	}
}
