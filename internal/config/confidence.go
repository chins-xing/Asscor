package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/asscor/asscor/internal/model"
)

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
	// Algorithm selects the confidence aggregation algorithm id
	// ("weighted_evidence" default; extensible via registration).
	Algorithm string
	// AcceptByLowerBound makes the acceptability decision use the 95%
	// interval lower bound instead of the point estimate (conservative).
	AcceptByLowerBound bool
	// Default is the confidence for a check/result that matches no rule.
	// 0 or unset → 1.0.
	Default float64
	// Floor is the minimum accepted confidence (clamp-up).
	Floor float64
	// PriorStrength is reserved for the beta_bayes aggregator.
	PriorStrength float64

	// ByCheckID maps an exact check/rule id to a confidence.
	ByCheckID map[string]float64
	// BySource maps a confidence source key (builtin/user/root/extension/
	// adapter/cti/spc/... or an external tool id like nuclei) to a confidence.
	BySource map[string]float64
	// ByDomain maps a domain id to a domain-level fallback confidence.
	ByDomain map[string]float64
	// CheckPatterns are regex selectors evaluated after exact-id misses:
	// pattern (compiled) → confidence. Evaluated in declaration order;
	// first match wins (design §3.3 rule DSL subset).
	CheckPatterns []ConfidencePatternRule
}

// ConfidencePatternRule is one declarative regex rule for confidence.
type ConfidencePatternRule struct {
	Pattern    *regexp.Regexp
	Confidence float64
}

// DefaultConfidenceConfig returns the disabled (legacy) configuration.
func DefaultConfidenceConfig() ConfidenceConfig {
	return ConfidenceConfig{
		Enabled:       false,
		Algorithm:     "weighted_evidence",
		AcceptByLowerBound: false,
		Default:       1.0,
		Floor:         0.05,
		PriorStrength: 2.0,
		ByCheckID:     map[string]float64{},
		BySource:      map[string]float64{},
		ByDomain:      map[string]float64{},
	}
}

// parseConfidenceSections populates cfg.Confidence from the config sections.
// Recognized sections:
//
//	[confidence]  enabled / algorithm / accept_by_lower_bound / default /
//	              floor / prior_strength
//	[confidence.check]    <check_id> = <conf>       (exact)
//	[confidence.checkrx]  <regex> = <conf>          (first-match pattern)
//	[confidence.source]   <source_key> = <conf>
//	[confidence.domain]   <domain> = <conf>
//
// Values are clamped to (0,1] on parse so a malformed entry cannot produce a
// nonsense confidence (0 is reinterpreted as the default at resolve time).
func (cfg *Config) parseConfidenceSections(sections map[string]map[string]string) error {
	cc := cfg.Confidence

	// [confidence]
	if sec, ok := sections["confidence"]; ok {
		if v, ok := sec["enabled"]; ok {
			cc.Enabled = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
		if v, ok := sec["algorithm"]; ok && v != "" {
			cc.Algorithm = strings.TrimSpace(v)
		}
		if v, ok := sec["accept_by_lower_bound"]; ok {
			cc.AcceptByLowerBound = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
		if v, ok := sec["default"]; ok {
			if f, err := parseConfidenceValue(v); err == nil {
				cc.Default = f
			}
		}
		if v, ok := sec["floor"]; ok {
			if f, err := parseConfidenceValue(v); err == nil {
				cc.Floor = f
			}
		}
		if v, ok := sec["prior_strength"]; ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
				cc.PriorStrength = f
			}
		}
	}

	// [confidence.check]
	if sec, ok := sections["confidence.check"]; ok {
		for k, v := range sec {
			if f, err := parseConfidenceValue(v); err == nil {
				cc.ByCheckID[k] = f
			}
		}
	}
	// [confidence.checkrx]
	if sec, ok := sections["confidence.checkrx"]; ok {
		for k, v := range sec {
			f, err := parseConfidenceValue(v)
			if err != nil {
				continue
			}
			re, rerr := regexp.Compile(k)
			if rerr != nil {
				return fmt.Errorf("confidence.checkrx: invalid regex %q: %w", k, rerr)
			}
			cc.CheckPatterns = append(cc.CheckPatterns, ConfidencePatternRule{Pattern: re, Confidence: f})
		}
	}
	// [confidence.source]
	if sec, ok := sections["confidence.source"]; ok {
		for k, v := range sec {
			if f, err := parseConfidenceValue(v); err == nil {
				cc.BySource[k] = f
			}
		}
	}
	// [confidence.domain]
	if sec, ok := sections["confidence.domain"]; ok {
		for k, v := range sec {
			if f, err := parseConfidenceValue(v); err == nil {
				cc.ByDomain[k] = f
			}
		}
	}

	cfg.Confidence = cc
	return nil
}

// parseConfidenceValue parses a confidence entry and clamps it to (0,1].
func parseConfidenceValue(v string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, err
	}
	if f <= 0 {
		return 0, fmt.Errorf("confidence must be > 0")
	}
	if f > 1 {
		return 1, nil
	}
	return f, nil
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
