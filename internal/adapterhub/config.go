//go:build adapter

package adapterhub

import (
	"fmt"
	"time"
)

// Config holds the configuration for the adapter hub.
type Config struct {
	SyncInterval    time.Duration
	HealthInterval  time.Duration
	MaxConcurrency  int
	AdapterDefaults map[string]map[string]string
	RuleProfiles    map[string]*SeverityProfile
	DefaultProfile  string
	GlobalRules     *RuleSetConfig
}

// RuleSetConfig holds the configuration for rule sets.
type RuleSetConfig struct {
	SeverityRules   []SeverityRuleConfig
	DomainRules     []DomainRuleConfig
	DeltaRules      []DeltaRuleConfig
	ValidationRules []ValidationRuleConfig
	TransformRules  []TransformRuleConfig
	FilterRules     []FilterRuleConfig
}

// SeverityRuleConfig holds configuration for a severity rule.
type SeverityRuleConfig struct {
	Tool        string
	Priority    int
	Mappings    map[string]string
	Description string
}

// DomainRuleConfig holds configuration for a domain rule.
type DomainRuleConfig struct {
	Tool        string
	Priority    int
	CheckID     string
	Domain      string
	Category    string
	Description string
}

// DeltaRuleConfig holds configuration for a delta rule.
type DeltaRuleConfig struct {
	Tool        string
	Priority    int
	Severity    string
	BaseDelta   float64
	Conditions  []DeltaConditionConfig
	Description string
}

// DeltaConditionConfig holds configuration for a delta condition.
type DeltaConditionConfig struct {
	Field    string
	Operator string
	Value    string
}

// ValidationRuleConfig holds configuration for a validation rule.
type ValidationRuleConfig struct {
	Tool        string
	Priority    int
	CheckID     string
	Description string
}

// TransformRuleConfig holds configuration for a transform rule.
type TransformRuleConfig struct {
	Tool        string
	Priority    int
	Field       string
	Pattern     string
	Replacement string
	Description string
}

// FilterRuleConfig holds configuration for a filter rule.
type FilterRuleConfig struct {
	Tool        string
	Priority    int
	Conditions  []FilterConditionConfig
	Action      string
	Description string
}

// FilterConditionConfig holds configuration for a filter condition.
type FilterConditionConfig struct {
	Field    string
	Operator string
	Value    string
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		SyncInterval:    6 * time.Hour,
		HealthInterval:  1 * time.Minute,
		MaxConcurrency:  10,
		AdapterDefaults: make(map[string]map[string]string),
		RuleProfiles:    BuiltInProfiles(),
		DefaultProfile:  "generic",
		GlobalRules:     DefaultRuleSetConfig(),
	}
}

// DefaultRuleSetConfig returns the default rule set configuration.
func DefaultRuleSetConfig() *RuleSetConfig {
	return &RuleSetConfig{
		SeverityRules: []SeverityRuleConfig{
			{
				Tool:     "openscap",
				Priority: 10,
				Mappings: map[string]string{
					"fatal":   "critical",
					"error":   "critical",
					"warning": "medium",
					"info":    "info",
				},
				Description: "OpenSCAP severity mapping (DISA STIG)",
			},
			{
				Tool:     "lynis",
				Priority: 10,
				Mappings: map[string]string{
					"warning": "high",
					"suggest": "medium",
					"note":    "low",
					"pass":    "info",
					"skipped": "info",
				},
				Description: "Lynis severity mapping",
			},
			{
				Tool:     "trivy",
				Priority: 10,
				Mappings: map[string]string{
					"critical": "critical",
					"high":     "high",
					"medium":   "medium",
					"low":      "low",
					"unknown":  "unknown",
				},
				Description: "Trivy severity mapping",
			},
			{
				Tool:     "clamav",
				Priority: 10,
				Mappings: map[string]string{
					"infected": "critical",
					"warning":  "high",
					"clean":    "info",
				},
				Description: "ClamAV severity mapping",
			},
			{
				Tool:     "suricata",
				Priority: 10,
				Mappings: map[string]string{
					"1": "critical",
					"2": "high",
					"3": "medium",
					"4": "low",
					"5": "info",
				},
				Description: "Suricata severity mapping (priority level)",
			},
			{
				Tool:     "falco",
				Priority: 10,
				Mappings: map[string]string{
					"emergency": "critical",
					"alert":     "critical",
					"critical":  "critical",
					"error":     "high",
					"warning":   "medium",
					"notice":    "low",
					"info":      "info",
					"debug":     "info",
				},
				Description: "Falco severity mapping",
			},
		},
		DomainRules: []DomainRuleConfig{
			{
				Tool:     "openscap",
				Priority: 10,
				CheckID:  "xccdf_org.ssgproject.content_rule_",
				Domain:   "operation_trust",
				Category: "compliance",
			},
			{
				Tool:     "osv_scanner",
				Priority: 10,
				CheckID:  "",
				Domain:   "attack_surface",
				Category: "vulnerability",
			},
			{
				Tool:     "wazuh_agent",
				Priority: 10,
				CheckID:  "WAZUH-AGENT-STATUS",
				Domain:   "resilience",
				Category: "alert",
			},
			{
				Tool:     "suricata",
				Priority: 10,
				CheckID:  "SURICATA-",
				Domain:   "resilience",
				Category: "alert",
			},
			{
				Tool:     "falco",
				Priority: 10,
				CheckID:  "FALCO-",
				Domain:   "resilience",
				Category: "alert",
			},
			{
				Tool:     "clamav",
				Priority: 10,
				CheckID:  "CLAMAV-",
				Domain:   "resilience",
				Category: "alert",
			},
			{
				Tool:     "freeipa",
				Priority: 10,
				CheckID:  "FREEIPA-",
				Domain:   "operation_trust",
				Category: "identity",
			},
			{
				Tool:     "keycloak",
				Priority: 10,
				CheckID:  "KEYCLOAK-",
				Domain:   "operation_trust",
				Category: "identity",
			},
			{
				Tool:     "aide",
				Priority: 10,
				CheckID:  "AIDE-",
				Domain:   "operation_trust",
				Category: "compliance",
			},
			{
				Tool:     "nikto",
				Priority: 10,
				CheckID:  "NIKTO-",
				Domain:   "attack_surface",
				Category: "vulnerability",
			},
		},
		DeltaRules: []DeltaRuleConfig{
			{
				Tool:        "",
				Priority:    100,
				Severity:    "critical",
				BaseDelta:   -15,
				Description: "Critical severity delta",
			},
			{
				Tool:        "",
				Priority:    100,
				Severity:    "high",
				BaseDelta:   -10,
				Description: "High severity delta",
			},
			{
				Tool:        "",
				Priority:    100,
				Severity:    "medium",
				BaseDelta:   -7.5,
				Description: "Medium severity delta",
			},
			{
				Tool:        "",
				Priority:    100,
				Severity:    "low",
				BaseDelta:   -5,
				Description: "Low severity delta",
			},
			{
				Tool:        "",
				Priority:    100,
				Severity:    "info",
				BaseDelta:   0,
				Description: "Info severity delta",
			},
		},
		ValidationRules: []ValidationRuleConfig{
			{
				Tool:        "",
				Priority:    100,
				CheckID:     "title_required",
				Description: "Finding must have a title",
			},
			{
				Tool:        "",
				Priority:    100,
				CheckID:     "severity_valid",
				Description: "Finding must have a valid severity",
			},
			{
				Tool:        "",
				Priority:    100,
				CheckID:     "domain_or_category",
				Description: "Finding must have either domain or category",
			},
		},
		FilterRules: []FilterRuleConfig{
			{
				Tool:        "",
				Priority:    100,
				Conditions:  []FilterConditionConfig{},
				Action:      "include",
				Description: "Default: include all findings",
			},
		},
	}
}

// ToRuleSet converts the config to a RuleSet.
func (c *RuleSetConfig) ToRuleSet() *RuleSet {
	rs := &RuleSet{}

	for _, cfg := range c.SeverityRules {
		mappings := make(map[string]Severity)
		for k, v := range cfg.Mappings {
			mappings[k] = Severity(v)
		}
		rs.SeverityRules = append(rs.SeverityRules, SeverityRule{
			Name:        cfg.Tool + "_severity",
			Tool:        cfg.Tool,
			Priority:    cfg.Priority,
			Mappings:    mappings,
			Description: cfg.Description,
		})
	}

	for _, cfg := range c.DomainRules {
		rs.DomainRules = append(rs.DomainRules, DomainRule{
			Name:        cfg.Tool + "_domain",
			Tool:        cfg.Tool,
			Priority:    cfg.Priority,
			CheckID:     cfg.CheckID,
			Domain:      cfg.Domain,
			Category:    cfg.Category,
			Description: cfg.Description,
		})
	}

	for _, cfg := range c.DeltaRules {
		var conditions []DeltaCondition
		for _, c := range cfg.Conditions {
			conditions = append(conditions, DeltaCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			})
		}
		rs.DeltaRules = append(rs.DeltaRules, DeltaRule{
			Name:        cfg.Tool + "_delta",
			Tool:        cfg.Tool,
			Priority:    cfg.Priority,
			Severity:    Severity(cfg.Severity),
			BaseDelta:   cfg.BaseDelta,
			Conditions:  conditions,
			Description: cfg.Description,
		})
	}

	for _, cfg := range c.ValidationRules {
		rs.ValidationRules = append(rs.ValidationRules, ValidationRule{
			Name:        cfg.CheckID,
			Tool:        cfg.Tool,
			Priority:    cfg.Priority,
			CheckFunc:   getDefaultValidationFunc(cfg.CheckID),
			Description: cfg.Description,
		})
	}

	for _, cfg := range c.FilterRules {
		var conditions []FilterCondition
		for _, c := range cfg.Conditions {
			conditions = append(conditions, FilterCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			})
		}
		rs.FilterRules = append(rs.FilterRules, FilterRule{
			Name:        cfg.Tool + "_filter",
			Tool:        cfg.Tool,
			Priority:    cfg.Priority,
			Conditions:  conditions,
			Action:      FilterAction(cfg.Action),
			Description: cfg.Description,
		})
	}

	return rs
}

func getDefaultValidationFunc(checkID string) func(f *NormalizedFinding) (bool, string) {
	switch checkID {
	case "title_required":
		return func(f *NormalizedFinding) (bool, string) {
			if f.Title == "" {
				return false, "title is required"
			}
			return true, ""
		}
	case "severity_valid":
		return func(f *NormalizedFinding) (bool, string) {
			if f.Severity == "" || f.Severity == SeverityNone {
				return false, "valid severity is required"
			}
			return true, ""
		}
	case "domain_or_category":
		return func(f *NormalizedFinding) (bool, string) {
			if f.Domain == "" && f.Category == "" {
				return false, "either domain or category is required"
			}
			return true, ""
		}
	default:
		return func(f *NormalizedFinding) (bool, string) {
			return true, ""
		}
	}
}

// ParseConfig parses a configuration from a map.
func ParseConfig(cfg map[string]string) (*Config, error) {
	config := DefaultConfig()

	if interval, ok := cfg["adapterhub.sync_interval"]; ok {
		if d, err := time.ParseDuration(interval); err == nil {
			config.SyncInterval = d
		}
	}

	if interval, ok := cfg["adapterhub.health_interval"]; ok {
		if d, err := time.ParseDuration(interval); err == nil {
			config.HealthInterval = d
		}
	}

	if max, ok := cfg["adapterhub.max_concurrency"]; ok {
		fmt.Sscanf(max, "%d", &config.MaxConcurrency)
	}

	if profile, ok := cfg["adapterhub.default_profile"]; ok {
		config.DefaultProfile = profile
	}

	return config, nil
}
