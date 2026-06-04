package adapterhub

import (
	"fmt"
	"strings"
)

// RuleType represents the type of rule.
type RuleType string

const (
	RuleTypeSeverity      RuleType = "severity"
	RuleTypeDomain       RuleType = "domain"
	RuleTypeDelta        RuleType = "delta"
	RuleTypeValidation   RuleType = "validation"
	RuleTypeTransform    RuleType = "transform"
	RuleTypeFilter       RuleType = "filter"
	RuleTypeAggregation  RuleType = "aggregation"
)

// RuleSet contains all rules for adapter processing.
type RuleSet struct {
	SeverityRules    []SeverityRule
	DomainRules      []DomainRule
	DeltaRules       []DeltaRule
	ValidationRules  []ValidationRule
	TransformRules   []TransformRule
	FilterRules      []FilterRule
}

// SeverityRule normalizes severity values from various tools to standard Severity levels.
type SeverityRule struct {
	Name        string
	Tool        string
	Priority    int
	Mappings    map[string]Severity
	Description string
}

// Normalize converts a raw severity string to a standard Severity.
func (r SeverityRule) Normalize(raw string) Severity {
	if s, ok := r.Mappings[strings.ToLower(raw)]; ok {
		return s
	}
	return SeverityNone
}

// DomainRule maps findings to SSAM domains based on rules.
type DomainRule struct {
	Name        string
	Tool        string
	Priority    int
	CheckID     string
	Domain      string
	Category    string
	Description string
}

// DeltaRule calculates delta values based on severity and context.
type DeltaRule struct {
	Name        string
	Tool        string
	Priority    int
	Severity    Severity
	BaseDelta   float64
	Conditions  []DeltaCondition
	Description string
}

// DeltaCondition is a condition that modifies delta calculation.
type DeltaCondition struct {
	Field    string
	Operator string
	Value    interface{}
}

// ValidationRule validates findings before processing.
type ValidationRule struct {
	Name        string
	Tool        string
	Priority    int
	CheckFunc   func(f *NormalizedFinding) (bool, string)
	Description string
}

// TransformRule transforms finding data based on patterns.
type TransformRule struct {
	Name         string
	Tool         string
	Priority     int
	Field        string
	TransformFunc func(input string) string
	Description  string
}

// FilterRule filters findings based on criteria.
type FilterRule struct {
	Name        string
	Tool        string
	Priority    int
	Conditions  []FilterCondition
	Action      FilterAction
	Description string
}

// FilterCondition is a condition for filtering findings.
type FilterCondition struct {
	Field    string
	Operator string
	Value    interface{}
}

// FilterAction determines what to do with filtered findings.
type FilterAction string

const (
	FilterActionInclude FilterAction = "include"
	FilterActionExclude FilterAction = "exclude"
	FilterActionTag     FilterAction = "tag"
)

// RuleEngine processes findings through all applicable rules.
type RuleEngine struct {
	globalRules    *RuleSet
	toolRules      map[string]*RuleSet
	defaultProfile *SeverityProfile
}

// NewRuleEngine creates a new rule engine with global rules.
func NewRuleEngine(globalRules *RuleSet) *RuleEngine {
	return &RuleEngine{
		globalRules:    globalRules,
		toolRules:      make(map[string]*RuleSet),
		defaultProfile:  DefaultGenericProfile(),
	}
}

// RegisterToolRules registers rules specific to a tool.
func (e *RuleEngine) RegisterToolRules(tool string, rules *RuleSet) {
	e.toolRules[tool] = rules
}

// ApplySeverity applies severity normalization rules to a finding.
func (e *RuleEngine) ApplySeverity(finding *NormalizedFinding) {
	rules := e.getSeverityRulesForTool(finding.Source)

	for _, rule := range rules {
		if finding.Severity = rule.Normalize(string(finding.Severity)); finding.Severity != SeverityNone {
			return
		}
	}
}

// ApplyDomain applies domain mapping rules to a finding.
func (e *RuleEngine) ApplyDomain(finding *NormalizedFinding) {
	if finding.Domain != "" {
		return
	}

	rules := e.getDomainRulesForTool(finding.Source)

	for _, rule := range rules {
		if rule.CheckID != "" && rule.CheckID == finding.CheckID {
			finding.Domain = rule.Domain
			return
		}
	}
}

// ApplyDelta applies delta calculation rules to a finding.
func (e *RuleEngine) ApplyDelta(finding *NormalizedFinding) {
	if finding.Result == ResultPass {
		finding.Delta = 0
		return
	}

	rules := e.getDeltaRulesForTool(finding.Source)

	for _, rule := range rules {
		if rule.Severity == finding.Severity {
			delta := rule.BaseDelta
			for _, cond := range rule.Conditions {
				if e.evaluateCondition(finding, cond) {
					delta *= 1.1
				}
			}
			finding.Delta = delta
			return
		}
	}

	finding.Delta = e.defaultProfile.DeltaFromSeverity(string(finding.Severity))
}

// Validate applies validation rules to a finding.
func (e *RuleEngine) Validate(finding *NormalizedFinding) (bool, []string) {
	var errors []string

	rules := e.getValidationRulesForTool(finding.Source)

	for _, rule := range rules {
		if ok, msg := rule.CheckFunc(finding); !ok {
			errors = append(errors, fmt.Sprintf("[%s] %s", rule.Name, msg))
		}
	}

	return len(errors) == 0, errors
}

// ApplyTransform applies transformation rules to a finding.
func (e *RuleEngine) ApplyTransform(finding *NormalizedFinding) {
	rules := e.getTransformRulesForTool(finding.Source)

	for _, rule := range rules {
		switch rule.Field {
		case "check_id":
			finding.CheckID = rule.TransformFunc(finding.CheckID)
		case "rule_id":
			finding.RuleID = rule.TransformFunc(finding.RuleID)
		case "title":
			finding.Title = rule.TransformFunc(finding.Title)
		case "description":
			finding.Description = rule.TransformFunc(finding.Description)
		}
	}
}

// ApplyFilter applies filter rules to a list of findings.
func (e *RuleEngine) ApplyFilter(findings []*NormalizedFinding, tool string) []*NormalizedFinding {
	rules := e.getFilterRulesForTool(tool)

	result := findings
	for _, rule := range rules {
		result = e.applyFilterRule(result, rule)
	}
	return result
}

func (e *RuleEngine) getValidationRulesForTool(tool string) []ValidationRule {
	var result []ValidationRule

	for _, r := range e.globalRules.ValidationRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	return result
}

func (e *RuleEngine) getTransformRulesForTool(tool string) []TransformRule {
	var result []TransformRule

	for _, r := range e.globalRules.TransformRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	return result
}

func (e *RuleEngine) getFilterRulesForTool(tool string) []FilterRule {
	var result []FilterRule

	for _, r := range e.globalRules.FilterRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	return result
}

func (e *RuleEngine) applyFilterRule(findings []*NormalizedFinding, rule FilterRule) []*NormalizedFinding {
	var result []*NormalizedFinding
	for _, f := range findings {
		matches := e.matchesFilterConditions(f, rule.Conditions)
		if matches && rule.Action == FilterActionInclude {
			result = append(result, f)
		} else if !matches && rule.Action == FilterActionExclude {
			result = append(result, f)
		} else if matches && rule.Action == FilterActionTag {
			if f.Metadata == nil {
				f.Metadata = make(map[string]string)
			}
			f.Metadata["filtered_by"] = rule.Name
			result = append(result, f)
		}
	}
	return result
}

func (e *RuleEngine) matchesFilterConditions(f *NormalizedFinding, conditions []FilterCondition) bool {
	for _, cond := range conditions {
		if !e.evaluateCondition(f, DeltaCondition{Field: cond.Field, Operator: cond.Operator, Value: cond.Value}) {
			return false
		}
	}
	return true
}

func (e *RuleEngine) evaluateCondition(f *NormalizedFinding, cond DeltaCondition) bool {
	var fieldVal interface{}
	switch cond.Field {
	case "severity":
		fieldVal = string(f.Severity)
	case "domain":
		fieldVal = f.Domain
	case "category":
		fieldVal = f.Category
	case "result":
		fieldVal = string(f.Result)
	case "check_id":
		fieldVal = f.CheckID
	case "has_cve":
		fieldVal = f.CVE != ""
	default:
		if f.Metadata != nil {
			fieldVal = f.Metadata[cond.Field]
		}
	}

	switch cond.Operator {
	case "==":
		return fmt.Sprintf("%v", fieldVal) == fmt.Sprintf("%v", cond.Value)
	case "!=":
		return fmt.Sprintf("%v", fieldVal) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldVal), fmt.Sprintf("%v", cond.Value))
	case "exists":
		return fieldVal != nil && fmt.Sprintf("%v", fieldVal) != ""
	default:
		return false
	}
}

func (e *RuleEngine) getSeverityRulesForTool(tool string) []SeverityRule {
	var result []SeverityRule

	for _, r := range e.globalRules.SeverityRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	if toolRules, ok := e.toolRules[tool]; ok {
		for _, r := range toolRules.SeverityRules {
			if r.Tool == "" || r.Tool == tool {
				result = append(result, r)
			}
		}
	}

	return result
}

func (e *RuleEngine) getDomainRulesForTool(tool string) []DomainRule {
	var result []DomainRule

	for _, r := range e.globalRules.DomainRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	if toolRules, ok := e.toolRules[tool]; ok {
		for _, r := range toolRules.DomainRules {
			if r.Tool == "" || r.Tool == tool {
				result = append(result, r)
			}
		}
	}

	return result
}

func (e *RuleEngine) getDeltaRulesForTool(tool string) []DeltaRule {
	var result []DeltaRule

	for _, r := range e.globalRules.DeltaRules {
		if r.Tool == "" || r.Tool == tool {
			result = append(result, r)
		}
	}

	if toolRules, ok := e.toolRules[tool]; ok {
		for _, r := range toolRules.DeltaRules {
			if r.Tool == "" || r.Tool == tool {
				result = append(result, r)
			}
		}
	}

	return result
}

// ApplyAll applies all applicable rules to a finding.
func (e *RuleEngine) ApplyAll(finding *NormalizedFinding) {
	e.ApplyTransform(finding)
	e.ApplySeverity(finding)
	e.ApplyDomain(finding)
	e.ApplyDelta(finding)
}

// SeverityProfile defines how severity levels map to delta values.
type SeverityProfile struct {
	Critical float64
	High     float64
	Medium   float64
	Low      float64
	Info     float64
	Unknown  float64
}

// DefaultGenericProfile returns the default generic severity profile.
func DefaultGenericProfile() *SeverityProfile {
	return &SeverityProfile{
		Critical: -15,
		High:     -10,
		Medium:   -7.5,
		Low:      -5,
		Info:     0,
		Unknown:  -7.5,
	}
}

// DeltaFromSeverity converts a severity to a delta value.
func (p *SeverityProfile) DeltaFromSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return p.Critical
	case "high":
		return p.High
	case "medium":
		return p.Medium
	case "low":
		return p.Low
	case "info", "none":
		return p.Info
	default:
		return p.Unknown
	}
}

// BuiltInProfiles returns all built-in severity profiles.
func BuiltInProfiles() map[string]*SeverityProfile {
	return map[string]*SeverityProfile{
		"generic":  DefaultGenericProfile(),
		"cvss":    {Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -5},
		"lynis":   {Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -5},
		"cis":     {Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -5},
		"disa":    {Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -5},
		"cisa":    {Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -5},
	}
}
