package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/argus-security/argus/internal/model"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityNone     Severity = "none"
)

func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high":
		return SeverityHigh
	case "MEDIUM", "medium":
		return SeverityMedium
	case "LOW", "low":
		return SeverityLow
	case "INFO", "info":
		return SeverityInfo
	default:
		return SeverityNone
	}
}

type FindingType string

const (
	FindingVulnerability FindingType = "vulnerability"
	FindingMisconfig     FindingType = "misconfiguration"
	FindingCompliance    FindingType = "compliance"
	FindingAsset         FindingType = "asset"
	FindingIdentity      FindingType = "identity"
	FindingAlert         FindingType = "alert"
	FindingConfigState   FindingType = "config_state"
)

type NormalizedFinding struct {
	ID          string
	Source      string
	ToolName    string
	Timestamp   time.Time
	FindingType FindingType
	Severity    Severity

	CheckID     string
	Domain      string
	DelegatedTo string

	Title       string
	Description string
	Resource    string
	CVE         string
	CVSEScore   float64
	CVSSVector  string
	FixVersion  string
	Reference   string

	Passed  bool
	Detail  string

	RawData  string
	Metadata map[string]string
}

func (n NormalizedFinding) ToCheckResult() model.CheckResult {
	return model.CheckResult{
		CheckID:       n.CheckID,
		Domain:        n.Domain,
		Name:          n.Title,
		Passed:        n.Passed,
		Delta:         n.severityToDelta(),
		Detail:        n.Detail,
		ComplianceRef: n.Reference,
	}
}

func (n NormalizedFinding) severityToDelta() float64 {
	if n.Passed {
		return 0
	}
	switch n.Severity {
	case SeverityCritical:
		return -20
	case SeverityHigh:
		return -15
	case SeverityMedium:
		return -10
	case SeverityLow:
		return -5
	case SeverityInfo:
		return -2
	default:
		return 0
	}
}

type Adapter interface {
	ID() string
	Name() string
	Category() string
	Priority() string
	Version() string

	Fetch(ctx context.Context, config map[string]string) ([]byte, error)

	Parse(raw []byte) ([]*NormalizedFinding, error)

	Map(findings []*NormalizedFinding) []*NormalizedFinding

	Validate(findings []*NormalizedFinding) ([]*NormalizedFinding, []error)

	IsEnabled(config map[string]string) bool
}

type BaseAdapter struct {
	id       string
	name     string
	category string
	priority string
	version  string
}

func NewBaseAdapter(id, name, category, priority, version string) BaseAdapter {
	return BaseAdapter{
		id:       id,
		name:     name,
		category: category,
		priority: priority,
		version:  version,
	}
}

func (b BaseAdapter) ID() string        { return b.id }
func (b BaseAdapter) Name() string      { return b.name }
func (b BaseAdapter) Category() string  { return b.category }
func (b BaseAdapter) Priority() string  { return b.priority }
func (b BaseAdapter) Version() string   { return b.version }

func (b BaseAdapter) IsEnabled(config map[string]string) bool {
	v, ok := config[b.id]
	if !ok {
		return false
	}
	switch v {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

func ExecuteAdapter(ctx context.Context, a Adapter, config map[string]string) ([]*NormalizedFinding, error) {
	if !a.IsEnabled(config) {
		return nil, nil
	}

	raw, err := a.Fetch(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("adapter %s fetch: %w", a.ID(), err)
	}

	findings, err := a.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("adapter %s parse: %w", a.ID(), err)
	}

	findings = a.Map(findings)

	valid, errs := a.Validate(findings)
	if len(errs) > 0 {
		for _, e := range errs {
			LogWarn("adapter %s validation: %v", a.ID(), e)
		}
	}

	return valid, nil
}

func DefaultValidate(findings []*NormalizedFinding) ([]*NormalizedFinding, []error) {
	var valid []*NormalizedFinding
	var errs []error

	for _, f := range findings {
		if f == nil {
			continue
		}
		if f.Title == "" {
			errs = append(errs, fmt.Errorf("finding %s has empty title", f.ID))
			continue
		}
		if f.Domain == "" {
			errs = append(errs, fmt.Errorf("finding %s (%s) has empty domain", f.ID, f.Title))
			continue
		}
		valid = append(valid, f)
	}
	return valid, errs
}

func DefaultMap(findings []*NormalizedFinding) []*NormalizedFinding {
	return findings
}
