//go:build adapter

package adapterhub

import (
	"time"

	"github.com/asscor/asscor/internal/adapter"
)

// Severity is a type alias for adapter.Severity, unifying the two packages.
type Severity = adapter.Severity

const (
	SeverityCritical = adapter.SeverityCritical
	SeverityHigh     = adapter.SeverityHigh
	SeverityMedium   = adapter.SeverityMedium
	SeverityLow      = adapter.SeverityLow
	SeverityInfo     = adapter.SeverityInfo
	SeverityNone     = adapter.SeverityNone
)

// Category represents the adapter category.
type Category string

const (
	CategoryScanner    Category = "scanner"
	CategoryManagement Category = "management"
	CategoryPrism     Category = "prism"
)

// Priority represents the adapter priority level.
type Priority string

const (
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
)

// AdapterMetadata contains basic adapter information.
type AdapterMetadata struct {
	ID          string
	Name        string
	Category    Category
	Priority    Priority
	Version     string
	Description string
	Author      string
	Tags        []string
}

// HealthStatus represents the health state of an adapter.
type HealthStatus string

const (
	HealthUnknown   HealthStatus = "unknown"
	HealthHealthy   HealthStatus = "healthy"
	HealthDegraded  HealthStatus = "degraded"
	HealthUnhealthy HealthStatus = "unhealthy"
)

// HealthInfo contains health check details.
type HealthInfo struct {
	Status    HealthStatus
	Message   string
	Timestamp time.Time
	Latency   time.Duration
}

// AdapterState represents the lifecycle state of an adapter.
type AdapterState int

const (
	StateRegistered  AdapterState = iota
	StateInitialized
	StateRunning
	StateStopping
	StateStopped
)

func (s AdapterState) String() string {
	switch s {
	case StateRegistered:
		return "registered"
	case StateInitialized:
		return "initialized"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Input represents the raw input to an adapter.
type Input struct {
	Source    string
	Path      string
	Data      []byte
	Metadata  map[string]string
	Timestamp time.Time
}

// Output represents the normalized output from an adapter.
type Output struct {
	AdapterID string
	Findings  []*NormalizedFinding
	RawReport interface{}
	Metadata  map[string]string
	Timestamp time.Time
	Duration  time.Duration
	Error     error
}

// NormalizedFinding is the universal finding format across all adapters.
type NormalizedFinding struct {
	ID          string
	Source      string
	CheckID     string
	RuleID      string
	Title       string
	Description string
	Severity    Severity
	Domain      string
	Category    string
	Result      Result
	Delta       float64
	CVSSScore   float64
	CVE         string
	Resource    string
	Timestamp   time.Time
	References  []string
	Metadata    map[string]string
	Passed      bool
}

// Severity is a type alias for adapter.Severity — see top of file.

// Result represents the check result.
type Result string

const (
	ResultPass    Result = "pass"
	ResultFail    Result = "fail"
	ResultError   Result = "error"
	ResultSkip    Result = "skip"
	ResultUnknown Result = "unknown"
)

// AdapterContext carries adapter execution context including rules.
type AdapterContext struct {
	Rules    *RuleSet
	Config   map[string]string
	Metadata map[string]interface{}
}

// UnifiedAdapter is the universal interface for all adapters.
type UnifiedAdapter interface {
	Metadata() AdapterMetadata
	Initialize(ctx AdapterContext) error
	Execute(ctx AdapterContext, input Input) (Output, error)
	HealthCheck(ctx AdapterContext) HealthInfo
	Stop(ctx AdapterContext) error
	Capabilities() []Capability
}

// Capability describes what an adapter can do.
type Capability struct {
	Type        CapabilityType
	Description string
	InputTypes  []string
	OutputTypes []string
}

// CapabilityType represents the type of capability.
type CapabilityType string

const (
	CapabilityScan      CapabilityType = "scan"
	CapabilityMonitor   CapabilityType = "monitor"
	CapabilityImport   CapabilityType = "import"
	CapabilityExport   CapabilityType = "export"
	CapabilityTransform CapabilityType = "transform"
	CapabilityValidate CapabilityType = "validate"
)
