package srd

import "time"

// ExternalAssessmentReport is the canonical form consumed by the SRD/Prism engine
// from any external assessment tool. All tool-specific adapters normalize into this type.
type ExternalAssessmentReport struct {
	Tool       string                   `json:"tool"`
	HostID     string                   `json:"host_id"`
	Hostname   string                   `json:"hostname"`
	ScanTime   time.Time                `json:"scan_time"`
	RawScore   float64                  `json:"raw_score"`
	RawGrade   string                   `json:"raw_grade,omitempty"`
	Items      []ExternalCheckResult    `json:"items"`
	Metadata   map[string]string        `json:"metadata,omitempty"`
}

// ExternalCheckResult represents a single finding from an external tool,
// normalized to a form compatible with SRD's CheckFailure.
type ExternalCheckResult struct {
	CheckID    string                 `json:"check_id"`
	RuleID     string                 `json:"rule_id,omitempty"`
	Title      string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Severity   string                 `json:"severity"`
	Result     string                 `json:"result"`
	Delta      float64                `json:"delta"`
	FailAt     int64                  `json:"fail_at_unix"`
	Category   string                 `json:"category"`
	Refs       []string               `json:"refs,omitempty"`
}

// SeverityProfile defines how an external tool's severity levels map to SSAM delta values.
type SeverityProfile struct {
	Critical float64
	High    float64
	Medium  float64
	Low     float64
	Info    float64
	Unknown float64
}

// Known profiles for common tools.
var (
	// CVSSProfile maps CVSS numeric severity to SSAM delta.
	// Delta = -(severity / 10), clamped to [-15, -5].
	CVSSProfile = SeverityProfile{
		Critical: -15,
		High:     -10,
		Medium:   -7.5,
		Low:      -5,
		Info:     0,
		Unknown:  -5,
	}

	// LynisSeverityProfile maps Lynis hardening categories to delta.
	LynisProfile = SeverityProfile{
		Critical: -15,
		High:     -10,
		Medium:   -7.5,
		Low:      -5,
		Info:     0,
		Unknown:  -5,
	}

	// CISProfile maps CIS benchmark achievement percentages to delta.
	// PassRate >= 80% -> delta = 0; lower percentages scale linearly.
	CISProfile = SeverityProfile{
		Critical: -15,
		High:     -10,
		Medium:   -7.5,
		Low:      -5,
		Info:     0,
		Unknown:  -5,
	}

	// GenericProfile is a conservative fallback.
	GenericProfile = SeverityProfile{
		Critical: -15,
		High:     -10,
		Medium:   -7.5,
		Low:      -5,
		Info:     0,
		Unknown:  -7.5,
	}
)

// DeltaFromSeverity converts a severity string to an SSAM delta value using the given profile.
// Supports multiple naming conventions (CIS, DISA, NIST, custom).
func (p SeverityProfile) DeltaFromSeverity(severity string) float64 {
	switch normalizeSeverity(severity) {
	case "critical", "high", "error":
		return p.Critical
	case "medium", "warning", "medium-high":
		return p.High
	case "low", "minimal":
		return p.Low
	case "info", "informational", "none", "pass":
		return p.Info
	default:
		return p.Unknown
	}
}

func normalizeSeverity(s string) string {
	switch s {
	case "I", "informational", "INFO", "none", "pass", "Pass":
		return "info"
	case "II", "low", "MINIMAL", "Low":
		return "low"
	case "III", "medium", "MEDIUM", "MED", "Medium", "Warning", "warning":
		return "medium"
	case "IV", "high", "HIGH", "High", "Error", "error":
		return "high"
	case "V", "critical", "CRITICAL", "Critical":
		return "critical"
	default:
		return s
	}
}

// Config holds SRD adapter module configuration.
type Config struct {
	SyncIntervalSec     int
	DefaultTransmission float64
	Profiles            map[string]SeverityProfile
	ProfilesDefault  string
	ScanPaths        map[string]string
	DefaultProfile   string
	EnabledAdapters  map[string]bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SyncIntervalSec: 3600,
		Profiles: map[string]SeverityProfile{
			"cvss":   CVSSProfile,
			"lynis":  LynisProfile,
			"cis":    CISProfile,
			"generic": GenericProfile,
		},
		ProfilesDefault: "generic",
		ScanPaths: map[string]string{
			"openscap": "/usr/share/xml/scap/ssg/content/",
			"lynis":    "/var/log/lynis/",
			"cis":      "/opt/cis-cat-reporter/",
		},
		EnabledAdapters: map[string]bool{
			"openscap": false,
			"lynis":    false,
			"generic":  true,
		},
	}
}
