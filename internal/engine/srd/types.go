//go:build engine

package srd

import (
	"time"

	kernelconfig "github.com/chins-xing/asscor/internal/config"
)

// ExternalAssessmentReport is the canonical form consumed by the SRD/Prism engine
// from any external assessment tool. All tool-specific adapters normalize into this type.
type ExternalAssessmentReport struct {
	Tool     string                `json:"tool"`
	HostID   string                `json:"host_id"`
	Hostname string                `json:"hostname"`
	ScanTime time.Time             `json:"scan_time"`
	RawScore float64               `json:"raw_score"`
	RawGrade string                `json:"raw_grade,omitempty"`
	Items    []ExternalCheckResult `json:"items"`
	Metadata map[string]string     `json:"metadata,omitempty"`
}

// ExternalCheckResult represents a single finding from an external tool,
// normalized to a form compatible with SRD's CheckFailure.
type ExternalCheckResult struct {
	CheckID     string   `json:"check_id"`
	RuleID      string   `json:"rule_id,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Result      string   `json:"result"`
	Delta       float64  `json:"delta"`
	FailAt      int64    `json:"fail_at_unix"`
	Category    string   `json:"category"`
	Refs        []string `json:"refs,omitempty"`
	// Confidence is the intelligence confidence of this external finding in
	// [0,1] (model-native, design CONFIDENCE_MODEL_DESIGN_2026-09-08 §2.5).
	// Adapters map it from the tool's own confidence/source signals; 0 means
	// unspecified → prism treats as 1.0 (legacy).
	Confidence float64 `json:"confidence,omitempty"`
}

// SeverityProfile defines how an external tool's severity levels map to SSAM delta values.
type SeverityProfile struct {
	Critical float64
	High     float64
	Medium   float64
	Low      float64
	Info     float64
	Unknown  float64
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
	ProfilesDefault     string
	ScanPaths           map[string]string
	DefaultProfile      string
	EnabledAdapters     map[string]bool
	// LayeredGraph 打开 SRD 的**分层图**边构造（L1 链路 / L2 广播域 / L3 路由 /
	// L4 策略 / L5 资产）。**SRD v2.0 起默认开启**：实测 ROC（10 轮随机 ACL，
	// 每轮实测真值）分层模型 AUC 0.888±0.039，单层模型 0.474±0.035。
	// 需要回退到单层模型时在 config.ini 设 `[srd] layered_graph = false`。
	LayeredGraph bool
	// Roles 是运维配置的业务角色（host -> role），用于 L5 资产语义：
	// 有角色时覆盖区域映射得到的关键性。
	Roles map[string]string

	// 以下参数来自 config.ini [srd] / [prism]，v2.2 起可运维调整：
	MaxPathDepth    int     // 路径枚举最大深度（prism.MaxPathDepth）
	PathDecay       float64 // 路径风险衰减（prism.PathDecay）
	PropCap         float64 // 传播惩罚上限（prism.PropCap）
	AggregationMode string  // 传播聚合模式 rss/max/linear
	HorizonDays     int     // 推理层预测窗口（prism.HorizonDays）

	// v2.3.6：补齐 prism 的其余可调参数（[prism] 段，srd.* 亦可覆盖）。
	DebtAlpha          float64 // 安全债务超线性指数（默认 1.2）
	DebtCap            float64 // 债务惩罚上限（默认 0.30）
	DebtNormDays       float64 // 债务归一化分母（天，默认 1500）
	ScoreFloor         float64 // 下界稳定项（默认 0.15）
	CollapseBeta       float64 // 塌缩超线性指数（默认 1.5）
	StableThreshold    float64 // Stable 隶属度上界（默认 0.90）
	DegradedThreshold  float64 // Degraded 隶属度上界（默认 0.70）
	UntrustedThreshold float64 // Untrusted 隶属度上界（默认 0.50）

	// Confidence is the kernel's [confidence] rule table (same
	// config.ConfidenceConfig the SSAM/legacy paths use). nil means "not
	// wired" → legacy passthrough. When non-nil AND Enabled, a failed external
	// item that carries no confidence of its own resolves through
	// ConfidenceConfig.Resolve with the report's tool id as the source key
	// (tool-supplied > [confidence.source] > default; audit I-8).
	Confidence *kernelconfig.ConfidenceConfig
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SyncIntervalSec:    3600,
		LayeredGraph:       true,
		MaxPathDepth:       5,
		PathDecay:          0.80,
		PropCap:            0.25,
		AggregationMode:    "rss",
		HorizonDays:        7,
		DebtAlpha:          1.2,
		DebtCap:            0.30,
		DebtNormDays:       1500,
		ScoreFloor:         0.15,
		CollapseBeta:       1.5,
		StableThreshold:    0.90,
		DegradedThreshold:  0.70,
		UntrustedThreshold: 0.50,
		Profiles: map[string]SeverityProfile{
			"cvss":    CVSSProfile,
			"lynis":   LynisProfile,
			"cis":     CISProfile,
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
