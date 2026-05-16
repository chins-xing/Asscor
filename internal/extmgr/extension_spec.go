package extmgr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ExtensionType string

const (
	ExtTypeCheckModule  ExtensionType = "check_module"
	ExtTypeScoringPlugin ExtensionType = "scoring_plugin"
	ExtTypeAdapter      ExtensionType = "adapter"
	ExtTypeHook         ExtensionType = "hook"
	ExtTypeDomain       ExtensionType = "domain"
	ExtTypeEdgeFactor   ExtensionType = "edge_factor"
	ExtTypeCustom       ExtensionType = "custom"
)

type ExtensionState string

const (
	ExtStateInstalled ExtensionState = "installed"
	ExtStateEnabled   ExtensionState = "enabled"
	ExtStateDisabled  ExtensionState = "disabled"
	ExtStateError     ExtensionState = "error"
)

type SemVer struct {
	Major int
	Minor int
	Patch int
	Pre   string
}

func ParseSemVer(v string) (SemVer, error) {
	sv := SemVer{}
	rest := v

	idxDash := strings.Index(rest, "-")
	if idxDash >= 0 {
		sv.Pre = rest[idxDash+1:]
		rest = rest[:idxDash]
	}

	parts := strings.Split(rest, ".")
	if len(parts) < 1 {
		return sv, fmt.Errorf("invalid semver: %s", v)
	}

	var err error
	sv.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return sv, fmt.Errorf("invalid major version in %s: %w", v, err)
	}
	if len(parts) >= 2 {
		sv.Minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return sv, fmt.Errorf("invalid minor version in %s: %w", v, err)
		}
	}
	if len(parts) >= 3 {
		sv.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return sv, fmt.Errorf("invalid patch version in %s: %w", v, err)
		}
	}
	return sv, nil
}

func (s SemVer) String() string {
	if s.Pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s", s.Major, s.Minor, s.Patch, s.Pre)
	}
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
}

func (s SemVer) Compare(other SemVer) int {
	if s.Major != other.Major {
		return s.Major - other.Major
	}
	if s.Minor != other.Minor {
		return s.Minor - other.Minor
	}
	if s.Patch != other.Patch {
		return s.Patch - other.Patch
	}
	if s.Pre == "" && other.Pre == "" {
		return 0
	}
	if s.Pre == "" {
		return 1
	}
	if other.Pre == "" {
		return -1
	}
	if s.Pre < other.Pre {
		return -1
	}
	if s.Pre > other.Pre {
		return 1
	}
	return 0
}

func (s SemVer) Less(other SemVer) bool  { return s.Compare(other) < 0 }
func (s SemVer) Greater(other SemVer) bool { return s.Compare(other) > 0 }
func (s SemVer) Equal(other SemVer) bool   { return s.Compare(other) == 0 }

type VersionConstraint struct {
	Min     SemVer
	Max     SemVer
	MinOpen bool
	MaxOpen bool
	hasMin  bool
	hasMax  bool
}

func ParseVersionConstraint(s string) (VersionConstraint, error) {
	vc := VersionConstraint{}
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, ">=") {
		var err error
		vc.Min, err = ParseSemVer(strings.TrimSpace(s[2:]))
		if err != nil {
			return vc, err
		}
		vc.MinOpen = false
		vc.hasMin = true
		return vc, nil
	}
	if strings.HasPrefix(s, ">") {
		var err error
		vc.Min, err = ParseSemVer(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.MinOpen = true
		vc.hasMin = true
		return vc, nil
	}
	if strings.HasPrefix(s, "<=") {
		var err error
		vc.Max, err = ParseSemVer(strings.TrimSpace(s[2:]))
		if err != nil {
			return vc, err
		}
		vc.MaxOpen = false
		vc.hasMax = true
		return vc, nil
	}
	if strings.HasPrefix(s, "<") {
		var err error
		vc.Max, err = ParseSemVer(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.MaxOpen = true
		vc.hasMax = true
		return vc, nil
	}
	if strings.Contains(s, " - ") {
		parts := strings.SplitN(s, " - ", 2)
		var err error
		vc.Min, err = ParseSemVer(strings.TrimSpace(parts[0]))
		if err != nil {
			return vc, err
		}
		vc.hasMin = true
		vc.Max, err = ParseSemVer(strings.TrimSpace(parts[1]))
		if err != nil {
			return vc, err
		}
		vc.hasMax = true
		return vc, nil
	}

	ver, err := ParseSemVer(s)
	if err != nil {
		return vc, err
	}
	vc.Min = ver
	vc.Max = ver
	vc.MinOpen = false
	vc.MaxOpen = false
	vc.hasMin = true
	vc.hasMax = true
	return vc, nil
}

func (vc VersionConstraint) SatisfiedBy(v SemVer) bool {
	if vc.hasMin {
		cmp := v.Compare(vc.Min)
		if vc.MinOpen {
			if cmp <= 0 {
				return false
			}
		} else {
			if cmp < 0 {
				return false
			}
		}
	}
	if vc.hasMax {
		cmp := v.Compare(vc.Max)
		if vc.MaxOpen {
			if cmp >= 0 {
				return false
			}
		} else {
			if cmp > 0 {
				return false
			}
		}
	}
	return true
}

type DependencySpec struct {
	ExtensionID string
	Constraint  VersionConstraint
}

type SourceSpec struct {
	URL      string
	Type     string
	Checksum string
	Branch   string
}

type ExtensionSpec struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	ExtType      ExtensionType     `json:"type"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage"`
	Dependencies []DependencySpec  `json:"dependencies"`
	Source       SourceSpec        `json:"source"`
	CustomConfig map[string]string `json:"custom_config"`
	InstallPath  string            `json:"install_path"`
	InstallTime  time.Time         `json:"install_time"`
	State        ExtensionState    `json:"state"`
	Error        string            `json:"error,omitempty"`
}

func (s ExtensionSpec) SemVer() (SemVer, error) {
	return ParseSemVer(s.Version)
}

func (s ExtensionSpec) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("extension id is required")
	}
	if s.Name == "" {
		return fmt.Errorf("extension name is required")
	}
	if s.Version == "" {
		return fmt.Errorf("extension version is required")
	}
	if _, err := s.SemVer(); err != nil {
		return fmt.Errorf("invalid version %q: %w", s.Version, err)
	}
	if s.Source.URL == "" {
		return fmt.Errorf("extension source URL is required")
	}
	if s.Source.Type == "" {
		s.Source.Type = detectSourceType(s.Source.URL)
	}
	switch s.ExtType {
	case ExtTypeCheckModule, ExtTypeScoringPlugin, ExtTypeAdapter,
		ExtTypeHook, ExtTypeDomain, ExtTypeEdgeFactor, ExtTypeCustom:
	default:
		return fmt.Errorf("unknown extension type: %s", s.ExtType)
	}
	for _, dep := range s.Dependencies {
		if dep.ExtensionID == "" {
			return fmt.Errorf("dependency extension id is required")
		}
	}
	return nil
}

func (s ExtensionSpec) VerifyIntegrity(data []byte) error {
	if s.Source.Checksum == "" {
		return nil
	}
	parts := strings.SplitN(s.Source.Checksum, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid checksum format: %s", s.Source.Checksum)
	}
	algo, expected := parts[0], parts[1]
	switch algo {
	case "sha256":
		h := sha256.Sum256(data)
		actual := hex.EncodeToString(h[:])
		if actual != expected {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
		}
	default:
		return fmt.Errorf("unsupported checksum algorithm: %s", algo)
	}
	return nil
}

func detectSourceType(url string) string {
	url = strings.ToLower(url)
	if strings.HasPrefix(url, "git://") || strings.HasPrefix(url, "git+") ||
		strings.HasSuffix(url, ".git") || strings.Contains(url, "github.com") ||
		strings.Contains(url, "gitlab.com") {
		return "git"
	}
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return "http"
	}
	return "local"
}
