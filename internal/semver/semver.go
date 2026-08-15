package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// SemVer represents a semantic version (major.minor.patch[-pre]).
type SemVer struct {
	Major int
	Minor int
	Patch int
	Pre   string
}

// ParseSemVer parses a semantic version string.
func Parse(v string) (SemVer, error) {
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

func (s SemVer) Less(other SemVer) bool    { return s.Compare(other) < 0 }
func (s SemVer) Greater(other SemVer) bool { return s.Compare(other) > 0 }
func (s SemVer) Equal(other SemVer) bool   { return s.Compare(other) == 0 }

// Constraint represents a version constraint.
type Constraint struct {
	Min     SemVer
	Max     SemVer
	MinOpen bool
	MaxOpen bool
	hasMin  bool
	hasMax  bool
}

// ParseConstraint parses a version constraint string.
// Supports: >=1.0, >1.0, <=2.0, <2.0, 1.0-2.0, ^1.2.3, ~1.2.3, 1.x, exact
func ParseConstraint(s string) (Constraint, error) {
	vc := Constraint{}
	s = strings.TrimSpace(s)
	if s == "" {
		return vc, fmt.Errorf("empty constraint")
	}

	if strings.HasPrefix(s, ">=") {
		v, err := Parse(strings.TrimSpace(s[2:]))
		if err != nil {
			return vc, err
		}
		vc.Min = v
		vc.hasMin = true
		return vc, nil
	}
	if strings.HasPrefix(s, ">") {
		v, err := Parse(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.Min = v
		vc.MinOpen = true
		vc.hasMin = true
		return vc, nil
	}
	if strings.HasPrefix(s, "<=") {
		v, err := Parse(strings.TrimSpace(s[2:]))
		if err != nil {
			return vc, err
		}
		vc.Max = v
		vc.hasMax = true
		return vc, nil
	}
	if strings.HasPrefix(s, "<") {
		v, err := Parse(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.Max = v
		vc.MaxOpen = true
		vc.hasMax = true
		return vc, nil
	}

	// ^1.2.3 → >=1.2.3 <2.0.0
	if strings.HasPrefix(s, "^") {
		v, err := Parse(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.Min = v
		vc.hasMin = true
		vc.Max = SemVer{Major: v.Major + 1}
		vc.MaxOpen = true
		vc.hasMax = true
		return vc, nil
	}

	// ~1.2.3 → >=1.2.3 <1.3.0
	if strings.HasPrefix(s, "~") {
		v, err := Parse(strings.TrimSpace(s[1:]))
		if err != nil {
			return vc, err
		}
		vc.Min = v
		vc.hasMin = true
		vc.Max = SemVer{Major: v.Major, Minor: v.Minor + 1}
		vc.MaxOpen = true
		vc.hasMax = true
		return vc, nil
	}

	// 1.0 - 2.0 or 1.0-2.0
	if strings.Contains(s, "-") && !strings.Contains(s, " - ") {
		// Only treat as range if it looks like "1.0-2.0" (two version-looking parts)
		parts := strings.SplitN(s, "-", 2)
		if looksLikeVersion(parts[0]) && looksLikeVersion(parts[1]) {
			v1, err := Parse(strings.TrimSpace(parts[0]))
			if err != nil {
				return vc, err
			}
			v2, err := Parse(strings.TrimSpace(parts[1]))
			if err != nil {
				return vc, err
			}
			vc.Min = v1
			vc.hasMin = true
			vc.Max = v2
			vc.hasMax = true
			return vc, nil
		}
	}
	if strings.Contains(s, " - ") {
		parts := strings.SplitN(s, " - ", 2)
		v1, err := Parse(strings.TrimSpace(parts[0]))
		if err != nil {
			return vc, err
		}
		v2, err := Parse(strings.TrimSpace(parts[1]))
		if err != nil {
			return vc, err
		}
		vc.Min = v1
		vc.hasMin = true
		vc.Max = v2
		vc.hasMax = true
		return vc, nil
	}

	// 1.x, 1.X, 1.* → ~1.0.0
	if strings.ContainsAny(s, "xX*") {
		lo := strings.NewReplacer("x", "0", "X", "0", "*", "0").Replace(s)
		v, err := Parse(strings.TrimSpace(lo))
		if err != nil {
			return vc, err
		}
		vc.Min = v
		vc.hasMin = true
		vc.Max = SemVer{Major: v.Major + 1}
		vc.MaxOpen = true
		vc.hasMax = true
		return vc, nil
	}

	v, err := Parse(s)
	if err != nil {
		return vc, err
	}
	vc.Min = v
	vc.Max = v
	vc.hasMin = true
	vc.hasMax = true
	return vc, nil
}

func looksLikeVersion(s string) bool {
	parts := strings.SplitN(strings.TrimSpace(s), ".", 2)
	if len(parts) > 0 {
		_, err := strconv.Atoi(parts[0])
		return err == nil
	}
	return false
}

// SatisfiedBy checks if the given version satisfies the constraint.
func (vc Constraint) SatisfiedBy(v SemVer) bool {
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

func (vc Constraint) HasMin() bool { return vc.hasMin }
func (vc Constraint) HasMax() bool { return vc.hasMax }
