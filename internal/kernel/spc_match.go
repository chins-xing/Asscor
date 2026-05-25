package kernel

import (
	"strconv"
	"strings"
)

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func extractPkgNames(packages []string) []string {
	names := make([]string, 0, len(packages)*2)
	seen := make(map[string]bool, len(packages)*2)

	suffixes := []string{
		"-libs", "-devel", "-static", "-doc", "-debuginfo", "-debugsource",
		"-common", "-utils", "-tools", "-plugins", "-module", "-modules",
		"-daemon", "-server", "-client", "-cli", "-bin", "-data", "-lang",
		"-help", "-license", "-logrotate", "-sysconfig", "-config", "-conf",
		"-headers", "-dev", "-perl", "-python", "-python3", "-ruby",
		"-java", "-jni", "-bash", "-zsh", "-fish", "-tcsh",
		"-compat", "-legacy", "-minimal", "-full", "-core", "-base",
	}

	for _, pkg := range packages {
		name := pkg
		if idx := strings.IndexByte(name, ' '); idx > 0 {
			name = name[:idx]
		}

		baseName := name
		if idx := strings.IndexByte(name, '-'); idx > 0 {
			hasDigit := false
			for i := idx + 1; i < len(name); i++ {
				if name[i] >= '0' && name[i] <= '9' {
					hasDigit = true
					break
				}
			}
			if hasDigit {
				baseName = name[:idx]
			}
		}

		if baseName != "" && len(baseName) >= 2 && !seen[baseName] {
			names = append(names, baseName)
			seen[baseName] = true
		}

		stripped := baseName
		for _, suffix := range suffixes {
			if strings.HasSuffix(stripped, suffix) {
				core := stripped[:len(stripped)-len(suffix)]
				if core != "" && len(core) >= 2 && !seen[core] {
					names = append(names, core)
					seen[core] = true
				}
				stripped = core
			}
		}
	}
	return names
}

func (m *SPCModule) compareCPE(installed, vuln string) MatchType {
	cpePart := vuln
	var versionRange string
	if pipeIdx := strings.Index(vuln, "|"); pipeIdx >= 0 {
		cpePart = vuln[:pipeIdx]
		versionRange = vuln[pipeIdx+1:]
	}

	instParts := strings.Split(installed, ":")
	vulnParts := strings.Split(cpePart, ":")

	minLen := len(instParts)
	if len(vulnParts) < minLen {
		minLen = len(vulnParts)
	}

	matchCount := 0
	for i := 0; i < minLen; i++ {
		vulnPart := vulnParts[i]
		instPart := instParts[i]

		if vulnPart == "*" {
			matchCount++
			continue
		}
		if strings.EqualFold(vulnPart, instPart) {
			matchCount++
			continue
		}
		break
	}

	if matchCount >= 5 && versionRange == "" {
		if len(instParts) > 5 && instParts[5] != "*" && instParts[5] != "-" && len(vulnParts) > 5 && vulnParts[5] != "*" && vulnParts[5] != "-" {
			return MatchExactVersion
		}
		return MatchVersionRange
	}
	if matchCount >= 4 {
		if versionRange != "" && len(instParts) > 5 {
			instVersion := instParts[5]
			if m.versionInRange(instVersion, versionRange) {
				return MatchVersionRange
			}
			return MatchNone
		}
		return MatchVersionRange
	}
	if matchCount >= 3 {
		return MatchCPEProduct
	}
	if matchCount >= 2 {
		return MatchCPEVendor
	}
	return MatchNone
}

func (m *SPCModule) versionInRange(installedVersion, versionRange string) bool {
	if installedVersion == "*" || installedVersion == "-" {
		return true
	}

	constraints := strings.Split(versionRange, ",")
	for _, c := range constraints {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "vsi=") {
			bound := c[4:]
			if compareVersions(installedVersion, bound) < 0 {
				return false
			}
		} else if strings.HasPrefix(c, "vse=") {
			bound := c[4:]
			if compareVersions(installedVersion, bound) <= 0 {
				return false
			}
		} else if strings.HasPrefix(c, "vei=") {
			bound := c[4:]
			if compareVersions(installedVersion, bound) > 0 {
				return false
			}
		} else if strings.HasPrefix(c, "vee=") {
			bound := c[4:]
			if compareVersions(installedVersion, bound) >= 0 {
				return false
			}
		}
	}
	return true
}

func compareVersions(a, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var aPart, bPart versionPart
		if i < len(aParts) {
			aPart = aParts[i]
		}
		if i < len(bParts) {
			bPart = bParts[i]
		}
		cmp := compareVersionPart(aPart, bPart)
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

type versionPart struct {
	numVal   int
	strVal   string
	isNumber bool
}

func compareVersionPart(a, b versionPart) int {
	if a.isNumber && b.isNumber {
		if a.numVal < b.numVal {
			return -1
		}
		if a.numVal > b.numVal {
			return 1
		}
		return 0
	}
	if a.isNumber && !b.isNumber {
		return 1
	}
	if !a.isNumber && b.isNumber {
		return -1
	}
	if a.strVal < b.strVal {
		return -1
	}
	if a.strVal > b.strVal {
		return 1
	}
	return 0
}

func splitVersion(v string) []versionPart {
	v = strings.TrimLeft(v, "v")
	var parts []versionPart
	var current strings.Builder
	hasDigit := false
	hasAlpha := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		s := current.String()
		if !hasAlpha {
			n, err := strconv.Atoi(s)
			if err == nil {
				parts = append(parts, versionPart{numVal: n, strVal: s, isNumber: true})
				current.Reset()
				hasDigit = false
				hasAlpha = false
				return
			}
		}
		parts = append(parts, versionPart{strVal: s, isNumber: false})
		current.Reset()
		hasDigit = false
		hasAlpha = false
	}

	for _, ch := range v {
		if ch == '.' || ch == '-' || ch == '_' {
			flush()
			continue
		}
		if ch >= '0' && ch <= '9' {
			if hasAlpha {
				flush()
			}
			current.WriteRune(ch)
			hasDigit = true
		} else {
			if hasDigit {
				flush()
			}
			current.WriteRune(ch)
			hasAlpha = true
		}
	}
	flush()
	return parts
}
