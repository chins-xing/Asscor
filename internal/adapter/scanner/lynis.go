//go:build adapter

package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type lynisFinding struct {
	TestID      string
	Category    string
	Description string
	Result      string
	Severity    string
	Suggestion  string
}

var lynisPattern = regexp.MustCompile(`^([A-Z]+-\d{4})\s*\|(.+?)\|(.+?)\|(.+?)\|(.+)$`)

type LynisAdapter struct {
	adapter.BaseAdapter
}

func NewLynisAdapter() *LynisAdapter {
	return &LynisAdapter{
		BaseAdapter: adapter.NewBaseAdapter(
			"lynis",
			"Lynis",
			"scanner",
			"P0",
			"1.0",
		),
	}
}

var lynisSeverityMap = map[string]adapter.Severity{
	"HARDENING":   adapter.SeverityHigh,
	"WARNING":     adapter.SeverityMedium,
	"SUGGESTION":  adapter.SeverityLow,
	"INFORMATION": adapter.SeverityInfo,
	"OK":          adapter.SeverityInfo,
	"FOUND":       adapter.SeverityInfo,
	"NOT_FOUND":   adapter.SeverityMedium,
	"VULNERABLE":  adapter.SeverityCritical,
}

func (l *LynisAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	lynisPath := config["adapter_paths.lynis"]
	if lynisPath == "" {
		lynisPath = "lynis"
	}

	args := []string{"audit", "system", "--quick", "--no-colors"}

	cmd := exec.CommandContext(ctx, lynisPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return out, nil
		}
		return nil, fmt.Errorf("lynis execution failed: %w", err)
	}
	return out, nil
}

func (l *LynisAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	lines := strings.Split(string(raw), "\n")
	var findings []*adapter.NormalizedFinding
	now := time.Now()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := lynisPattern.FindStringSubmatch(line)
		if len(matches) != 6 {
			continue
		}

		testID := strings.TrimSpace(matches[1])
		category := strings.TrimSpace(matches[2])
		description := strings.TrimSpace(matches[3])
		result := strings.TrimSpace(matches[4])
		suggestion := strings.TrimSpace(matches[5])

		sev, ok := lynisSeverityMap[result]
		if !ok {
			sev = adapter.SeverityInfo
		}

		passed := result == "OK" || result == "FOUND" || result == "INFORMATION"

		domain := l.mapCategoryToDomain(category)

		f := &adapter.NormalizedFinding{
			ID:          testID,
			Source:      "lynis",
			ToolName:    "Lynis",
			Timestamp:   now,
			FindingType: adapter.FindingCompliance,
			Severity:    sev,
			Title:       description,
			Description: suggestion,
			Resource:    category,
			Passed:      passed,
			Detail:      fmt.Sprintf("[%s] %s", result, suggestion),
			Domain:      domain,
			Metadata: map[string]string{
				"category": category,
				"result":   result,
			},
		}

		adapter.ApplyDelegation(f, "lynis")
		findings = append(findings, f)
	}

	return findings, nil
}

func (l *LynisAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	for _, f := range findings {
		if !f.Passed && f.Severity == adapter.SeverityInfo {
			f.Severity = adapter.SeverityLow
		}
	}
	return findings
}

func (l *LynisAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

func (l *LynisAdapter) mapCategoryToDomain(category string) string {
	category = strings.ToUpper(strings.TrimSpace(category))
	switch {
	case strings.HasPrefix(category, "FIRE"):
		return model.DomainAttackSurface
	case strings.HasPrefix(category, "NETW"):
		return model.DomainAttackSurface
	case strings.HasPrefix(category, "KRNL"):
		return model.DomainKernelSecurity
	case strings.HasPrefix(category, "BOOT"):
		return model.DomainBusinessContinuity
	case strings.HasPrefix(category, "PROC"):
		return model.DomainBusinessContinuity
	case strings.HasPrefix(category, "AUTH"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "FILE"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "ACCT"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "LOGG"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "PKGS"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "MALW"):
		return model.DomainResilience
	case strings.HasPrefix(category, "HOME"):
		return model.DomainOperationTrust
	case strings.HasPrefix(category, "STRG"):
		return model.DomainBusinessContinuity
	default:
		return model.DomainOperationTrust
	}
}

func mapLynisScore(warnings int, suggestions int) int {
	score := 100
	score -= warnings * 2
	score -= suggestions
	if score < 0 {
		score = 0
	}
	return score
}

func parseLynisInt(s string) int {
	s = strings.TrimSpace(s)
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return 0
}
