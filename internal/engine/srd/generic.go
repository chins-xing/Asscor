//go:build engine

package srd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// genericAdapter is a catch-all JSON adapter. It accepts any JSON file conforming to
// the GenericJSONReport schema. Tools that don't have a dedicated adapter (CIS-CAT,
// OWASP Dependency-Check, grype, Trivy, Gitleaks, Semgrep, etc.) can use this adapter
// by producing output in the GenericJSONReport format.
//
// To use: set `srd.generic.file` config to the path of the JSON report file.
type genericAdapter struct{}

func newGenericAdapter() Adapter { return &genericAdapter{} }

func (a *genericAdapter) ToolID() string   { return "generic" }
func (a *genericAdapter) ToolName() string { return "Generic JSON (fallback for other tools)" }

func (a *genericAdapter) IsEnabled(cfg Config) bool {
	if enabled, ok := cfg.EnabledAdapters["generic"]; ok {
		return enabled
	}
	return true // generic is enabled by default as the fallback
}

func (a *genericAdapter) SupportsFormat(path string) bool {
	return strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".jsonl")
}

// Parse accepts any JSON that can be unmarshaled into GenericJSONReport.
// If the top-level JSON is not a GenericJSONReport, it attempts to:
//   - Unmarshal as a list of GenericCheckItem (array-of-items format)
//   - Unmarshal as a map with known finding keys
func (a *genericAdapter) Parse(ctx context.Context, input []byte) (*ExternalAssessmentReport, error) {
	input = trimSpace(input)
	if len(input) == 0 {
		return nil, fmt.Errorf("generic: empty input")
	}

	// Try the full GenericJSONReport schema first.
	var full GenericJSONReport
	if err := json.Unmarshal(input, &full); err == nil && full.Items != nil {
		profile := a.resolveProfile(full.Tool)
		return BuildReportFromGeneric(full, profile)
	}

	// Try as a list of GenericCheckItem (some tools output just an array).
	var items []GenericCheckItem
	if err := json.Unmarshal(input, &items); err == nil && len(items) > 0 {
		return a.buildFromItems(items, GenericProfile)
	}

	// Try common wrapped formats.
	wrapped := a.tryUnwrap(input)
	if wrapped != nil {
		return a.Parse(ctx, wrapped)
	}

	return nil, fmt.Errorf("generic: input does not match known JSON schemas")
}

// tryUnwrap handles common wrapper formats used by various tools.
func (a *genericAdapter) tryUnwrap(input []byte) []byte {
	// Try {"findings": [...]} or {"vulnerabilities": [...]} or {"results": [...]}.
	wrappers := []string{"findings", "vulnerabilities", "results", "issues", "alerts", "matches"}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(input, &m); err != nil {
		return nil
	}

	for _, key := range wrappers {
		if raw, ok := m[key]; ok {
			// Verify it's actually an array.
			if len(raw) > 0 && raw[0] == '[' {
				return raw
			}
		}
	}

	// Try {"report": {...}}.
	if raw, ok := m["report"]; ok {
		if len(raw) > 0 && raw[0] == '{' {
			return raw
		}
	}

	return nil
}

func (a *genericAdapter) buildFromItems(items []GenericCheckItem, profile SeverityProfile) (*ExternalAssessmentReport, error) {
	now := time.Now()
	report := &ExternalAssessmentReport{
		Tool:     "generic",
		HostID:   "unknown",
		Hostname: "unknown",
		ScanTime: now,
		Items:    make([]ExternalCheckResult, 0, len(items)),
	}

	var failCount int
	for _, item := range items {
		result := "pass"
		if item.Result == "fail" || item.Result == "error" || item.Result == "warning" {
			result = "fail"
		}

		failAt := item.FailAt
		if failAt == 0 {
			failAt = now.Unix()
		}

		delta := 0.0
		if result == "fail" {
			delta = profile.DeltaFromSeverity(item.Severity)
			failCount++
		}

		checkID := item.ID
		if checkID == "" && item.RuleID != "" {
			checkID = item.RuleID
		}
		if checkID == "" {
			checkID = fmt.Sprintf("generic-%d", len(report.Items))
		}

		report.Items = append(report.Items, ExternalCheckResult{
			CheckID:     checkID,
			RuleID:      item.RuleID,
			Title:       item.Title,
			Description: item.Description,
			Severity:    item.Severity,
			Result:      result,
			Delta:       delta,
			FailAt:      failAt,
			Category:    item.Category,
			Refs:        item.Refs,
		})
	}

	if len(items) > 0 {
		report.RawScore = 100.0 * float64(len(items)-failCount) / float64(len(items))
	}

	return report, nil
}

func (a *genericAdapter) resolveProfile(tool string) SeverityProfile {
	switch strings.ToLower(tool) {
	case "trivy", "grype", "snyk", "ossindex":
		return SeverityProfile{
			Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -7.5,
		}
	case "owasp", "dependency-check", "zip":
		return SeverityProfile{
			Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -10,
		}
	case "gitleaks", "semgrep", "trufflehog":
		return SeverityProfile{
			Critical: -10, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -7.5,
		}
	case "wazuh", "ossec":
		return SeverityProfile{
			Critical: -15, High: -10, Medium: -7.5, Low: -5, Info: 0, Unknown: -7.5,
		}
	default:
		return GenericProfile
	}
}

func trimSpace(b []byte) []byte {
	i := 0
	for ; i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r'); i++ {
	}
	j := len(b)
	for ; j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r'); j-- {
	}
	return b[i:j]
}
