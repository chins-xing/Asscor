//go:build engine

package srd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// atomicRedAdapter parses Atomic Red Team execution results (JSON).
// Atomic Red Team is a framework for testing detection capabilities against
// MITRE ATT&CK techniques. It produces structured JSON output via
// Invoke-AtomicTest -GetExecutedResults.
//
// Severity mapping (based on test execution outcome):
//   test succeeded (no detection) -> severity "high"
//   test succeeded (detection triggered) -> severity "medium"
//   test failed (could not execute) -> severity "low"
//   test skipped / manual -> severity "info"

type atomicRedAdapter struct{}

func newAtomicRedAdapter() Adapter { return &atomicRedAdapter{} }

// --- Atomic Red Team JSON types ---

// AtomicRedResults is the top-level structure for Atomic Red Team execution output.
type AtomicRedResults struct {
	Techniques []AtomicRedTechnique `json:"techniques"`
}

// AtomicRedTechnique represents a single technique execution result.
type AtomicRedTechnique struct {
	TechniqueID   string                `json:"technique_id"`
	TechniqueName string                `json:"technique_name"`
	DisplayName   string                `json:"display_name,omitempty"`
	Tactic        string                `json:"tactic,omitempty"`
	Platform      string                `json:"platform,omitempty"`
	Tests         []AtomicRedTestResult `json:"tests,omitempty"`
	// Flat format: single test per entry
	TestName         string `json:"test_name,omitempty"`
	TestNumber       string `json:"test_number,omitempty"`
	TestGUID         string `json:"test_guid,omitempty"`
	ExecutionTime    string `json:"execution_time,omitempty"`
	ExecutionStatus  string `json:"execution_status,omitempty"`
	Status           string `json:"status,omitempty"`
	DetectionTriggered bool `json:"detection_triggered,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	ComputerName     string `json:"computer_name,omitempty"`
	Output           string `json:"output,omitempty"`
	Error            string `json:"error,omitempty"`
}

// AtomicRedTestResult is a single test execution within a technique.
type AtomicRedTestResult struct {
	TestName         string `json:"test_name"`
	TestNumber       string `json:"test_number,omitempty"`
	TestGUID         string `json:"test_guid,omitempty"`
	ExecutionTime    string `json:"execution_time,omitempty"`
	Status           string `json:"status"`
	DetectionTriggered bool `json:"detection_triggered,omitempty"`
	Output           string `json:"output,omitempty"`
	Error            string `json:"error,omitempty"`
}

// --- Adapter implementation ---

func (a *atomicRedAdapter) ToolID() string   { return "atomic_red_team" }
func (a *atomicRedAdapter) ToolName() string { return "Atomic Red Team" }

func (a *atomicRedAdapter) IsEnabled(cfg Config) bool {
	if enabled, ok := cfg.EnabledAdapters["atomic_red_team"]; ok {
		return enabled
	}
	return false
}

func (a *atomicRedAdapter) SupportsFormat(path string) bool {
	return strings.HasSuffix(path, ".json") &&
		(strings.Contains(path, "atomic") ||
			strings.Contains(path, "art") ||
			strings.Contains(path, "red_team"))
}

func (a *atomicRedAdapter) Parse(ctx context.Context, input []byte) (*ExternalAssessmentReport, error) {
	input = []byte(strings.TrimSpace(string(input)))

	// Try structured format: {"techniques": [...]}
	if strings.Contains(string(input), `"techniques"`) {
		return a.parseStructured(input)
	}

	// Try flat format: array of technique results
	if strings.HasPrefix(string(input), "[") {
		return a.parseFlatArray(input)
	}

	// Try single technique object
	if strings.HasPrefix(string(input), "{") && strings.Contains(string(input), `"technique_id"`) {
		return a.parseSingleTechnique(input)
	}

	return nil, fmt.Errorf("atomic_red_team: unrecognized input format")
}

// parseStructured parses the full {"techniques": [...]} format.
func (a *atomicRedAdapter) parseStructured(input []byte) (*ExternalAssessmentReport, error) {
	var results AtomicRedResults
	if err := json.Unmarshal(input, &results); err != nil {
		return nil, fmt.Errorf("atomic_red_team parse error: %w", err)
	}

	hostname := "unknown"
	scanTime := time.Now()
	items := make([]ExternalCheckResult, 0)

	for _, tech := range results.Techniques {
		// Collect hostname from first technique that has it
		if hostname == "unknown" && tech.Hostname != "" {
			hostname = tech.Hostname
		} else if hostname == "unknown" && tech.ComputerName != "" {
			hostname = tech.ComputerName
		}

		// Parse execution time
		if tech.ExecutionTime != "" {
			if t, err := time.Parse(time.RFC3339, tech.ExecutionTime); err == nil {
				scanTime = t
			}
		}

		// Process nested tests
		for _, test := range tech.Tests {
			item := a.buildCheckResult(tech.TechniqueID, test.TestName, test.TestNumber,
				test.Status, test.DetectionTriggered, test.ExecutionTime, tech.Tactic)
			items = append(items, item)
		}

		// Process flat-format test in the technique itself
		if len(tech.Tests) == 0 && tech.TestName != "" {
			status := tech.ExecutionStatus
			if status == "" {
				status = tech.Status
			}
			item := a.buildCheckResult(tech.TechniqueID, tech.TestName, tech.TestNumber,
				status, tech.DetectionTriggered, tech.ExecutionTime, tech.Tactic)
			items = append(items, item)
		}
	}

	return a.buildReport(hostname, scanTime, items), nil
}

// parseFlatArray parses [{technique_id: "T1059.001", ...}, ...] format.
func (a *atomicRedAdapter) parseFlatArray(input []byte) (*ExternalAssessmentReport, error) {
	var techniques []AtomicRedTechnique
	if err := json.Unmarshal(input, &techniques); err != nil {
		return nil, fmt.Errorf("atomic_red_team flat array parse error: %w", err)
	}

	hostname := "unknown"
	scanTime := time.Now()
	items := make([]ExternalCheckResult, 0)

	for _, tech := range techniques {
		if hostname == "unknown" && tech.Hostname != "" {
			hostname = tech.Hostname
		} else if hostname == "unknown" && tech.ComputerName != "" {
			hostname = tech.ComputerName
		}

		if tech.ExecutionTime != "" {
			if t, err := time.Parse(time.RFC3339, tech.ExecutionTime); err == nil {
				scanTime = t
			}
		}

		status := tech.ExecutionStatus
		if status == "" {
			status = tech.Status
		}

		item := a.buildCheckResult(tech.TechniqueID, tech.TestName, tech.TestNumber,
			status, tech.DetectionTriggered, tech.ExecutionTime, tech.Tactic)
		items = append(items, item)
	}

	return a.buildReport(hostname, scanTime, items), nil
}

// parseSingleTechnique parses a single {"technique_id": "T1059.001", ...} object.
func (a *atomicRedAdapter) parseSingleTechnique(input []byte) (*ExternalAssessmentReport, error) {
	var tech AtomicRedTechnique
	if err := json.Unmarshal(input, &tech); err != nil {
		return nil, fmt.Errorf("atomic_red_team single technique parse error: %w", err)
	}

	hostname := tech.Hostname
	if hostname == "" {
		hostname = tech.ComputerName
	}
	if hostname == "" {
		hostname = "unknown"
	}

	scanTime := time.Now()
	if tech.ExecutionTime != "" {
		if t, err := time.Parse(time.RFC3339, tech.ExecutionTime); err == nil {
			scanTime = t
		}
	}

	status := tech.ExecutionStatus
	if status == "" {
		status = tech.Status
	}

	item := a.buildCheckResult(tech.TechniqueID, tech.TestName, tech.TestNumber,
		status, tech.DetectionTriggered, tech.ExecutionTime, tech.Tactic)

	return a.buildReport(hostname, scanTime, []ExternalCheckResult{item}), nil
}

// buildCheckResult creates an ExternalCheckResult from an Atomic Red Team test.
func (a *atomicRedAdapter) buildCheckResult(techID, testName, testNumber, status string,
	detectionTriggered bool, execTime, tactic string) ExternalCheckResult {

	// In Atomic Red Team, "succeeded" means the attack test ran successfully.
	// In ASSCOR terms, this means the defense failed → "fail".
	// "failed" means the test couldn't run → "pass" (defense may have blocked it).
	// "skipped" / "manual" → "pass" (not applicable).
	assessmentResult := "fail"
	severity := "high"

	switch status {
	case "succeeded", "success", "completed":
		assessmentResult = "fail"
		if detectionTriggered {
			severity = "medium" // Detection triggered but attack still succeeded
		} else {
			severity = "high" // Attack succeeded with no detection
		}
	case "failed", "failure", "error":
		assessmentResult = "pass" // Test could not execute
		severity = "low"
	case "skipped", "manual", "not_applicable":
		assessmentResult = "pass"
		severity = "info"
	default:
		assessmentResult = "fail"
		severity = "medium"
	}

	delta := 0.0
	if assessmentResult == "fail" {
		switch severity {
		case "high":
			delta = -10.0
		case "medium":
			delta = -7.5
		case "low":
			delta = -5.0
		case "info":
			delta = 0.0
		default:
			delta = -5.0
		}
	}

	failAt := time.Now().Unix()
	if execTime != "" {
		if t, err := time.Parse(time.RFC3339, execTime); err == nil {
			failAt = t.Unix()
		}
	}

	checkID := fmt.Sprintf("art-%s-%s", techID, testNumber)
	if testNumber == "" {
		checkID = fmt.Sprintf("art-%s", techID)
	}

	desc := fmt.Sprintf("Atomic Red Team test: %s", testName)
	if tactic != "" {
		desc = fmt.Sprintf("[%s] %s", tactic, testName)
	}

	return ExternalCheckResult{
		CheckID:     checkID,
		RuleID:      techID,
		Title:       testName,
		Description: desc,
		Severity:    severity,
		Result:      assessmentResult,
		Delta:       delta,
		FailAt:      failAt,
		Category:    "AtomicRedTeam",
		Refs:        []string{fmt.Sprintf("https://attack.mitre.org/techniques/%s/", techID)},
	}
}

// buildReport constructs the final ExternalAssessmentReport.
func (a *atomicRedAdapter) buildReport(hostname string, scanTime time.Time,
	items []ExternalCheckResult) *ExternalAssessmentReport {

	var totalDelta float64
	var failCount, totalCount int
	for _, item := range items {
		totalDelta += item.Delta
		totalCount++
		if item.Result == "fail" {
			failCount++
		}
	}

	rawScore := 100.0
	if totalCount > 0 {
		rawScore = 100.0 * float64(totalCount-failCount) / float64(totalCount)
	}

	return &ExternalAssessmentReport{
		Tool:     "atomic_red_team",
		HostID:   hostname,
		Hostname: hostname,
		ScanTime: scanTime,
		RawScore: rawScore,
		Items:    items,
		Metadata: map[string]string{
			"total_tests":  fmt.Sprintf("%d", totalCount),
			"failed_tests": fmt.Sprintf("%d", failCount),
			"avg_delta":    fmt.Sprintf("%.2f", totalDelta/float64(max(totalCount, 1))),
		},
	}
}