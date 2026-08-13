//go:build engine

package srd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// lynisAdapter parses Lynis JSON output (lynis report --json) and Lynis report dat files.
// Lynis severity mapping:
//   - "warning" or "hardening potential" >= 50%  -> high (-10)
//   - "suggestion" or "hardening potential" 20-49% -> medium (-7.5)
//   - "note"                                    -> low (-5)
//   - passed/no finding                         -> 0

type lynisAdapter struct{}

func newLynisAdapter() Adapter { return &lynisAdapter{} }

// LynisReport is the JSON structure emitted by `lynis show report --json`.
type LynisReport struct {
	Header    LynisHeader    `json:"header"`
	Host      LynisHost      `json:"host"`
	Groups    map[string]interface{} `json:"groups,omitempty"`
	Tests     map[string]LynisTest  `json:"tests,omitempty"`
	Plugins   map[string]json.RawMessage `json:"plugins,omitempty"`
}

type LynisHeader struct {
	Program   string `json:"program"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname,omitempty"`
}

type LynisHost struct {
	Hostname   string `json:"hostname"`
	HostID1    string `json:"hostid1,omitempty"`
	HostID2    string `json:"hostid2,omitempty"`
	HostIDUUID string `json:"hostid2-uuid,omitempty"`
	IPAddress  string `json:"ip-address,omitempty"`
	MACAddress string `json:"mac-address,omitempty"`
}

type LynisTest struct {
	Result    string  `json:"result"`
	UUID      string  `json:"uuid,omitempty"`
	Date      string  `json:"date,omitempty"`
	WarnCount int     `json:"warnings,omitempty"`
}

// LynisReportDat is the key=value format from /var/log/lynis-report.dat.
type LynisReportDat struct {
	HardeningIndex float64 `json:"hardening_index"`
	TestsPassed    int     `json:"tests_passed"`
	TestsWarning   int     `json:"tests_warning"`
	TestsFailed    int     `json:"tests_failed"`
	Hostname       string  `json:"host_name"`
	HostID1        string  `json:"hostid1"`
	HostID2        string  `json:"hostid2"`
}

// LynisItem is the normalized check result used internally.
type LynisItem struct {
	ID       string
	Category string
	Title    string
	Result   string
	Level    string
	Date     string
}

func (a *lynisAdapter) ToolID()   string { return "lynis" }
func (a *lynisAdapter) ToolName() string { return "Lynis (Unix/Linux Security Auditing)" }

func (a *lynisAdapter) IsEnabled(cfg Config) bool {
	if enabled, ok := cfg.EnabledAdapters["lynis"]; ok {
		return enabled
	}
	return false
}

func (a *lynisAdapter) SupportsFormat(path string) bool {
	return strings.HasSuffix(path, "lynis-report.json") ||
		strings.HasSuffix(path, "lynis-report.dat") ||
		strings.Contains(path, "lynis")
}

func (a *lynisAdapter) Parse(ctx context.Context, input []byte) (*ExternalAssessmentReport, error) {
	input = trimmedBytes(input)

	if isJSON(input) {
		return a.parseJSON(input)
	}

	if bytes.Contains(input, []byte("=")) && !bytes.HasPrefix(input, []byte("<")) {
		return a.parseReportDat(input)
	}

	return nil, fmt.Errorf("lynis: unrecognized format")
}

func isJSON(b []byte) bool {
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

func trimmedBytes(b []byte) []byte {
	return bytes.TrimSpace(b)
}

func (a *lynisAdapter) parseJSON(input []byte) (*ExternalAssessmentReport, error) {
	var report LynisReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("lynis JSON parse error: %w", err)
	}

	scanTime := time.Now()
	if report.Header.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, report.Header.Timestamp); err == nil {
			scanTime = t
		}
	}

	hostID := report.Host.Hostname
	if report.Host.HostID1 != "" {
		hostID = report.Host.HostID1
	}

	result := &ExternalAssessmentReport{
		Tool:     "lynis",
		HostID:   hostID,
		Hostname: report.Host.Hostname,
		ScanTime: scanTime,
		Items:    make([]ExternalCheckResult, 0),
		Metadata: map[string]string{
			"version": report.Header.Version,
		},
	}

	var warnCount, total int

	for id, test := range report.Groups {
		if id == "" {
			continue
		}
		total++
		res, level := normalizeLynisTestResult(test, id)
		delta := 0.0
		if res == "fail" {
			delta = lynisDelta(level)
			warnCount++
		}
		result.Items = append(result.Items, ExternalCheckResult{
			CheckID:  sanitizeLynisID(id),
			Title:   id,
			Result:  res,
			Severity: level,
			Delta:   delta,
			FailAt:  scanTime.Unix(),
			Category: "Lynis",
		})
	}

	for id, test := range report.Tests {
		total++
		res, level := normalizeLynisTest(test, id)
		delta := 0.0
		if res == "fail" {
			delta = lynisDelta(level)
			warnCount++
		}
		failAt := scanTime.Unix()
		if test.Date != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", test.Date); err == nil {
				failAt = t.Unix()
			}
		}
		result.Items = append(result.Items, ExternalCheckResult{
			CheckID:  sanitizeLynisID(id),
			Title:   id,
			Result:  res,
			Severity: level,
			Delta:   delta,
			FailAt:  failAt,
			Category: "Lynis",
		})
	}

	if total > 0 {
		result.RawScore = 100.0 * float64(total-warnCount) / float64(total)
	} else {
		result.RawScore = 100.0
	}

	return result, nil
}

func normalizeLynisTestResult(v interface{}, id string) (string, string) {
	switch val := v.(type) {
	case string:
		return normalizeLynisResult(val), lynisInferLevel(val)
	case float64:
		if val > 0 {
			return "fail", "high"
		}
		return "pass", "info"
	default:
		return "pass", "info"
	}
}

func normalizeLynisTest(t LynisTest, id string) (string, string) {
	return normalizeLynisResult(t.Result), lynisInferLevel(t.Result)
}

func normalizeLynisResult(r string) string {
	r = strings.ToLower(r)
	switch {
	case strings.Contains(r, "warning") || strings.Contains(r, "suggestion") || strings.Contains(r, "hardening"):
		return "fail"
	case strings.Contains(r, "note"):
		return "fail"
	case strings.Contains(r, "skipped") || strings.Contains(r, "not performed"):
		return "pass"
	case strings.Contains(r, "done") || strings.Contains(r, "found") && !strings.Contains(r, "not found"):
		return "fail"
	default:
		if strings.Contains(r, "pass") || strings.Contains(r, "ok") {
			return "pass"
		}
		return "fail"
	}
}

func lynisInferLevel(r string) string {
	r = strings.ToLower(r)
	if strings.Contains(r, "warning") {
		if strings.Contains(r, "hardening") {
			return "high"
		}
		return "medium"
	}
	if strings.Contains(r, "suggestion") {
		return "medium"
	}
	if strings.Contains(r, "note") {
		return "low"
	}
	return "info"
}

// lynisDelta maps Lynis finding level to SSAM delta.
func lynisDelta(level string) float64 {
	switch level {
	case "critical", "high":
		return -10.0
	case "medium":
		return -7.5
	case "low":
		return -5.0
	default:
		return 0.0
	}
}

func sanitizeLynisID(id string) string {
	id = strings.TrimPrefix(id, "lynis_")
	id = strings.ReplaceAll(id, "_", "-")
	if id == "" {
		return "lynis-unknown"
	}
	return "LYN-" + strings.ToUpper(id[:min(len(id), 8)])
}

// parseReportDat parses Lynis report dat (key=value format from /var/log/lynis-report.dat).
func (a *lynisAdapter) parseReportDat(input []byte) (*ExternalAssessmentReport, error) {
	lines := strings.Split(string(input), "\n")
	scanTime := time.Now()
	hostID := "unknown"
	hostname := "unknown"
	var items []ExternalCheckResult
	var hardeningIndex float64 = 100
	var testsPassed, testsWarning, testsFailed int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "hostid1":
			hostID = val
		case "host_name", "hostname":
			hostname = val
		case "hardening_index":
			fmt.Sscanf(val, "%f", &hardeningIndex)
		case "tests_passed":
			fmt.Sscanf(val, "%d", &testsPassed)
		case "tests_warning":
			fmt.Sscanf(val, "%d", &testsWarning)
		case "tests_failed":
			fmt.Sscanf(val, "%d", &testsFailed)
		default:
			if strings.HasPrefix(key, "test.") && val != "" && !strings.Contains(val, "OK") {
				result := "fail"
				if strings.Contains(val, "WARNING") {
					items = append(items, ExternalCheckResult{
						CheckID:  "LYN-" + strings.ToUpper(key[5:12]),
						Title:    key,
						Result:   result,
						Severity: lynisInferLevel(val),
						Delta:    -7.5,
						FailAt:   scanTime.Unix(),
						Category: "Lynis",
					})
				}
			}
		}
	}

	rawScore := hardeningIndex
	if rawScore == 0 && (testsPassed+testsWarning+testsFailed) > 0 {
		rawScore = 100.0 * float64(testsPassed) / float64(testsPassed+testsWarning+testsFailed)
	}

	return &ExternalAssessmentReport{
		Tool:     "lynis",
		HostID:   hostID,
		Hostname: hostname,
		ScanTime: scanTime,
		RawScore: rawScore,
		Items:    items,
		Metadata: map[string]string{
			"tests_passed":  fmt.Sprintf("%d", testsPassed),
			"tests_warning": fmt.Sprintf("%d", testsWarning),
			"tests_failed":  fmt.Sprintf("%d", testsFailed),
		},
	}, nil
}
