package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/argus-security/argus/internal/adapter"
	"github.com/argus-security/argus/internal/model"
)

// ===== OpenSCAP Adapter (SC-004, P1) =====

type OpenSCAPAdapter struct {
	adapter.BaseAdapter
}

func NewOpenSCAPAdapter() *OpenSCAPAdapter {
	return &OpenSCAPAdapter{
		BaseAdapter: adapter.NewBaseAdapter("openscap", "OpenSCAP", "scanner", "P1", "1.0"),
	}
}

func (o *OpenSCAPAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	oscapPath := config["adapter_paths.openscap"]
	if oscapPath == "" {
		oscapPath = "oscap"
	}

	profile := config["openscap.profile"]
	if profile == "" {
		profile = "xccdf_org.ssgproject.content_profile_standard"
	}

	datastream := config["openscap.datastream"]
	if datastream == "" {
		datastream = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
	}

	cmd := exec.CommandContext(ctx, oscapPath, "xccdf", "eval", "--profile", profile,
		"--results", "/tmp/oscap-results.xml", "--report", "/tmp/oscap-report.html",
		datastream)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return out, nil
		}
		return nil, fmt.Errorf("openscap execution failed: %w", err)
	}
	return out, nil
}

func (o *OpenSCAPAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	text := string(raw)
	var findings []*adapter.NormalizedFinding
	now := time.Now()

	lines := strings.Split(text, "\n")
	resultID := ""
	severity := adapter.SeverityInfo
	passed := true

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "pass"):
			passed = true
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				resultID = strings.TrimSpace(line[:idx])
			}
		case strings.Contains(line, "fail"):
			passed = false
			severity = adapter.ParseSeverity("medium")
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				resultID = strings.TrimSpace(line[:idx])
			}
		default:
			continue
		}
		if resultID == "" {
			continue
		}

		findings = append(findings, &adapter.NormalizedFinding{
			ID:          resultID,
			Source:      "openscap",
			ToolName:    "OpenSCAP",
			Timestamp:   now,
			FindingType: adapter.FindingCompliance,
			Severity:    severity,
			Title:       resultID,
			Passed:      passed,
			Detail:      fmt.Sprintf("Compliance check %s: %v", resultID, passed),
			Domain:      model.DomainOperationTrust,
		})
		adapter.ApplyDelegation(findings[len(findings)-1], "openscap")
		resultID = ""
		severity = adapter.SeverityInfo
	}

	return findings, nil
}

func (o *OpenSCAPAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (o *OpenSCAPAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Wazuh Agent Adapter (SC-005, P1) =====

type WazuhAgentAdapter struct {
	adapter.BaseAdapter
}

func NewWazuhAgentAdapter() *WazuhAgentAdapter {
	return &WazuhAgentAdapter{
		BaseAdapter: adapter.NewBaseAdapter("wazuh_agent", "Wazuh Agent", "scanner", "P1", "1.0"),
	}
}

type wazuhAlert struct {
	Timestamp string          `json:"timestamp"`
	Rule      wazuhRule       `json:"rule"`
	Agent     wazuhAgentInfo  `json:"agent"`
	Location  string          `json:"location"`
	FullLog   string          `json:"full_log"`
}

type wazuhRule struct {
	ID          int    `json:"id"`
	Level       int    `json:"level"`
	Description string `json:"description"`
	Groups      []string `json:"groups"`
}

type wazuhAgentInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func (w *WazuhAgentAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	wazuhPath := config["adapter_paths.wazuh_agent"]
	if wazuhPath == "" {
		wazuhPath = "/var/ossec/bin/wazuh-control"
	}
	cmd := exec.CommandContext(ctx, wazuhPath, "status")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wazuh agent fetch failed: %w", err)
	}
	return out, nil
}

func (w *WazuhAgentAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	text := strings.TrimSpace(string(raw))
	now := time.Now()
	running := strings.Contains(strings.ToLower(text), "running")

	return []*adapter.NormalizedFinding{{
		ID:          "WAZUH-AGENT-STATUS",
		Source:      "wazuh_agent",
		ToolName:    "Wazuh Agent",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "Wazuh Agent Status",
		Passed:      running,
		Detail:      fmt.Sprintf("Wazuh agent is %s", map[bool]string{true: "running", false: "not running"}[running]),
		Domain:      model.DomainResilience,
		DelegatedTo: "wazuh_agent",
	}}, nil
}

func (w *WazuhAgentAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (w *WazuhAgentAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Suricata Adapter (SC-006, P1) =====

type SuricataAdapter struct {
	adapter.BaseAdapter
}

func NewSuricataAdapter() *SuricataAdapter {
	return &SuricataAdapter{
		BaseAdapter: adapter.NewBaseAdapter("suricata", "Suricata", "scanner", "P1", "1.0"),
	}
}

type suricataEVE struct {
	Timestamp   string          `json:"timestamp"`
	EventType   string          `json:"event_type"`
	SrcIP       string          `json:"src_ip"`
	DestIP      string          `json:"dest_ip"`
	Alert       *suricataAlert  `json:"alert"`
}

type suricataAlert struct {
	Action    string `json:"action"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
}

func (s *SuricataAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	suricataPath := config["adapter_paths.suricata"]
	if suricataPath == "" {
		suricataPath = "suricata"
	}
	eveFile := config["suricata.eve_json_path"]
	if eveFile == "" {
		eveFile = "/var/log/suricata/eve.json"
	}

	cmd := exec.CommandContext(ctx, suricataPath, "--build-info")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("suricata fetch failed: %w", err)
	}

	result := suricataCombinedOutput{
		BuildInfo: strings.TrimSpace(string(out)),
	}

	if eveData, err := os.ReadFile(eveFile); err == nil && len(eveData) > 0 {
		result.Alerts = parseSuricataEVELines(eveData, 100)
	}

	statsFile := config["suricata.stats_path"]
	if statsFile == "" {
		statsFile = "/var/log/suricata/stats.log"
	}
	if statsData, err := os.ReadFile(statsFile); err == nil {
		result.Stats = strings.TrimSpace(string(statsData))
	}

	combined, err := json.Marshal(result)
	if err != nil {
		return out, nil
	}
	return combined, nil
}

type suricataCombinedOutput struct {
	BuildInfo string               `json:"build_info"`
	Alerts    []suricataEVEAlert   `json:"alerts,omitempty"`
	Stats     string               `json:"stats,omitempty"`
}

type suricataEVEAlert struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
	Action    string `json:"action"`
}

func parseSuricataEVELines(data []byte, maxAlerts int) []suricataEVEAlert {
	var alerts []suricataEVEAlert
	lines := strings.Split(string(data), "\n")
	count := 0
	for i := len(lines) - 1; i >= 0 && count < maxAlerts; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var eve suricataEVE
		if err := json.Unmarshal([]byte(line), &eve); err != nil {
			continue
		}
		if eve.EventType != "alert" || eve.Alert == nil {
			continue
		}
		alerts = append(alerts, suricataEVEAlert{
			Timestamp: eve.Timestamp,
			SrcIP:     eve.SrcIP,
			DestIP:    eve.DestIP,
			Signature: eve.Alert.Signature,
			Category:  eve.Alert.Category,
			Severity:  eve.Alert.Severity,
			Action:    eve.Alert.Action,
		})
		count++
	}
	return alerts
}

func (s *SuricataAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var combined suricataCombinedOutput
	if err := json.Unmarshal(raw, &combined); err != nil {
		running := strings.Contains(string(raw), "Suricata")
		return []*adapter.NormalizedFinding{{
			ID:          "SURICATA-STATUS",
			Source:      "suricata",
			ToolName:    "Suricata",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Title:       "Suricata NIDS Status",
			Passed:      running,
			Detail:      fmt.Sprintf("Suricata NIDS is %s", map[bool]string{true: "available", false: "not available"}[running]),
			Domain:      model.DomainResilience,
			DelegatedTo: "suricata",
		}}, nil
	}

	installed := strings.Contains(combined.BuildInfo, "Suricata")
	findings := []*adapter.NormalizedFinding{{
		ID:          "SURICATA-STATUS",
		Source:      "suricata",
		ToolName:    "Suricata",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "Suricata NIDS Status",
		Passed:      installed,
		Detail:      fmt.Sprintf("Suricata NIDS is %s", map[bool]string{true: "installed", false: "not installed"}[installed]),
		Domain:      model.DomainResilience,
		DelegatedTo: "suricata",
	}}

	for i, alert := range combined.Alerts {
		sev := adapter.SeverityLow
		switch {
		case alert.Severity == 1:
			sev = adapter.SeverityCritical
		case alert.Severity == 2:
			sev = adapter.SeverityHigh
		case alert.Severity == 3:
			sev = adapter.SeverityMedium
		}

		findings = append(findings, &adapter.NormalizedFinding{
			ID:          fmt.Sprintf("SURICATA-ALERT-%d", i+1),
			Source:      "suricata",
			ToolName:    "Suricata",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Severity:    sev,
			Title:       alert.Signature,
			Passed:      false,
			Detail:      fmt.Sprintf("Alert: %s [%s] from %s to %s (severity=%d, action=%s)", alert.Signature, alert.Category, alert.SrcIP, alert.DestIP, alert.Severity, alert.Action),
			Domain:      model.DomainResilience,
			DelegatedTo: "suricata",
			Metadata: map[string]string{
				"src_ip":   alert.SrcIP,
				"dest_ip":  alert.DestIP,
				"category": alert.Category,
				"action":   alert.Action,
			},
		})
	}

	return findings, nil
}

func (s *SuricataAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (s *SuricataAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== Falco Adapter (SC-007, P1) =====

type FalcoAdapter struct {
	adapter.BaseAdapter
}

func NewFalcoAdapter() *FalcoAdapter {
	return &FalcoAdapter{
		BaseAdapter: adapter.NewBaseAdapter("falco", "Falco", "scanner", "P1", "1.0"),
	}
}

func (f *FalcoAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	falcoPath := config["adapter_paths.falco"]
	if falcoPath == "" {
		falcoPath = "falco"
	}

	cmd := exec.CommandContext(ctx, falcoPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("falco fetch failed: %w", err)
	}

	result := falcoCombinedOutput{
		Version: strings.TrimSpace(string(out)),
	}

	logFile := config["falco.log_path"]
	if logFile == "" {
		logFile = "/var/log/falco.log"
	}
	if logData, err := os.ReadFile(logFile); err == nil && len(logData) > 0 {
		result.Events = parseFalcoLogLines(logData, 100)
	}

	jsonOutput := config["falco.json_output"]
	if jsonOutput == "" {
		jsonOutput = "/var/log/falco.json"
	}
	if jsonData, err := os.ReadFile(jsonOutput); err == nil && len(jsonData) > 0 {
		result.JSONEvents = parseFalcoJSONLines(jsonData, 100)
	}

	combined, err := json.Marshal(result)
	if err != nil {
		return out, nil
	}
	return combined, nil
}

type falcoCombinedOutput struct {
	Version    string             `json:"version"`
	Events     []falcoLogEvent    `json:"events,omitempty"`
	JSONEvents []falcoJSONEvent   `json:"json_events,omitempty"`
}

type falcoLogEvent struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type falcoJSONEvent struct {
	Time       string `json:"time"`
	Rule       string `json:"rule"`
	Priority   string `json:"priority"`
	Output     string `json:"output"`
	Source     string `json:"source"`
	Tags       string `json:"tags,omitempty"`
}

func parseFalcoLogLines(data []byte, maxEvents int) []falcoLogEvent {
	var events []falcoLogEvent
	lines := strings.Split(string(data), "\n")
	count := 0
	for i := len(lines) - 1; i >= 0 && count < maxEvents; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}

		ts := parts[0]
		level := ""
		msg := ""
		if len(parts) >= 3 {
			level = strings.Trim(parts[1], "[]")
			msg = parts[2]
		}

		events = append(events, falcoLogEvent{
			Timestamp: ts,
			Level:     level,
			Message:   msg,
		})
		count++
	}
	return events
}

func parseFalcoJSONLines(data []byte, maxEvents int) []falcoJSONEvent {
	var events []falcoJSONEvent
	lines := strings.Split(string(data), "\n")
	count := 0
	for i := len(lines) - 1; i >= 0 && count < maxEvents; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var evt falcoJSONEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}
		events = append(events, evt)
		count++
	}
	return events
}

func (f *FalcoAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var combined falcoCombinedOutput
	if err := json.Unmarshal(raw, &combined); err != nil {
		installed := strings.Contains(string(raw), "Falco")
		return []*adapter.NormalizedFinding{{
			ID:          "FALCO-STATUS",
			Source:      "falco",
			ToolName:    "Falco",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Title:       "Falco Runtime Security Status",
			Passed:      installed,
			Detail:      fmt.Sprintf("Falco is %s", map[bool]string{true: "installed", false: "not installed"}[installed]),
			Domain:      model.DomainResilience,
			DelegatedTo: "falco",
		}}, nil
	}

	installed := strings.Contains(combined.Version, "Falco")
	findings := []*adapter.NormalizedFinding{{
		ID:          "FALCO-STATUS",
		Source:      "falco",
		ToolName:    "Falco",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "Falco Runtime Security Status",
		Passed:      installed,
		Detail:      fmt.Sprintf("Falco %s", map[bool]string{true: "installed: " + combined.Version, false: "not installed"}[installed]),
		Domain:      model.DomainResilience,
		DelegatedTo: "falco",
	}}

	for i, evt := range combined.JSONEvents {
		sev := adapter.SeverityMedium
		switch strings.ToUpper(evt.Priority) {
		case "EMERGENCY", "ALERT", "CRITICAL":
			sev = adapter.SeverityCritical
		case "ERROR":
			sev = adapter.SeverityHigh
		case "WARNING":
			sev = adapter.SeverityMedium
		case "NOTICE", "INFORMATIONAL":
			sev = adapter.SeverityLow
		case "DEBUG":
			sev = adapter.SeverityInfo
		}

		findings = append(findings, &adapter.NormalizedFinding{
			ID:          fmt.Sprintf("FALCO-EVT-%d", i+1),
			Source:      "falco",
			ToolName:    "Falco",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Severity:    sev,
			Title:       evt.Rule,
			Passed:      false,
			Detail:      evt.Output,
			Domain:      model.DomainResilience,
			DelegatedTo: "falco",
			Metadata: map[string]string{
				"priority": evt.Priority,
				"source":   evt.Source,
				"tags":     evt.Tags,
			},
		})
	}

	for i, evt := range combined.Events {
		sev := adapter.SeverityMedium
		switch strings.ToUpper(evt.Level) {
		case "EMERGENCY", "ALERT", "CRITICAL", "ERROR":
			sev = adapter.SeverityHigh
		case "WARNING":
			sev = adapter.SeverityMedium
		default:
			sev = adapter.SeverityLow
		}

		findings = append(findings, &adapter.NormalizedFinding{
			ID:          fmt.Sprintf("FALCO-LOG-%d", i+1),
			Source:      "falco",
			ToolName:    "Falco",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Severity:    sev,
			Title:       "Falco Log Event",
			Passed:      false,
			Detail:      evt.Message,
			Domain:      model.DomainResilience,
			DelegatedTo: "falco",
			Metadata: map[string]string{
				"level": evt.Level,
			},
		})
	}

	return findings, nil
}

func (f *FalcoAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (f *FalcoAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ===== ClamAV Adapter (SC-008, P1) =====

type ClamAVAdapter struct {
	adapter.BaseAdapter
}

func NewClamAVAdapter() *ClamAVAdapter {
	return &ClamAVAdapter{
		BaseAdapter: adapter.NewBaseAdapter("clamav", "ClamAV", "scanner", "P1", "1.0"),
	}
}

func (c *ClamAVAdapter) Fetch(ctx context.Context, config map[string]string) ([]byte, error) {
	clamavPath := config["adapter_paths.clamav"]
	if clamavPath == "" {
		clamavPath = "clamscan"
	}

	cmd := exec.CommandContext(ctx, clamavPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("clamav fetch failed: %w", err)
	}

	result := clamavCombinedOutput{
		Version: strings.TrimSpace(string(out)),
	}

	scanPath := config["clamav.scan_path"]
	if scanPath == "" {
		scanPath = "/tmp"
	}

	scanEnabled := config["clamav.scan_enabled"]
	if scanEnabled == "true" || scanEnabled == "1" {
		scanCmd := exec.CommandContext(ctx, clamavPath, "--infected", "--no-summary", scanPath)
		scanOut, scanErr := scanCmd.Output()
		if scanErr != nil && len(scanOut) == 0 {
			result.ScanError = scanErr.Error()
		} else {
			result.ScanOutput = strings.TrimSpace(string(scanOut))
			result.Infected = strings.Count(result.ScanOutput, "FOUND")
		}
	}

	combined, err := json.Marshal(result)
	if err != nil {
		return out, nil
	}
	return combined, nil
}

type clamavCombinedOutput struct {
	Version    string `json:"version"`
	ScanOutput string `json:"scan_output,omitempty"`
	Infected   int    `json:"infected"`
	ScanError  string `json:"scan_error,omitempty"`
}

func (c *ClamAVAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()

	var combined clamavCombinedOutput
	if err := json.Unmarshal(raw, &combined); err != nil {
		text := string(raw)
		running := strings.Contains(text, "ClamAV")
		version := ""
		if idx := strings.Index(text, "ClamAV"); idx >= 0 {
			version = strings.TrimSpace(text[idx:])
		}
		return []*adapter.NormalizedFinding{{
			ID:          "CLAMAV-STATUS",
			Source:      "clamav",
			ToolName:    "ClamAV",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Title:       "ClamAV Antivirus Status",
			Passed:      running,
			Detail:      fmt.Sprintf("ClamAV %s", map[bool]string{true: "installed: " + version, false: "not installed"}[running]),
			Domain:      model.DomainResilience,
			DelegatedTo: "clamav",
		}}, nil
	}

	installed := strings.Contains(combined.Version, "ClamAV")
	findings := []*adapter.NormalizedFinding{{
		ID:          "CLAMAV-STATUS",
		Source:      "clamav",
		ToolName:    "ClamAV",
		Timestamp:   now,
		FindingType: adapter.FindingAlert,
		Title:       "ClamAV Antivirus Status",
		Passed:      installed,
		Detail:      fmt.Sprintf("ClamAV %s", map[bool]string{true: "installed: " + combined.Version, false: "not installed"}[installed]),
		Domain:      model.DomainResilience,
		DelegatedTo: "clamav",
	}}

	if combined.ScanOutput != "" {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "CLAMAV-SCAN",
			Source:      "clamav",
			ToolName:    "ClamAV",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Severity:    map[bool]adapter.Severity{true: adapter.SeverityCritical, false: adapter.SeverityInfo}[combined.Infected > 0],
			Title:       "ClamAV Scan Result",
			Passed:      combined.Infected == 0,
			Detail:      fmt.Sprintf("ClamAV scan found %d infected files", combined.Infected),
			Domain:      model.DomainResilience,
			DelegatedTo: "clamav",
		})

		lines := strings.Split(combined.ScanOutput, "\n")
		idx := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "FOUND") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			filePath := strings.TrimSpace(parts[0])
			malwareName := ""
			if len(parts) >= 2 {
				malwareName = strings.TrimSpace(strings.TrimSuffix(parts[1], "FOUND"))
			}

			findings = append(findings, &adapter.NormalizedFinding{
				ID:          fmt.Sprintf("CLAMAV-INFECTED-%d", idx+1),
				Source:      "clamav",
				ToolName:    "ClamAV",
				Timestamp:   now,
				FindingType: adapter.FindingAlert,
				Severity:    adapter.SeverityCritical,
				Title:       fmt.Sprintf("Malware detected: %s", malwareName),
				Passed:      false,
				Detail:      fmt.Sprintf("File %s infected with %s", filePath, malwareName),
				Domain:      model.DomainResilience,
				DelegatedTo: "clamav",
				Metadata: map[string]string{
					"file":     filePath,
					"malware":  malwareName,
				},
			})
			idx++
		}
	}

	if combined.ScanError != "" {
		findings = append(findings, &adapter.NormalizedFinding{
			ID:          "CLAMAV-SCAN-ERROR",
			Source:      "clamav",
			ToolName:    "ClamAV",
			Timestamp:   now,
			FindingType: adapter.FindingAlert,
			Severity:    adapter.SeverityMedium,
			Title:       "ClamAV Scan Error",
			Passed:      false,
			Detail:      combined.ScanError,
			Domain:      model.DomainResilience,
			DelegatedTo: "clamav",
		})
	}

	return findings, nil
}

func (c *ClamAVAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (c *ClamAVAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ensure json import is used
var _ = json.Marshal
