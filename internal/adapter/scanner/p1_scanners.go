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

	if eveData, err := os.ReadFile(eveFile); err == nil && len(eveData) > 0 {
		out = append(out, '\n')
		out = append(out, eveData...)
	}

	return out, nil
}

func (s *SuricataAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
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
	return out, nil
}

func (f *FalcoAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
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
	return out, nil
}

func (c *ClamAVAdapter) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
	now := time.Now()
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

func (c *ClamAVAdapter) Map(findings []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
	return adapter.DefaultMap(findings)
}

func (c *ClamAVAdapter) Validate(findings []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
	return adapter.DefaultValidate(findings)
}

// ensure json import is used
var _ = json.Marshal
