//go:build adapter

package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

func TestSuricataEVEParsing(t *testing.T) {
	eveJSON := `{"timestamp":"2024-01-15T10:00:00.000000+0000","event_type":"alert","src_ip":"192.168.1.100","dest_ip":"10.0.0.1","alert":{"action":"allowed","signature":"ET POLICY Suspicious traffic","category":"Potential Corporate Privacy Violation","severity":3}}
{"timestamp":"2024-01-15T10:01:00.000000+0000","event_type":"dns","src_ip":"192.168.1.100","dest_ip":"10.0.0.1"}
{"timestamp":"2024-01-15T10:02:00.000000+0000","event_type":"alert","src_ip":"192.168.1.200","dest_ip":"10.0.0.2","alert":{"action":"blocked","signature":"ET TROJAN Known malware","category":"A Network Trojan was detected","severity":1}}`

	alerts := parseSuricataEVELines([]byte(eveJSON), 100)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}

	if alerts[0].Signature != "ET TROJAN Known malware" {
		t.Errorf("first alert (newest) signature = %s, want ET TROJAN Known malware", alerts[0].Signature)
	}
	if alerts[0].Severity != 1 {
		t.Errorf("first alert severity = %d, want 1", alerts[0].Severity)
	}
	if alerts[1].Signature != "ET POLICY Suspicious traffic" {
		t.Errorf("second alert signature = %s", alerts[1].Signature)
	}
}

func TestSuricataEVEParsingLimit(t *testing.T) {
	var lines []string
	for i := 0; i < 200; i++ {
		line, _ := json.Marshal(map[string]interface{}{
			"timestamp":  "2024-01-15T10:00:00Z",
			"event_type": "alert",
			"src_ip":     "192.168.1.100",
			"dest_ip":    "10.0.0.1",
			"alert": map[string]interface{}{
				"action":    "allowed",
				"signature": "Test Alert",
				"category":  "Test",
				"severity":  3,
			},
		})
		lines = append(lines, string(line))
	}

	data := []byte(strings.Join(lines, "\n"))
	alerts := parseSuricataEVELines(data, 50)

	if len(alerts) != 50 {
		t.Errorf("expected 50 alerts (limited), got %d", len(alerts))
	}
}

func TestSuricataAdapterParse(t *testing.T) {
	combined := suricataCombinedOutput{
		BuildInfo: "Suricata 7.0.0",
		Alerts: []suricataEVEAlert{
			{
				Timestamp: "2024-01-15T10:00:00Z",
				SrcIP:     "192.168.1.100",
				DestIP:    "10.0.0.1",
				Signature: "ET TROJAN Known malware",
				Category:  "A Network Trojan was detected",
				Severity:  1,
				Action:    "blocked",
			},
			{
				Timestamp: "2024-01-15T10:01:00Z",
				SrcIP:     "192.168.1.200",
				DestIP:    "10.0.0.2",
				Signature: "ET POLICY Suspicious traffic",
				Category:  "Potential Corporate Privacy Violation",
				Severity:  3,
				Action:    "allowed",
			},
		},
	}

	raw, _ := json.Marshal(combined)
	s := NewSuricataAdapter()
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (1 status + 2 alerts), got %d", len(findings))
	}

	if findings[0].ID != "SURICATA-STATUS" {
		t.Errorf("first finding ID = %s, want SURICATA-STATUS", findings[0].ID)
	}
	if !findings[0].Passed {
		t.Error("Suricata should be installed")
	}

	if findings[1].Severity != adapter.SeverityCritical {
		t.Errorf("alert severity = %s, want critical for severity 1", findings[1].Severity)
	}
	if findings[2].Severity != adapter.SeverityMedium {
		t.Errorf("alert severity = %s, want medium for severity 3", findings[2].Severity)
	}
}

func TestFalcoLogParsing(t *testing.T) {
	logData := `10:00:00.000000000 Warning Test warning message
10:01:00.000000000 Error Critical system call
10:02:00.000000000 Notice Normal event`

	events := parseFalcoLogLines([]byte(logData), 100)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	if events[0].Level != "Notice" {
		t.Errorf("first event (newest) level = %s, want Notice", events[0].Level)
	}
	if events[1].Level != "Error" {
		t.Errorf("second event level = %s, want Error", events[1].Level)
	}
}

func TestFalcoJSONParsing(t *testing.T) {
	jsonData := `{"time":"2024-01-15T10:00:00Z","rule":"Terminal Shell","priority":"Notice","output":"A shell was spawned in a container","source":"syscall","tags":"T1059"}
{"time":"2024-01-15T10:01:00Z","rule":"Read Sensitive File","priority":"Warning","output":"Sensitive file opened","source":"syscall"}`

	events := parseFalcoJSONLines([]byte(jsonData), 100)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Rule != "Read Sensitive File" {
		t.Errorf("first event (newest) rule = %s, want Read Sensitive File", events[0].Rule)
	}
	if events[0].Priority != "Warning" {
		t.Errorf("first event priority = %s, want Warning", events[0].Priority)
	}
}

func TestFalcoAdapterParse(t *testing.T) {
	combined := falcoCombinedOutput{
		Version: "Falco 0.37.0",
		JSONEvents: []falcoJSONEvent{
			{
				Time:     "2024-01-15T10:00:00Z",
				Rule:     "Terminal Shell in Container",
				Priority: "Notice",
				Output:   "A shell was spawned in a container",
				Source:   "syscall",
				Tags:     "T1059",
			},
			{
				Time:     "2024-01-15T10:01:00Z",
				Rule:     "Read Sensitive File",
				Priority: "Warning",
				Output:   "Sensitive file opened by untrusted process",
				Source:   "syscall",
			},
		},
		Events: []falcoLogEvent{
			{
				Timestamp: "10:02:00",
				Level:     "Error",
				Message:   "Critical system call detected",
			},
		},
	}

	raw, _ := json.Marshal(combined)
	f := NewFalcoAdapter()
	findings, err := f.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (1 status + 2 JSON + 1 log), got %d", len(findings))
	}

	if findings[0].ID != "FALCO-STATUS" {
		t.Errorf("first finding ID = %s, want FALCO-STATUS", findings[0].ID)
	}
	if !findings[0].Passed {
		t.Error("Falco should be installed")
	}

	if findings[1].Title != "Terminal Shell in Container" {
		t.Errorf("JSON event title = %s", findings[1].Title)
	}
	if findings[1].Severity != adapter.SeverityLow {
		t.Errorf("Notice priority severity = %s, want low", findings[1].Severity)
	}

	if findings[3].Title != "Falco Log Event" {
		t.Errorf("log event title = %s", findings[3].Title)
	}
}

func TestClamAVAdapterParse(t *testing.T) {
	combined := clamavCombinedOutput{
		Version:    "ClamAV 1.2.0",
		ScanOutput: "/tmp/malware.exe: Win.Trojan.Agent-123 FOUND\n/tmp/clean.txt: OK\n/tmp/backdoor.py: Win.Backdoor.DarkComet FOUND",
		Infected:   2,
	}

	raw, _ := json.Marshal(combined)
	c := NewClamAVAdapter()
	findings, err := c.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (1 status + 1 scan + 2 infected), got %d", len(findings))
	}

	if findings[0].ID != "CLAMAV-STATUS" {
		t.Errorf("first finding ID = %s, want CLAMAV-STATUS", findings[0].ID)
	}

	if findings[1].ID != "CLAMAV-SCAN" {
		t.Errorf("scan finding ID = %s, want CLAMAV-SCAN", findings[1].ID)
	}
	if findings[1].Passed {
		t.Error("scan should not pass with infected files")
	}

	if findings[2].Title != "Malware detected: Win.Trojan.Agent-123" {
		t.Errorf("infected file title = %s", findings[2].Title)
	}
	if findings[2].Metadata["file"] != "/tmp/malware.exe" {
		t.Errorf("infected file path = %s", findings[2].Metadata["file"])
	}
}

func TestClamAVAdapterParseClean(t *testing.T) {
	combined := clamavCombinedOutput{
		Version:    "ClamAV 1.2.0",
		ScanOutput: "",
		Infected:   0,
	}

	raw, _ := json.Marshal(combined)
	c := NewClamAVAdapter()
	findings, err := c.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (status only), got %d", len(findings))
	}
	if !findings[0].Passed {
		t.Error("ClamAV should be installed")
	}
}

func TestOSVScannerAdapterParse(t *testing.T) {
	result := osvResult{
		Results: []osvPackageResult{
			{
				Package: osvPackage{
					Name:      "openssl",
					Version:   "3.0.2",
					Ecosystem: "Conan",
				},
				Vulnerabilities: []osvVuln{
					{
						ID:      "GHSA-xxxx-yyyy",
						Summary: "OpenSSL buffer overflow",
						Details: "A buffer overflow was found in OpenSSL",
						Aliases: []string{"CVE-2024-OSV01"},
						Severity: []osvSeverity{
							{Type: "CVSS_V3", Score: "CRITICAL"},
						},
					},
				},
			},
		},
	}

	raw, _ := json.Marshal(result)
	o := NewOSVScannerAdapter()
	findings, err := o.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].CVE != "CVE-2024-OSV01" {
		t.Errorf("CVE = %s, want CVE-2024-OSV01", findings[0].CVE)
	}
	if findings[0].Severity != adapter.SeverityCritical {
		t.Errorf("Severity = %s, want critical", findings[0].Severity)
	}
	if findings[0].Resource != "openssl@3.0.2 (Conan)" {
		t.Errorf("Resource = %s", findings[0].Resource)
	}
}

func TestOSVScannerAdapterParseNoVulns(t *testing.T) {
	result := osvResult{
		Results: []osvPackageResult{},
	}

	raw, _ := json.Marshal(result)
	o := NewOSVScannerAdapter()
	findings, err := o.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (clean result), got %d", len(findings))
	}
	if !findings[0].Passed {
		t.Error("should pass with no vulnerabilities")
	}
}

func TestTrivyAdapterParse(t *testing.T) {
	trivyJSON := `{
		"SchemaVersion": 2,
		"ArtifactName": "test-image",
		"Results": [
			{
				"Target": "openssl (debian)",
				"Type": "debian",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2024-TRV01",
						"PkgName": "openssl",
						"InstalledVersion": "3.0.2",
						"FixedVersion": "3.0.3",
						"Title": "OpenSSL buffer overflow",
						"Description": "A buffer overflow in OpenSSL",
						"Severity": "CRITICAL",
						"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-trv01",
						"References": [
							{"Source": "NVD", "URL": "https://nvd.nist.gov/vuln/detail/CVE-2024-TRV01"}
						]
					}
				]
			}
		]
	}`

	trivy := NewTrivyAdapter()
	findings, err := trivy.Parse([]byte(trivyJSON))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestNiktoAdapterProperties(t *testing.T) {
	n := NewNiktoAdapter()
	if n.ID() != "nikto" {
		t.Errorf("ID = %s, want nikto", n.ID())
	}
	if n.Name() != "Nikto" {
		t.Errorf("Name = %s, want Nikto", n.Name())
	}
}

func TestAIDEAdapterProperties(t *testing.T) {
	a := NewAIDEAdapter()
	if a.ID() != "aide" {
		t.Errorf("ID = %s, want aide", a.ID())
	}
	if a.Name() != "AIDE" {
		t.Errorf("Name = %s, want AIDE", a.Name())
	}
}

func TestAdapterDomainMapping(t *testing.T) {
	adapters := []struct {
		name     string
		adapter  adapter.Adapter
		expected string
	}{
		{"Trivy", NewTrivyAdapter(), model.DomainAttackSurface},
		{"Nuclei", NewNucleiAdapter(), model.DomainAttackSurface},
		{"Lynis", NewLynisAdapter(), model.DomainOperationTrust},
		{"OpenSCAP", NewOpenSCAPAdapter(), model.DomainOperationTrust},
		{"Suricata", NewSuricataAdapter(), model.DomainResilience},
		{"Falco", NewFalcoAdapter(), model.DomainResilience},
		{"ClamAV", NewClamAVAdapter(), model.DomainResilience},
		{"OSVScanner", NewOSVScannerAdapter(), model.DomainAttackSurface},
		{"AIDE", NewAIDEAdapter(), model.DomainOperationTrust},
		{"Nikto", NewNiktoAdapter(), model.DomainAttackSurface},
	}

	for _, tt := range adapters {
		findings, err := tt.adapter.Parse([]byte(`{}`))
		if err != nil {
			t.Logf("%s Parse with empty input: %v (acceptable)", tt.name, err)
			continue
		}
		for _, f := range findings {
			if f.Domain != tt.expected {
				t.Errorf("%s: Domain = %s, want %s", tt.name, f.Domain, tt.expected)
			}
		}
	}
}

func TestSuricataAdapterParseFallback(t *testing.T) {
	s := NewSuricataAdapter()
	findings, err := s.Parse([]byte(`Suricata 7.0.0`))
	if err != nil {
		t.Fatalf("Parse fallback error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 fallback finding, got %d", len(findings))
	}
	if findings[0].ID != "SURICATA-STATUS" {
		t.Errorf("fallback ID = %s, want SURICATA-STATUS", findings[0].ID)
	}
}

func TestFalcoAdapterParseFallback(t *testing.T) {
	f := NewFalcoAdapter()
	findings, err := f.Parse([]byte(`Falco 0.37.0`))
	if err != nil {
		t.Fatalf("Parse fallback error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 fallback finding, got %d", len(findings))
	}
	if findings[0].ID != "FALCO-STATUS" {
		t.Errorf("fallback ID = %s, want FALCO-STATUS", findings[0].ID)
	}
}

func TestClamAVAdapterParseFallback(t *testing.T) {
	c := NewClamAVAdapter()
	findings, err := c.Parse([]byte(`ClamAV 1.2.0`))
	if err != nil {
		t.Fatalf("Parse fallback error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 fallback finding, got %d", len(findings))
	}
	if findings[0].ID != "CLAMAV-STATUS" {
		t.Errorf("fallback ID = %s, want CLAMAV-STATUS", findings[0].ID)
	}
}

func TestFalcoLogParsingEmptyLines(t *testing.T) {
	logData := `

10:01:00.000000000 Warning Valid event


`
	events := parseFalcoLogLines([]byte(logData), 100)
	if len(events) != 1 {
		t.Errorf("expected 1 event (skipping empty lines), got %d", len(events))
	}
}

func TestFalcoLogParsingLimit(t *testing.T) {
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "10:00:00.000000000 Warning Test message")
	}

	data := []byte(strings.Join(lines, "\n"))
	events := parseFalcoLogLines(data, 50)

	if len(events) != 50 {
		t.Errorf("expected 50 events (limited), got %d", len(events))
	}
}

func TestClamAVParseScanError(t *testing.T) {
	combined := clamavCombinedOutput{
		Version:   "ClamAV 1.2.0",
		ScanError: "permission denied: /root/secret",
	}

	raw, _ := json.Marshal(combined)
	c := NewClamAVAdapter()
	findings, err := c.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	hasError := false
	for _, f := range findings {
		if f.ID == "CLAMAV-SCAN-ERROR" {
			hasError = true
			if f.Passed {
				t.Error("scan error should not pass")
			}
		}
	}
	if !hasError {
		t.Error("expected CLAMAV-SCAN-ERROR finding")
	}
}

func TestOSVScannerParseFallback(t *testing.T) {
	o := NewOSVScannerAdapter()
	findings, err := o.Parse([]byte(`some non-json output`))
	if err != nil {
		t.Fatalf("Parse fallback error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 fallback finding, got %d", len(findings))
	}
}

func TestSuricataSeverityMapping(t *testing.T) {
	tests := []struct {
		severity int
		expected adapter.Severity
	}{
		{1, adapter.SeverityCritical},
		{2, adapter.SeverityHigh},
		{3, adapter.SeverityMedium},
		{4, adapter.SeverityLow},
	}

	for _, tt := range tests {
		combined := suricataCombinedOutput{
			BuildInfo: "Suricata 7.0",
			Alerts: []suricataEVEAlert{
				{
					Signature: "Test",
					Category:  "Test",
					Severity:  tt.severity,
				},
			},
		}

		raw, _ := json.Marshal(combined)
		s := NewSuricataAdapter()
		findings, _ := s.Parse(raw)

		alertFinding := findings[1]
		if alertFinding.Severity != tt.expected {
			t.Errorf("severity %d -> %s, want %s", tt.severity, alertFinding.Severity, tt.expected)
		}
	}
}

func TestFalcoPriorityMapping(t *testing.T) {
	tests := []struct {
		priority string
		expected adapter.Severity
	}{
		{"EMERGENCY", adapter.SeverityCritical},
		{"ALERT", adapter.SeverityCritical},
		{"CRITICAL", adapter.SeverityCritical},
		{"ERROR", adapter.SeverityHigh},
		{"WARNING", adapter.SeverityMedium},
		{"NOTICE", adapter.SeverityLow},
		{"INFORMATIONAL", adapter.SeverityLow},
		{"DEBUG", adapter.SeverityInfo},
	}

	for _, tt := range tests {
		combined := falcoCombinedOutput{
			Version: "Falco 0.37",
			JSONEvents: []falcoJSONEvent{
				{
					Rule:     "Test Rule",
					Priority: tt.priority,
					Output:   "Test output",
				},
			},
		}

		raw, _ := json.Marshal(combined)
		f := NewFalcoAdapter()
		findings, _ := f.Parse(raw)

		eventFinding := findings[1]
		if eventFinding.Severity != tt.expected {
			t.Errorf("priority %s -> %s, want %s", tt.priority, eventFinding.Severity, tt.expected)
		}
	}
}
