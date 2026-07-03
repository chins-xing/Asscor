package adapter

import (
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"high", SeverityHigh},
		{"MEDIUM", SeverityMedium},
		{"medium", SeverityMedium},
		{"LOW", SeverityLow},
		{"low", SeverityLow},
		{"INFO", SeverityInfo},
		{"info", SeverityInfo},
		{"unknown", SeverityNone},
		{"", SeverityNone},
	}

	for _, tt := range tests {
		got := ParseSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizedFindingToCheckResult(t *testing.T) {
	tests := []struct {
		name     string
		finding  NormalizedFinding
		expectedDelta float64
	}{
		{
			name:     "passed finding has zero delta",
			finding:  NormalizedFinding{Passed: true, Severity: SeverityCritical},
			expectedDelta: 0,
		},
		{
			name:     "critical failure",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityCritical},
			expectedDelta: -20,
		},
		{
			name:     "high failure",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityHigh},
			expectedDelta: -15,
		},
		{
			name:     "medium failure",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityMedium},
			expectedDelta: -10,
		},
		{
			name:     "low failure",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityLow},
			expectedDelta: -5,
		},
		{
			name:     "info failure",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityInfo},
			expectedDelta: -2,
		},
		{
			name:     "none severity",
			finding:  NormalizedFinding{Passed: false, Severity: SeverityNone},
			expectedDelta: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.finding.ToCheckResult()
			if result.Delta != tt.expectedDelta {
				t.Errorf("Delta = %.0f, want %.0f", result.Delta, tt.expectedDelta)
			}
		})
	}
}

func TestBaseAdapterIsEnabled(t *testing.T) {
	adapter := NewBaseAdapter("test", "Test Adapter", "scanner", "P1", "1.0")

	tests := []struct {
		config   map[string]string
		expected bool
	}{
		{map[string]string{"test": "on"}, true},
		{map[string]string{"test": "true"}, true},
		{map[string]string{"test": "1"}, true},
		{map[string]string{"test": "yes"}, true},
		{map[string]string{"test": "off"}, false},
		{map[string]string{"test": "false"}, false},
		{map[string]string{"other": "on"}, false},
		{map[string]string{}, false},
	}

	for _, tt := range tests {
		got := adapter.IsEnabled(tt.config)
		if got != tt.expected {
			t.Errorf("IsEnabled(%v) = %v, want %v", tt.config, got, tt.expected)
		}
	}
}

func TestBaseAdapterProperties(t *testing.T) {
	adapter := NewBaseAdapter("trivy", "Trivy", "scanner", "P0", "1.0")

	if adapter.ID() != "trivy" {
		t.Errorf("ID() = %s, want trivy", adapter.ID())
	}
	if adapter.Name() != "Trivy" {
		t.Errorf("Name() = %s, want Trivy", adapter.Name())
	}
	if adapter.Category() != "scanner" {
		t.Errorf("Category() = %s, want scanner", adapter.Category())
	}
	if adapter.Priority() != "P0" {
		t.Errorf("Priority() = %s, want P0", adapter.Priority())
	}
	if adapter.Version() != "1.0" {
		t.Errorf("Version() = %s, want 1.0", adapter.Version())
	}
}

func TestDefaultValidate(t *testing.T) {
	tests := []struct {
		name        string
		findings    []*NormalizedFinding
		expectValid int
		expectErrs  int
	}{
		{
			name: "all valid",
			findings: []*NormalizedFinding{
				{ID: "1", Title: "Test", Domain: "attack_surface"},
				{ID: "2", Title: "Test2", Domain: "resilience"},
			},
			expectValid: 2,
			expectErrs:  0,
		},
		{
			name: "nil finding skipped",
			findings: []*NormalizedFinding{
				{ID: "1", Title: "Test", Domain: "attack_surface"},
				nil,
			},
			expectValid: 1,
			expectErrs:  0,
		},
		{
			name: "empty title rejected",
			findings: []*NormalizedFinding{
				{ID: "1", Title: "", Domain: "attack_surface"},
			},
			expectValid: 0,
			expectErrs:  1,
		},
		{
			name: "empty domain rejected",
			findings: []*NormalizedFinding{
				{ID: "1", Title: "Test", Domain: ""},
			},
			expectValid: 0,
			expectErrs:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, errs := DefaultValidate(tt.findings)
			if len(valid) != tt.expectValid {
				t.Errorf("valid count = %d, want %d", len(valid), tt.expectValid)
			}
			if len(errs) != tt.expectErrs {
				t.Errorf("error count = %d, want %d", len(errs), tt.expectErrs)
			}
		})
	}
}

func TestApplyDelegation(t *testing.T) {
	tests := []struct {
		name         string
		finding      *NormalizedFinding
		adapterID    string
		expectCheckID string
		expectDomain  string
	}{
		{
			name:         "trivy delegation with kernel resource",
			finding:      &NormalizedFinding{Title: "CVE in kernel", Resource: "kernel-package"},
			adapterID:    "trivy",
			expectCheckID: "KS-001",
			expectDomain:  "kernel_security",
		},
		{
			name:         "trivy delegation fallback",
			finding:      &NormalizedFinding{Title: "CVE in nginx"},
			adapterID:    "trivy",
			expectCheckID: "AS-005",
			expectDomain:  "attack_surface",
		},
		{
			name:         "nuclei delegation",
			finding:      &NormalizedFinding{Title: "Web vuln"},
			adapterID:    "nuclei",
			expectCheckID: "AS-005",
			expectDomain:  "attack_surface",
		},
		{
			name:         "lynis delegation",
			finding:      &NormalizedFinding{Title: "Compliance issue"},
			adapterID:    "lynis",
			expectCheckID: "OT-099",
			expectDomain:  "operation_trust",
		},
		{
			name:         "already has domain and checkID",
			finding:      &NormalizedFinding{Title: "Test", Domain: "resilience", CheckID: "RS-001"},
			adapterID:    "trivy",
			expectCheckID: "RS-001",
			expectDomain:  "resilience",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ApplyDelegation(tt.finding, tt.adapterID)
			if tt.finding.CheckID != tt.expectCheckID {
				t.Errorf("CheckID = %s, want %s", tt.finding.CheckID, tt.expectCheckID)
			}
			if tt.finding.Domain != tt.expectDomain {
				t.Errorf("Domain = %s, want %s", tt.finding.Domain, tt.expectDomain)
			}
		})
	}
}

func TestDelegationRulesExist(t *testing.T) {
	expectedAdapters := []string{
		"trivy", "nuclei", "lynis", "openscap", "wazuh_agent",
		"suricata", "falco", "clamav", "osv_scanner", "aide", "nikto",
	}

	for _, id := range expectedAdapters {
		rules := GetDelegationRules(id)
		if len(rules) == 0 {
			t.Errorf("no delegation rules for adapter %s", id)
		}
	}
}

func TestMatchCriteria(t *testing.T) {
	finding := &NormalizedFinding{
		Resource:    "kernel-package",
		Title:       "Kernel vulnerability",
		Description: "A flaw in the kernel",
	}

	tests := []struct {
		name     string
		criteria []DelegationCriterion
		expected bool
	}{
		{
			name:     "no criteria matches",
			criteria: nil,
			expected: true,
		},
		{
			name: "contains match",
			criteria: []DelegationCriterion{
				{Field: "Resource", Operator: "contains", Value: "kernel"},
			},
			expected: true,
		},
		{
			name: "contains no match",
			criteria: []DelegationCriterion{
				{Field: "Resource", Operator: "contains", Value: "nginx"},
			},
			expected: false,
		},
		{
			name: "eq match",
			criteria: []DelegationCriterion{
				{Field: "Title", Operator: "eq", Value: "Kernel vulnerability"},
			},
			expected: true,
		},
		{
			name: "prefix match",
			criteria: []DelegationCriterion{
				{Field: "Resource", Operator: "prefix", Value: "kernel"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchCriteria(finding, tt.criteria)
			if got != tt.expected {
				t.Errorf("matchCriteria = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDeriveDomain(t *testing.T) {
	tests := []struct {
		findingType FindingType
		expected    string
	}{
		{FindingVulnerability, "attack_surface"},
		{FindingMisconfig, "operation_trust"},
		{FindingCompliance, "operation_trust"},
		{FindingAlert, "resilience"},
		{FindingConfigState, "operation_trust"},
		{FindingAsset, "attack_surface"},
	}

	for _, tt := range tests {
		f := &NormalizedFinding{FindingType: tt.findingType}
		got := deriveDomain(f)
		if got != tt.expected {
			t.Errorf("deriveDomain(%s) = %s, want %s", tt.findingType, got, tt.expected)
		}
	}
}

func TestDeriveCheckID(t *testing.T) {
	tests := []struct {
		adapterID string
		finding   *NormalizedFinding
	}{
		{"trivy", &NormalizedFinding{}},
		{"verylongadapterid", &NormalizedFinding{}},
		{"ab", &NormalizedFinding{}},
	}

	for _, tt := range tests {
		got := deriveCheckID(tt.adapterID, tt.finding)
		if got == "" {
			t.Errorf("deriveCheckID(%s) returned empty", tt.adapterID)
		}
		if !endsWith(got, "-AUTO") {
			t.Errorf("deriveCheckID(%s) = %s, should end with -AUTO", tt.adapterID, got)
		}
	}
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
