package adapter

import "strings"

type DelegationRule struct {
	CheckID  string
	Domain   string
	Criteria []DelegationCriterion
}

type DelegationCriterion struct {
	Field    string
	Operator string
	Value    string
}

var delegationRules = map[string][]DelegationRule{
	"trivy": {
		{CheckID: "KS-001", Domain: "kernel_security", Criteria: []DelegationCriterion{
			{Field: "Resource", Operator: "contains", Value: "kernel"},
		}},
		{CheckID: "AS-005", Domain: "attack_surface", Criteria: nil},
	},
	"nuclei": {
		{CheckID: "AS-006", Domain: "attack_surface", Criteria: []DelegationCriterion{
			{Field: "Severity", Operator: "eq", Value: "critical"},
		}},
		{CheckID: "AS-005", Domain: "attack_surface", Criteria: nil},
	},
	"lynis": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "permission"},
		}},
		{CheckID: "KS-001", Domain: "kernel_security", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "kernel"},
		}},
		{CheckID: "OT-099", Domain: "operation_trust", Criteria: nil},
	},
	"openscap": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: nil},
	},
	"wazuh_agent": {
		{CheckID: "RS-006", Domain: "resilience", Criteria: nil},
	},
	"suricata": {
		{CheckID: "RS-006", Domain: "resilience", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "alert"},
		}},
		{CheckID: "AS-006", Domain: "attack_surface", Criteria: nil},
	},
	"falco": {
		{CheckID: "RS-006", Domain: "resilience", Criteria: nil},
	},
	"clamav": {
		{CheckID: "RS-008", Domain: "resilience", Criteria: nil},
	},
	"osv_scanner": {
		{CheckID: "KS-001", Domain: "kernel_security", Criteria: []DelegationCriterion{
			{Field: "CVE", Operator: "prefix", Value: "CVE"},
		}},
		{CheckID: "RS-001", Domain: "resilience", Criteria: nil},
	},
	"aide": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: nil},
	},
	"nikto": {
		{CheckID: "AS-006", Domain: "attack_surface", Criteria: nil},
	},
	"ansible": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: nil},
	},
	"netbox": {
		{CheckID: "BC-005", Domain: "business_continuity", Criteria: nil},
	},
	"snipe_it": {
		{CheckID: "BC-006", Domain: "business_continuity", Criteria: nil},
	},
	"freeipa": {
		{CheckID: "OT-004", Domain: "operation_trust", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "Disabled"},
		}},
		{CheckID: "OT-099", Domain: "operation_trust", Criteria: nil},
	},
	"keycloak": {
		{CheckID: "OT-004", Domain: "operation_trust", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "Realms"},
		}},
		{CheckID: "OT-099", Domain: "operation_trust", Criteria: nil},
	},
	"wazuh_siem": {
		{CheckID: "RS-007", Domain: "resilience", Criteria: nil},
	},
	"rundeck": {
		{CheckID: "OT-009", Domain: "operation_trust", Criteria: []DelegationCriterion{
			{Field: "Title", Operator: "contains", Value: "executor"},
		}},
		{CheckID: "OT-099", Domain: "operation_trust", Criteria: nil},
	},
	"jira": {
		{CheckID: "OT-009", Domain: "operation_trust", Criteria: nil},
	},
	"terraform": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: nil},
	},
	"opentofu": {
		{CheckID: "OT-001", Domain: "operation_trust", Criteria: nil},
	},
}

func GetDelegationRules(adapterID string) []DelegationRule {
	return delegationRules[adapterID]
}

func ApplyDelegation(finding *NormalizedFinding, adapterID string) {
	if finding.Domain != "" && finding.CheckID != "" {
		return
	}

	rules := GetDelegationRules(adapterID)
	for _, rule := range rules {
		if !matchCriteria(finding, rule.Criteria) {
			continue
		}
		if finding.CheckID == "" {
			finding.CheckID = rule.CheckID
		}
		if finding.Domain == "" {
			finding.Domain = rule.Domain
		}
		finding.DelegatedTo = adapterID
		return
	}

	if finding.CheckID == "" {
		finding.CheckID = deriveCheckID(adapterID, finding)
	}
	if finding.Domain == "" {
		finding.Domain = deriveDomain(finding)
	}
}

func matchCriteria(f *NormalizedFinding, criteria []DelegationCriterion) bool {
	if len(criteria) == 0 {
		return true
	}
	for _, c := range criteria {
		value := getFieldValue(f, c.Field)
		if !matchCondition(value, c.Operator, c.Value) {
			return false
		}
	}
	return true
}

func getFieldValue(f *NormalizedFinding, field string) string {
	switch field {
	case "Resource":
		return f.Resource
	case "Title":
		return f.Title
	case "Description":
		return f.Description
	case "CVE":
		return f.CVE
	case "Severity":
		return string(f.Severity)
	default:
		return ""
	}
}

func matchCondition(value, operator, expected string) bool {
	switch operator {
	case "eq":
		return strings.EqualFold(value, expected)
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(expected))
	case "prefix":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(expected))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(expected))
	default:
		return true
	}
}

func deriveCheckID(adapterID string, f *NormalizedFinding) string {
	prefix := strings.ToUpper(adapterID)
	if len(prefix) > 6 {
		prefix = prefix[:6]
	}
	return prefix + "-AUTO"
}

func deriveDomain(f *NormalizedFinding) string {
	switch f.FindingType {
	case FindingVulnerability:
		return "attack_surface"
	case FindingMisconfig:
		return "operation_trust"
	case FindingCompliance:
		return "operation_trust"
	case FindingAlert:
		return "resilience"
	case FindingConfigState:
		return "operation_trust"
	default:
		return "attack_surface"
	}
}
