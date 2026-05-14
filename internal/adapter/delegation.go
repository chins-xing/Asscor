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
		{CheckID: "AS-099-T", Domain: "attack_surface", Criteria: []DelegationCriterion{
			{Field: "Resource", Operator: "contains", Value: "kernel"},
		}},
		{CheckID: "TS-001", Domain: "attack_surface", Criteria: nil},
	},
	"nuclei": {
		{CheckID: "AS-099-N", Domain: "attack_surface", Criteria: nil},
	},
	"lynis": {
		{CheckID: "OT-099-L", Domain: "operation_trust", Criteria: nil},
	},
	"openscap": {
		{CheckID: "OT-099-O", Domain: "operation_trust", Criteria: nil},
	},
	"wazuh_agent": {
		{CheckID: "RS-099-W", Domain: "resilience", Criteria: nil},
	},
	"suricata": {
		{CheckID: "RS-099-S", Domain: "resilience", Criteria: nil},
	},
	"falco": {
		{CheckID: "RS-099-F", Domain: "resilience", Criteria: nil},
	},
	"clamav": {
		{CheckID: "RS-099-C", Domain: "resilience", Criteria: nil},
	},
	"osv_scanner": {
		{CheckID: "AS-099-V", Domain: "attack_surface", Criteria: nil},
	},
	"aide": {
		{CheckID: "OT-099-A", Domain: "operation_trust", Criteria: nil},
	},
	"nikto": {
		{CheckID: "AS-099-K", Domain: "attack_surface", Criteria: nil},
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
