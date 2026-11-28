package federation

import (
	"fmt"
	"net"
	"strings"
)

// ValidateNodeReport rejects structurally invalid facts before they enter the
// master collector (audit LayeredGraph 3.2). It is intentionally conservative:
// malformed facts are rejected rather than silently merged.
func ValidateNodeReport(r NodeReport) error {
	if strings.TrimSpace(r.NodeID) == "" {
		return fmt.Errorf("node_id is required")
	}
	if len(r.HostFacts) > MaxHostFacts {
		return fmt.Errorf("too many host facts: %d > %d", len(r.HostFacts), MaxHostFacts)
	}
	if len(r.PolicyFacts) > MaxPolicyFacts {
		return fmt.Errorf("too many policy facts: %d > %d", len(r.PolicyFacts), MaxPolicyFacts)
	}
	for i, h := range r.HostFacts {
		if strings.TrimSpace(h.ID) == "" {
			return fmt.Errorf("host_facts[%d].id is required", i)
		}
		for _, ip := range h.IPs {
			if net.ParseIP(strings.TrimSpace(ip)) == nil {
				return fmt.Errorf("host %q: invalid ip %q", h.ID, ip)
			}
		}
		if h.Confidence < 0 || h.Confidence > 1 {
			return fmt.Errorf("host %q: confidence %v outside [0,1]", h.ID, h.Confidence)
		}
		for _, sn := range h.Subnets {
			if err := validateCIDR(sn); err != nil {
				return fmt.Errorf("host %q: %w", h.ID, err)
			}
		}
		for _, p := range h.Inbound {
			if err := validatePolicyFact(p); err != nil {
				return fmt.Errorf("host %q inbound: %w", h.ID, err)
			}
		}
		for _, p := range h.Outbound {
			if err := validatePolicyFact(p); err != nil {
				return fmt.Errorf("host %q outbound: %w", h.ID, err)
			}
		}
	}
	for i, p := range r.PolicyFacts {
		if err := validatePolicyFact(p); err != nil {
			return fmt.Errorf("policy_facts[%d]: %w", i, err)
		}
	}
	return nil
}

func validateCIDR(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty CIDR")
	}
	if ip := net.ParseIP(strings.TrimSuffix(s, "/32")); ip != nil && !strings.Contains(s, "/") {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err != nil {
		return fmt.Errorf("invalid CIDR %q", s)
	}
	return nil
}

func validatePolicyFact(p PolicyFact) error {
	if p.From != "" {
		if err := validateCIDR(p.From); err != nil {
			return fmt.Errorf("from: %w", err)
		}
	}
	if p.To != "" {
		if err := validateCIDR(p.To); err != nil {
			return fmt.Errorf("to: %w", err)
		}
	}
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if proto != "" && proto != "tcp" && proto != "udp" && proto != "icmp" {
		return fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
	if p.SrcPort < 0 || p.SrcPort > 65535 || p.DstPort < 0 || p.DstPort > 65535 {
		return fmt.Errorf("port out of range: %d/%d", p.SrcPort, p.DstPort)
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		return fmt.Errorf("confidence %v outside [0,1]", p.Confidence)
	}
	return nil
}
