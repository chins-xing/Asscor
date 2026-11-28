package federation

import "testing"

func validReport() NodeReport {
	return NodeReport{
		NodeID: "v1",
		HostFacts: []HostFact{{
			ID: "h1", IPs: []string{"10.0.0.1"}, Subnets: []string{"10.0.0.0/24"},
			Inbound: []PolicyFact{{From: "10.0.0.0/24", To: "10.0.0.0/24", Allow: true, Protocol: "tcp", DstPort: 443}},
		}},
		PolicyFacts: []PolicyFact{{From: "10.0.0.0/24", To: "10.1.0.0/24", Allow: false}},
	}
}

func TestValidateNodeReportValid(t *testing.T) {
	if err := ValidateNodeReport(validReport()); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
}

func TestValidateNodeReportRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*NodeReport)
	}{
		{"empty node", func(r *NodeReport) { r.NodeID = "" }},
		{"bad ip", func(r *NodeReport) { r.HostFacts[0].IPs = []string{"999.1.1.1"} }},
		{"bad cidr", func(r *NodeReport) { r.HostFacts[0].Subnets = []string{"10.0.0.0/99"} }},
		{"bad port", func(r *NodeReport) { r.HostFacts[0].Inbound[0].DstPort = 70000 }},
		{"bad proto", func(r *NodeReport) { r.HostFacts[0].Inbound[0].Protocol = "sctp" }},
		{"empty host id", func(r *NodeReport) { r.HostFacts[0].ID = "" }},
		{"too many hosts", func(r *NodeReport) {
			r.HostFacts = make([]HostFact, MaxHostFacts+1)
			for i := range r.HostFacts {
				r.HostFacts[i] = HostFact{ID: "h"}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validReport()
			tc.mut(&r)
			if err := ValidateNodeReport(r); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
