package federation

import (
	"testing"

	"github.com/chins-xing/asscor/internal/topology"
)

func conflictReports() []NodeReport {
	hosts := []HostFact{
		{ID: "A", Subnets: []string{"10.0.1.0/24"}},
		{ID: "GW", Subnets: []string{"10.0.1.0/24", "10.0.2.0/24"}, Forwards: true},
		{ID: "B", Subnets: []string{"10.0.2.0/24"}},
	}
	return []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: hosts,
			PolicyFacts: []PolicyFact{{From: "10.0.1.0/24", To: "10.0.2.0/24", Allow: true}}},
		{NodeID: "nk2", PolicyKnown: true, HostFacts: hosts,
			PolicyFacts: []PolicyFact{{From: "10.0.1.0/24", To: "10.0.2.0/24", Allow: false}}},
	}
}

func TestMergePolicyConflictIsExposed(t *testing.T) {
	g := BuildMergedGraphWithLocal(conflictReports(), nil, nil, false)
	conflicts := g.PolicyConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want 1", conflicts)
	}
	c := conflicts[0]
	if c.From != "10.0.1.0/24" || c.To != "10.0.2.0/24" {
		t.Fatalf("conflict pair = %s -> %s", c.From, c.To)
	}
	if len(c.AllowSources) != 1 || c.AllowSources[0] != "nk1" {
		t.Fatalf("allow sources = %v, want [nk1]", c.AllowSources)
	}
	if len(c.DenySources) != 1 || c.DenySources[0] != "nk2" {
		t.Fatalf("deny sources = %v, want [nk2]", c.DenySources)
	}
}

func TestMergePolicyConflictDoesNotSilentlyPickSide(t *testing.T) {
	g := BuildMergedGraphWithLocal(conflictReports(), nil, nil, false)
	res := CheckMerged(g, "A", "B", 5)
	if res.Verdict != string(topology.VerdictProbable) {
		t.Fatalf("conflicting policy verdict = %s, want probable (best=%+v)", res.Verdict, res.Best)
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("check conflicts = %+v, want 1", res.Conflicts)
	}
}

func TestMergeProvenanceIsPreserved(t *testing.T) {
	exp := MergedTopology(conflictReports())
	if len(exp.Hosts) == 0 || len(exp.Policies) == 0 {
		t.Fatalf("empty export: %+v", exp)
	}
	foundHost := false
	for _, h := range exp.Hosts {
		if h.ID == "A" {
			foundHost = true
			if len(h.SourceNodes) != 2 {
				t.Fatalf("host A sources = %v, want nk1+nk2", h.SourceNodes)
			}
		}
	}
	if !foundHost {
		t.Fatal("host A missing from export")
	}
	foundPolicy := false
	for _, p := range exp.Policies {
		if p.From == "10.0.1.0/24" && p.To == "10.0.2.0/24" {
			foundPolicy = true
			if len(p.SourceNodes) == 0 {
				t.Fatal("policy source nodes empty")
			}
		}
	}
	if !foundPolicy {
		t.Fatal("conflict policy missing from export")
	}
}

func TestMergePartialPolicyUnknown(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "A", Subnets: []string{"10.0.1.0/24"}},
			{ID: "GW", Subnets: []string{"10.0.1.0/24", "10.0.2.0/24"}, Forwards: true},
			{ID: "B", Subnets: []string{"10.0.2.0/24"}},
		}},
		{NodeID: "nk2", PolicyKnown: false, HostFacts: []HostFact{
			{ID: "C", Subnets: []string{"10.0.2.0/24"}},
		}},
	}
	g := BuildMergedGraphWithLocal(reports, nil, nil, false)
	unknown := g.PolicyUnknownSubnets()
	if len(unknown) != 1 || unknown[0] != "10.0.2.0/24" {
		t.Fatalf("unknown subnets = %v, want [10.0.2.0/24]", unknown)
	}
	if res := CheckMerged(g, "A", "B", 3); res.Verdict != string(topology.VerdictProbable) {
		t.Fatalf("partial unknown verdict = %s, want probable", res.Verdict)
	}
}

func TestHostLevelPolicyConflict(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "hk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "HX", Subnets: []string{"10.9.9.0/24"}},
			{ID: "HA", Subnets: []string{"10.9.9.0/24"}, Inbound: []PolicyFact{
				{From: "10.9.9.0/24", To: "10.9.9.0/24", Allow: true},
			}},
		}},
		{NodeID: "hk2", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "HX", Subnets: []string{"10.9.9.0/24"}},
			{ID: "HA", Subnets: []string{"10.9.9.0/24"}, Inbound: []PolicyFact{
				{From: "10.9.9.0/24", To: "10.9.9.0/24", Allow: false},
			}},
		}},
	}
	g := BuildMergedGraphWithLocal(reports, nil, nil, false)
	found := false
	for _, c := range g.PolicyConflicts() {
		if c.Host == "HA" && c.Direction == "inbound" {
			found = true
		}
	}
	if !found {
		t.Fatalf("host conflict missing: %+v", g.PolicyConflicts())
	}
	// A path whose endpoint carries a host-level conflict must not be silently
	// decided by first-match.
	if res := CheckMerged(g, "HX", "HA", 3); res.Verdict != string(topology.VerdictProbable) {
		t.Fatalf("host conflict path verdict = %s, want probable (best=%+v)", res.Verdict, res.Best)
	}
}

func TestDifferentPortsDoNotConflict(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "pk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "PA", Subnets: []string{"10.8.1.0/24"}},
			{ID: "PB", Subnets: []string{"10.8.1.0/24"}, Inbound: []PolicyFact{
				{From: "10.8.1.0/24", To: "10.8.1.0/24", Allow: true, Protocol: "tcp", DstPort: 80},
			}},
		}},
		{NodeID: "pk2", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "PA", Subnets: []string{"10.8.1.0/24"}},
			{ID: "PB", Subnets: []string{"10.8.1.0/24"}, Inbound: []PolicyFact{
				{From: "10.8.1.0/24", To: "10.8.1.0/24", Allow: false, Protocol: "tcp", DstPort: 22},
			}},
		}},
	}
	g := BuildMergedGraphWithLocal(reports, nil, nil, false)
	for _, c := range g.PolicyConflicts() {
		if c.Host == "PB" && c.Direction == "inbound" {
			t.Fatalf("different ports must not be a conflict: %+v", c)
		}
	}
}
