package topology

import "testing"

func depthChain() *LayeredGraph {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.1.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.1.0/24", "10.0.2.0/24"}, Forwards: true},
		{HostID: "C", Subnets: []string{"10.0.2.0/24", "10.0.3.0/24"}, Forwards: true},
		{HostID: "D", Subnets: []string{"10.0.3.0/24"}},
	}
	return BuildLayeredGraph(hosts, nil, true, true)
}

func TestDepthExhaustionIsProbable(t *testing.T) {
	g := depthChain()
	got := g.HostReachable("A", "D", 2)
	if Summary(got) != VerdictProbable {
		t.Fatalf("depth exhaustion verdict = %s, want probable (paths=%+v)", Summary(got), got)
	}
	found := false
	for _, pv := range got {
		for _, u := range pv.Unknowns {
			if u == "max_hops_exhausted" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("missing max_hops_exhausted unknown: %+v", got)
	}
}

func TestDepthSufficientReachable(t *testing.T) {
	g := depthChain()
	if got := Summary(g.HostReachable("A", "D", 3)); got != VerdictReachable {
		t.Fatalf("sufficient depth verdict = %s, want reachable", got)
	}
}

func TestNoPathStillBlocked(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.1.0/24"}},
		{HostID: "D", Subnets: []string{"10.0.9.0/24"}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	got := g.HostReachable("A", "D", 2)
	if Summary(got) != VerdictBlocked {
		t.Fatalf("no-path verdict = %s, want blocked", Summary(got))
	}
	for _, pv := range got {
		for _, u := range pv.Unknowns {
			if u == "max_hops_exhausted" {
				t.Fatalf("genuine block must not be marked exhausted: %+v", got)
			}
		}
	}
}

func TestPartialPolicyUnknownBySubnet(t *testing.T) {
	g := depthChain()
	// chain: A(s1)-B(s1,s2)-C(s2,s3)-D(s3)
	if got := Summary(g.HostReachable("A", "D", 3)); got != VerdictReachable {
		t.Fatalf("known policy verdict = %s, want reachable", got)
	}
	g2 := BuildLayeredGraphWithPolicyScope([]HostFacts{
		{HostID: "A", Subnets: []string{"10.0.1.0/24"}},
		{HostID: "GW", Subnets: []string{"10.0.1.0/24", "10.0.2.0/24"}, Forwards: true},
		{HostID: "B", Subnets: []string{"10.0.2.0/24"}},
	}, nil, true, true, []string{"10.0.2.0/24"})
	if got := Summary(g2.HostReachable("A", "B", 3)); got != VerdictProbable {
		t.Fatalf("partial unknown verdict = %s, want probable", got)
	}
	if got := g2.PolicyUnknownSubnets(); len(got) != 1 || got[0] != "10.0.2.0/24" {
		t.Fatalf("unknown subnets = %v", got)
	}
}
