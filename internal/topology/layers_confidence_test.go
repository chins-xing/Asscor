package topology

import "testing"

func TestLowConfidenceHostDowngrades(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.14.0.0/24"}, Confidence: 0.9},
		{HostID: "B", Subnets: []string{"10.14.0.0/24"}, Confidence: 0.3},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	got := g.HostReachable("A", "B", 2)
	if Summary(got) != VerdictProbable || !hasUnknown(got, "low_confidence") {
		t.Fatalf("low-confidence host = %s %+v, want probable/low_confidence", Summary(got), got)
	}
	g.SetConfidenceThreshold(0)
	if Summary(g.HostReachable("A", "B", 2)) != VerdictReachable {
		t.Fatal("threshold=0 should disable confidence downgrade")
	}
}

func TestLowConfidencePolicyDoesNotBlock(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.15.1.0/24"}},
		{HostID: "GW", Subnets: []string{"10.15.1.0/24", "10.15.2.0/24"}, Forwards: true},
		{HostID: "B", Subnets: []string{"10.15.2.0/24"}},
	}
	policies := []PolicyRule{{From: "10.15.1.0/24", To: "10.15.2.0/24", Allow: false, Confidence: 0.2}}
	g := BuildLayeredGraph(hosts, policies, true, true)
	if got := Summary(g.HostReachable("A", "B", 3)); got != VerdictProbable {
		t.Fatalf("low-confidence deny = %s, want probable", got)
	}
}

func hasUnknown(pvs []PathVerdict, want string) bool {
	for _, pv := range pvs {
		for _, u := range pv.Unknowns {
			if u == want {
				return true
			}
		}
	}
	return false
}
