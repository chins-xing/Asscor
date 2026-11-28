package topology

import "testing"

func TestNATExternalAliasReachable(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.16.1.0/24"}},
		{HostID: "SVC", Subnets: []string{"10.16.2.0/24"}, NAT: []NATRule{
			{External: "10.16.1.0/24", Internal: "10.16.2.0/24"},
		}},
	}
	withNAT := BuildLayeredGraph(hosts, nil, true, true)
	if got := Summary(withNAT.HostReachable("A", "SVC", 2)); got != VerdictReachable {
		t.Fatalf("NAT alias verdict = %s, want reachable", got)
	}
	without := BuildLayeredGraph([]HostFacts{hosts[0], {HostID: "SVC", Subnets: []string{"10.16.2.0/24"}}}, nil, true, true)
	if got := Summary(without.HostReachable("A", "SVC", 2)); got != VerdictBlocked {
		t.Fatalf("without NAT verdict = %s, want blocked", got)
	}
}
