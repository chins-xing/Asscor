package topology

import "testing"

func TestHostReachableFlowPorts(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.7.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.7.0.0/24"}, Inbound: []PolicyRule{
			{From: "10.7.0.0/24", To: "10.7.0.0/24", Allow: true, Protocol: "tcp", DstPort: 80},
			{From: "10.7.0.0/24", To: "10.7.0.0/24", Allow: false, Protocol: "tcp", DstPort: 22},
		}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{Protocol: "tcp", DstPort: 80})); got != VerdictReachable {
		t.Fatalf("tcp/80 = %s, want reachable", got)
	}
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{Protocol: "tcp", DstPort: 22})); got != VerdictBlocked {
		t.Fatalf("tcp/22 = %s, want blocked", got)
	}
	// Unspecified flow keeps the historical any-flow behavior (first allow).
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictReachable {
		t.Fatalf("any-flow = %s, want reachable", got)
	}
}
