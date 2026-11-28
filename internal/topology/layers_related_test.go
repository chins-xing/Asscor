package topology

import "testing"

func TestRelatedFlowBypassesStaticInput(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.21.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.21.0.0/24"}, StatefulRelated: true,
			Inbound: []PolicyRule{{From: "10.21.0.0/24", To: "10.21.0.0/24", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{State: "new"})); got != VerdictBlocked {
		t.Fatalf("new = %s, want blocked", got)
	}
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{State: "related"})); got != VerdictReachable {
		t.Fatalf("related = %s, want reachable", got)
	}
}
