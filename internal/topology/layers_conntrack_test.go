package topology

import "testing"

func TestInvalidStateDropped(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.18.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.18.0.0/24"}, StatefulInvalidDrop: true},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{State: "invalid"})); got != VerdictBlocked {
		t.Fatalf("invalid state = %s, want blocked", got)
	}
	if got := Summary(g.HostReachableFlow("A", "B", 2, Flow{State: "established"})); got != VerdictReachable {
		t.Fatalf("established state = %s, want reachable", got)
	}
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictReachable {
		t.Fatalf("default new state = %s, want reachable", got)
	}
}
