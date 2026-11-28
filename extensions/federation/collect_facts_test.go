package federation

import (
	"testing"

	"github.com/chins-xing/asscor/internal/topology"
)

func TestCollectFactsTruncationVisible(t *testing.T) {
	nodes := make([]*topology.TopoNode, MaxHostFacts+1)
	for i := range nodes {
		nodes[i] = &topology.TopoNode{HostID: "h"}
	}
	hosts, _, _, truncated, droppedHosts, _ := collectFacts(nodes)
	if !truncated || droppedHosts != 1 || len(hosts) != MaxHostFacts {
		t.Fatalf("truncated=%v dropped=%d hosts=%d", truncated, droppedHosts, len(hosts))
	}
}

func TestCollectFactsPreservesL4AndMetadata(t *testing.T) {
	nodes := []*topology.TopoNode{{
		HostID: "h1", PolicyKnown: true,
		Policies: []topology.TopoPolicyRule{{
			From: "10.0.0.0/24", To: "10.0.1.0/24", Allow: true,
			Protocol: "tcp", DstPort: 443, Confidence: 0.8,
		}},
	}}
	_, policies, _, _, _, _ := collectFacts(nodes)
	if len(policies) != 1 {
		t.Fatalf("policies=%+v", policies)
	}
	p := policies[0]
	if p.Protocol != "tcp" || p.DstPort != 443 || p.Confidence != 0.8 {
		t.Fatalf("metadata lost: %+v", p)
	}
}
