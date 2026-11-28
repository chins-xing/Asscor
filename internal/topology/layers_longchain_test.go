package topology

import (
	"fmt"
	"testing"
)

// buildChain builds H0 - H1 - ... - H(N-1), with each adjacent pair sharing
// one unique subnet. Intermediate hosts forward; endpoints do not.
func buildChain(n int) *LayeredGraph {
	hosts := make([]HostFacts, 0, n)
	for i := 0; i < n; i++ {
		h := HostFacts{HostID: fmt.Sprintf("H%d", i), Forwards: i > 0 && i < n-1}
		if i > 0 {
			h.Subnets = append(h.Subnets, fmt.Sprintf("10.%d.0.0/24", i))
		}
		if i < n-1 {
			h.Subnets = append(h.Subnets, fmt.Sprintf("10.%d.0.0/24", i+1))
		}
		hosts = append(hosts, h)
	}
	return BuildLayeredGraph(hosts, nil, true, true)
}

func TestLongChainDepthExhaustion(t *testing.T) {
	const n = 32
	g := buildChain(n)
	short := g.HostReachable("H0", fmt.Sprintf("H%d", n-1), 5)
	if Summary(short) != VerdictProbable {
		t.Fatalf("maxHops=5 on %d-chain verdict = %s, want probable (paths=%d)", n, Summary(short), len(short))
	}
	found := false
	for _, pv := range short {
		for _, u := range pv.Unknowns {
			if u == "max_hops_exhausted" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("long chain missing max_hops_exhausted: %+v", short)
	}

	full := g.HostReachable("H0", fmt.Sprintf("H%d", n-1), n-1)
	if Summary(full) != VerdictReachable {
		t.Fatalf("maxHops=%d on %d-chain verdict = %s, want reachable", n-1, n, Summary(full))
	}
}
