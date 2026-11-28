package topology

import (
	"fmt"
	"testing"
)

func BenchmarkBuildLayeredGraph1024(b *testing.B) {
	hosts := make([]HostFacts, 0, 1024)
	for i := 0; i < 1024; i++ {
		h := HostFacts{HostID: fmt.Sprintf("B%d", i), Forwards: i > 0 && i < 1023}
		if i > 0 {
			h.Subnets = append(h.Subnets, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		}
		if i < 1023 {
			h.Subnets = append(h.Subnets, fmt.Sprintf("10.%d.%d.0/24", (i+1)/256, (i+1)%256))
		}
		hosts = append(hosts, h)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := BuildLayeredGraph(hosts, nil, true, true)
		if len(g.hosts) != 1024 {
			b.Fatalf("hosts=%d", len(g.hosts))
		}
	}
}

func BenchmarkHostReachableChain1024(b *testing.B) {
	g := buildChain(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := Summary(g.HostReachable("H0", "H1023", 5)); got != VerdictProbable {
			b.Fatalf("verdict=%s", got)
		}
	}
}

func BenchmarkHostReachableDense256(b *testing.B) {
	hosts := make([]HostFacts, 0, 256)
	for i := 0; i < 256; i++ {
		hosts = append(hosts, HostFacts{HostID: fmt.Sprintf("D%d", i), Subnets: []string{"10.99.0.0/24"}})
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := Summary(g.HostReachable("D0", "D255", 2)); got != VerdictReachable {
			b.Fatalf("verdict=%s", got)
		}
	}
}
