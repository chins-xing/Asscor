package topology

import "testing"

func TestLookupRouteLongestPrefix(t *testing.T) {
	hosts := []HostFacts{{
		HostID: "A",
		Routes: []Route{
			{Destination: "10.0.0.0/8", NextHop: "R-wide"},
			{Destination: "10.1.0.0/16", NextHop: "R-narrow"},
			{Destination: "10.1.2.0/24", NextHop: "R-narrowest"},
		},
	}}
	g := BuildLayeredGraph(hosts, nil, true, true)
	cases := []struct{ ip, want string }{
		{"10.1.2.3", "R-narrowest"},
		{"10.1.9.9", "R-narrow"},
		{"10.9.9.9", "R-wide"},
	}
	for _, c := range cases {
		r, ok := g.LookupRoute("A", c.ip)
		if !ok || r.NextHop != c.want {
			t.Fatalf("lookup %s = %+v ok=%v, want %s", c.ip, r, ok, c.want)
		}
	}
	if _, ok := g.LookupRoute("A", "192.168.1.1"); ok {
		t.Fatal("unexpected default route match")
	}
}

func TestLookupRouteMetricTieBreak(t *testing.T) {
	hosts := []HostFacts{{HostID: "A", Routes: []Route{
		{Destination: "10.0.0.0/8", NextHop: "high", Metric: 20},
		{Destination: "10.0.0.0/8", NextHop: "low", Metric: 10},
	}}}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if r, ok := g.LookupRoute("A", "10.1.1.1"); !ok || r.NextHop != "low" {
		t.Fatalf("metric tie-break = %+v ok=%v", r, ok)
	}
}
