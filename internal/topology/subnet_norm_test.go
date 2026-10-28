package topology

import "testing"

// 子网规范化：带主机位的地址必须归一到网络地址，否则同一子网被判成两个。
func TestNormalizeSubnets(t *testing.T) {
	got := normalizeSubnets([]string{"172.23.10.101/24", "172.23.10.0/24", "192.168.30.102/24", "10.0.0.1"})
	want := []string{"172.23.10.0/24", "192.168.30.0/24", "10.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// 规范化后，带主机位子网的主机应与路由器同子网邻接。
func TestHostWithHostBitsSubnetAdjacentToRouter(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "h", Subnets: normalizeSubnets([]string{"10.0.0.11/24"}), IPs: []string{"10.0.0.11"}},
		{HostID: "r", Subnets: []string{"10.0.0.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g.Adjacent("h", "r"); !ok {
		t.Fatalf("规范化后应邻接，reason=%s", why)
	}
}
