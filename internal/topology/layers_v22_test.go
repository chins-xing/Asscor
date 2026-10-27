package topology

import "testing"

// L1：任一端口 down ⇒ 该子网不邻接（链路态是显式事实，不再靠"不上报子网"隐式表达）。
func TestLinkDownBlocksAdjacency(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, Links: map[string]bool{"10.0.0.0/24": true}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Links: map[string]bool{"10.0.0.0/24": false}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("B 的链路 down 时应不邻接（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictBlocked {
		t.Fatalf("链路 down 应判 blocked，got %v", got)
	}

	hosts[1].Links["10.0.0.0/24"] = true
	g2 := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g2.Adjacent("A", "B"); !ok {
		t.Fatalf("链路恢复后应邻接（reason=%s）", why)
	}
}

// 域内/主机级 ACL：target 的入向策略拒绝来源子网 ⇒ 不邻接（同子网也拦）。
func TestInboundPolicyDeniesSameSubnet(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{{From: "10.0.0.0/24", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("B 的入向策略拒绝该子网，应不邻接（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictBlocked {
		t.Fatalf("入向拒绝应判 blocked，got %v", got)
	}
}

// 入向策略只针对特定来源：其他来源不受影响。
func TestInboundPolicyScopedToSource(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "C", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{{From: "192.168.0.0/16", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, why := g.Adjacent("A", "B"); !ok {
		t.Fatalf("入向规则不匹配来源时不应阻断（reason=%s）", why)
	}
	if ok, _ := g.Adjacent("C", "B"); !ok {
		t.Fatal("同子网另一来源也应可通")
	}
}

// 无入向数据 ⇒ 不阻断（未知 ≠ 拒绝）。
func TestInboundUnknownDoesNotBlock(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g.Adjacent("A", "B"); !ok {
		t.Fatalf("无入向数据不应阻断（reason=%s）", why)
	}
}

// L5 角色语义映射。
func TestCriticalityForRole(t *testing.T) {
	cases := map[string]float64{
		"db": 0.95, "core": 0.95, "router": 0.90, "web": 0.70,
		"monitor": 0.60, "shadow": 0.30, "": 0.50, "unknown": 0.50,
	}
	for role, want := range cases {
		if got := CriticalityForRole(role); got != want {
			t.Errorf("CriticalityForRole(%q)=%v want %v", role, got, want)
		}
	}
}

// 注册表全链路：links/inbound 也必须接进分层图。
func TestRegistryWiresLinksAndInbound(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()
	RecordNetworkFacts("A", []string{"10.0.0.0/24"}, "internal", nil, false, nil, false,
		[]TopoLink{{Name: "eth0", Up: true, Subnets: []string{"10.0.0.0/24"}}})
	RecordNetworkFacts("B", []string{"10.0.0.0/24"}, "internal", nil, false,
		[]TopoPolicyRule{{From: "10.0.0.0/24", Allow: false, Direction: "inbound"}}, true,
		[]TopoLink{{Name: "eth0", Up: false, Subnets: []string{"10.0.0.0/24"}}})

	g := BuildLayeredFromRegistry()
	if g == nil {
		t.Fatal("注册表非空应构造出图")
	}
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("B 链路 down + 入向拒绝，应不邻接（reason=%s）", why)
	}
}
