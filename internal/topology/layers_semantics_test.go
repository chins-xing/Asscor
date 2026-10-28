package topology

import "testing"

// L2 语义：同子网但不同 VLAN ⇒ 不连通（重叠地址 + VLAN 隔离场景）。
func TestVLANGateBlocksSameSubnetDifferentBroadcast(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A1", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"101"}},
		{HostID: "B1", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"102"}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)

	if ok, why := g.Adjacent("A1", "B1"); ok {
		t.Fatalf("同子网不同 VLAN 不应邻接（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("A1", "B1", 2)); got != VerdictBlocked {
		t.Fatalf("L2 隔离应判 blocked，got %v", got)
	}
}

// 同 VLAN 同子网 ⇒ 邻接（即便另有同网段主机）。
func TestVLANGateAllowsSameBroadcast(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A1", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"101"}, Forwards: false},
		{HostID: "A2", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"101"}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if got := Summary(g.HostReachable("A1", "A2", 2)); got != VerdictReachable {
		t.Fatalf("同 VLAN 同子网应 reachable，got %v", got)
	}
}

// VLAN 未知时不阻断（未知 ≠ 拒绝），保持既有行为。
func TestVLANUnknownDoesNotBlock(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A1", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"101"}},
		{HostID: "A2", Subnets: []string{"10.0.0.0/24"}}, // VLAN 未知
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g.Adjacent("A1", "A2"); !ok {
		t.Fatalf("任一方 VLAN 未知时不应阻断，reason=%s", why)
	}
}

// L5：区域语义映射到关键性。
func TestCriticalityForZone(t *testing.T) {
	cases := map[string]float64{
		"internal": 0.80, "dmz": 0.60, "cloud": 0.60,
		"public": 0.40, "wan": 0.30, "": 0.50, "unknown": 0.50,
	}
	for zone, want := range cases {
		if got := CriticalityForZone(zone); got != want {
			t.Errorf("CriticalityForZone(%q)=%v want %v", zone, got, want)
		}
	}
}

// 跨层统计：主机/子网/VLAN/策略/转发者 都应被如实计数。
func TestLayeredGraphStats(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, VLANs: []string{"101"}, Zone: "internal"},
		{HostID: "B", Subnets: []string{"10.1.0.0/24"}, VLANs: []string{"102"}, Zone: "dmz"},
		{HostID: "R", Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, VLANs: []string{"101", "102"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{{From: "10.0.0.0/24", To: "10.1.0.0/24"}}, true, true)
	st := g.Stats()
	for k, want := range map[string]int{"hosts": 3, "subnets": 2, "vlans": 2, "policies": 1, "forwarding": 1, "policy_known": 1} {
		if st[k] != want {
			t.Errorf("stats[%s]=%d want %d (all=%v)", k, st[k], want, st)
		}
	}
}

// 数据接线：注册表里的 VLAN/Zone/Forwards 必须进入分层图。
func TestBuildLayeredFromRegistryWiresFacts(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	RecordNetworkFacts("A", []string{"10.0.0.0/24"}, "internal", []string{"101"}, false,
		[]TopoPolicyRule{{From: "10.0.0.0/24", To: "10.0.0.0/24", Allow: false}}, true,
		[]TopoLink{{Name: "eth0", Up: true, Subnets: []string{"10.0.0.0/24"}}}, nil, false, false)
	RecordNetworkFacts("B", []string{"10.0.0.0/24"}, "dmz", []string{"102"}, false, nil, false,
		[]TopoLink{{Name: "eth0", Up: true, Subnets: []string{"10.0.0.0/24"}}}, nil, false, false)

	g := BuildLayeredFromRegistry()
	if g == nil {
		t.Fatal("注册表非空时应构造出分层图")
	}
	if st := g.Stats(); st["hosts"] != 2 || st["vlans"] != 2 || st["policy_known"] != 1 {
		t.Fatalf("事实未接进图: %v", st)
	}
	if ok, _ := g.Adjacent("A", "B"); ok {
		t.Fatal("注册表里 VLAN 101 vs 102 应被 L2 闸门阻断")
	}
}
