package topology

import "testing"

// A-5：inbound 规则带 To（目标子网）时，只影响"送到该子网"的流量。
func TestInboundRuleScopedByTargetSubnet(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "A2", Subnets: []string{"10.9.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24", "10.9.0.0/24"},
			Inbound: []PolicyRule{{To: "10.0.0.0/24", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	// B 拒绝"送到 10.0.0.0/24"的入向 ⇒ A→B 被阻断
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 应被 daddr 规则阻断（reason=%s）", why)
	}
	// A2 与 B 共享 10.9.0.0/24，不在 B 的 daddr 范围内 ⇒ 不受影响
	if ok, why := g.Adjacent("A2", "B"); !ok {
		t.Fatalf("A2→B（10.9 段）不应受 daddr 规则影响（reason=%s）", why)
	}
}

// 首条匹配生效：先 drop 后 accept 与先 accept 后 drop 结果不同（顺序敏感）。
func TestInboundRuleOrderFirstMatch(t *testing.T) {
	dropFirst := BuildLayeredGraph([]HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{
			{From: "10.0.0.0/24", Allow: false},
			{From: "10.0.0.0/24", Allow: true},
		}},
	}, nil, true, true)
	if ok, _ := dropFirst.Adjacent("A", "B"); ok {
		t.Fatal("drop 在前时应阻断")
	}

	acceptFirst := BuildLayeredGraph([]HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{
			{From: "10.0.0.0/24", Allow: true},
			{From: "10.0.0.0/24", Allow: false},
		}},
	}, nil, true, true)
	if ok, why := acceptFirst.Adjacent("A", "B"); !ok {
		t.Fatalf("accept 在前时应放行（reason=%s）", why)
	}
}
