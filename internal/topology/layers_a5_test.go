package topology

import "testing"

// A-5：inbound 规则带 To（目标子网）时，只有"送到该子网"的流量受影响。
func TestInboundRuleScopedByTargetSubnet(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{{To: "10.0.0.0/24", Allow: false}}},
		{HostID: "C", Subnets: []string{"10.9.0.0/24"}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	// B 拒绝"送到 10.0.0.0/24"的入向 ⇒ A→B 与 B→A 都 blocked（会话双向）
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 应被 daddr 规则阻断（reason=%s）", why)
	}
	// C 在别的子网：共享子网为 10.9.0.0/24，不在 B 的 daddr 范围内 ⇒ 不受影响
	if ok, why := g.Adjacent("C", "A"); !ok {
		t.Fatalf("C→A 不应受 B 的 daddr 规则影响（reason=%s）", why)
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
