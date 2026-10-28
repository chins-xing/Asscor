package topology

import "testing"

// v2.3 T1：同子网主机级入向 ACL（/32 来源）——靠 HostFacts.IPs 匹配。
func TestIntraSubnetHostInboundRule(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "C", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.12"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"},
			Inbound: []PolicyRule{{From: "10.0.0.11/32", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	// A→B 被 /32 规则阻断（B 的 INPUT 拒 A 主机）
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 应被 /32 入向规则阻断（reason=%s）", why)
	}
	// C→B 不受影响（不同源主机）
	if ok, why := g.Adjacent("C", "B"); !ok {
		t.Fatalf("C→B 不应被针对 A 的 /32 规则影响（reason=%s）", why)
	}
}

// v2.3 T1：出向策略（OUTPUT）——源主机被禁止发往目标，会话失败。
func TestIntraSubnetOutboundRule(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"},
			Outbound: []PolicyRule{{To: "10.0.0.20/32", Allow: false}}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A 的 OUTPUT 拒绝 B，会话应 blocked（reason=%s）", why)
	}
	// 反向会话离不开 A 的 INPUT/OUTPUT：B→A 的请求能到 A，但 A 的回程（A→B）仍被 OUTPUT 拒
	if ok, why := g.Adjacent("B", "A"); ok {
		t.Fatalf("B→A 的回程被 A 的 OUTPUT 丢弃，应 blocked（reason=%s）", why)
	}
}

// 出向规则按目标子网作用域：只影响该子网。
func TestOutboundRuleScopedBySubnet(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24", "10.9.0.0/24"}, IPs: []string{"10.0.0.11", "10.9.0.11"},
			Outbound: []PolicyRule{{To: "10.9.0.0/24", Allow: false}}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, why := g.Adjacent("A", "B"); !ok {
		t.Fatalf("A→B 走 10.0.0.0/24，不应被 To=10.9 的出向规则影响（reason=%s）", why)
	}
}

// 未知出向数据 ⇒ 不阻断。
func TestOutboundUnknownDoesNotBlock(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	if ok, why := g.Adjacent("A", "B"); !ok {
		t.Fatalf("无出向数据不应阻断（reason=%s）", why)
	}
}

// 注册表接线：outbound 规则与 IPs 必须进入分层图。
func TestRegistryWiresOutboundAndIPs(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()
	RecordNetworkFacts("A", []string{"10.0.0.0/24"}, "internal", nil, false,
		[]TopoPolicyRule{{To: "10.0.0.20/32", Allow: false, Direction: "outbound"}}, true,
		nil, []string{"10.0.0.11"})
	RecordNetworkFacts("B", []string{"10.0.0.0/24"}, "internal", nil, false, nil, false,
		nil, []string{"10.0.0.20"})

	g := BuildLayeredFromRegistry()
	if g == nil {
		t.Fatal("注册表非空应构造出图")
	}
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A 的 outbound 规则应阻断 A→B（reason=%s）", why)
	}
}
