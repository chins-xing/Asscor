package topology

import "testing"

// v2.3 T2：有状态防火墙（ct established accept）下，**反向会话**仍可通。
// B 的 INPUT：`ct state established,related accept` 在前，`ip saddr A/32 drop` 在后：
//   - A→B：新连接被 drop ⇒ blocked；
//   - B→A：B 自己发起，回程 A→B 命中 B 的 conntrack（ESTABLISHED）⇒ 放行 ⇒ reachable。
func TestStatefulFirewallAsymmetricReachability(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"},
			StatefulInput: true,
			Inbound:       []PolicyRule{{From: "10.0.0.11/32", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 新连接应被 drop（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictBlocked {
		t.Fatalf("A→B 应 blocked，got %v", got)
	}
	if ok, why := g.Adjacent("B", "A"); !ok {
		t.Fatalf("B→A 的回程应被 conntrack 放行（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("B", "A", 2)); got != VerdictReachable {
		t.Fatalf("B→A 应 reachable（状态化），got %v", got)
	}
}

// 对照：无状态防火墙（无 ct accept）⇒ 双向都断。
func TestStatelessFirewallBlocksBothDirections(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"},
			Inbound: []PolicyRule{{From: "10.0.0.11/32", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, _ := g.Adjacent("A", "B"); ok {
		t.Fatal("A→B 应 blocked")
	}
	if ok, _ := g.Adjacent("B", "A"); ok {
		t.Fatal("无状态时 B→A 的回程也应被 drop")
	}
}

// 出向拒绝不受状态化影响：源主机主动发出的新连接仍被拦。
func TestStatefulDoesNotBypassOutbound(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"},
			StatefulInput: true,
			Outbound:      []PolicyRule{{To: "10.0.0.20/32", Allow: false}}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"}, StatefulInput: true},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("OUTPUT 拒绝仍应阻断 A→B（reason=%s）", why)
	}
}

// 注册表接线：stateful 标记必须进入分层图。
func TestRegistryWiresStateful(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()
	RecordNetworkFacts("A", []string{"10.0.0.0/24"}, "internal", nil, false, nil, true,
		nil, []string{"10.0.0.11"}, true, true)
	RecordNetworkFacts("B", []string{"10.0.0.0/24"}, "internal", nil, false,
		[]TopoPolicyRule{{From: "10.0.0.11/32", Allow: false, Direction: "inbound"}}, true,
		nil, []string{"10.0.0.20"}, true, true)

	g := BuildLayeredFromRegistry()
	if g == nil {
		t.Fatal("注册表非空应构造出图")
	}
	// A(有状态)→B 被 B 的 inbound 拒 ⇒ blocked
	if ok, _ := g.Adjacent("A", "B"); ok {
		t.Fatal("A→B 应 blocked")
	}
	// B→A：回程到 A，A 有状态 ⇒ 放行
	if ok, why := g.Adjacent("B", "A"); !ok {
		t.Fatalf("B→A 应因 A 有状态而放行（reason=%s）", why)
	}
}
