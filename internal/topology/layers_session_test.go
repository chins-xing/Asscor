package topology

import "testing"

// TestLayeredGraphOneWayDenyBlocksBothDirections 钉住**会话语义**：
// 真实防火墙里 `ct state ... accept` 排在 drop 之后 ⇒ 单向 deny 会让回程包也被丢，
// 于是两个方向都不可达。只按单方向判定会产生"非对称误报"（实测 D→A 被误判可达）。
func TestLayeredGraphOneWayDenyBlocksBothDirections(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "D-host", Subnets: []string{"172.26.0.0/24"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "172.26.0.0/24"}, Forwards: true},
	}
	// 只有 A→D 的 deny（D→A 没有规则）
	g := BuildLayeredGraph(hosts, []PolicyRule{
		{From: "172.22.10.0/24", To: "172.26.0.0/24", Allow: false},
	}, true, true)

	if got := Summary(g.HostReachable("A-web", "D-host", 3)); got != VerdictBlocked {
		t.Fatalf("A→D 被 deny，应 blocked，got %v", got)
	}
	if got := Summary(g.HostReachable("D-host", "A-web", 3)); got != VerdictBlocked {
		t.Fatalf("回程被丢 ⇒ D→A 也应 blocked（会话语义），got %v", got)
	}
}
