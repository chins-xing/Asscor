package topology

import "testing"

// A-4：INPUT 是**单向**语义。B 拒绝来自 A 子网的入向流量时：
//   - A→B 应 blocked（目标 B 的入向策略拒绝）；
//   - B→A 的目标 A 没有对应规则，模型不应凭空阻断（现实里回程包会被 B 自己的
//     INPUT 丢掉，但那是**有状态**行为，本模型只表达单向入向规则，需在文档里说明）。
//
// 本用例先钉住"方向性"本身：A→B blocked、B→A reachable。
func TestInboundPolicyIsDirectional(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{{From: "10.0.0.0/24", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 应被 B 的入向策略阻断（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("A", "B", 2)); got != VerdictBlocked {
		t.Fatalf("A→B 应 blocked，got %v", got)
	}
	if ok, why := g.Adjacent("B", "A"); !ok {
		t.Fatalf("B→A 目标 A 无入向规则，不应阻断（reason=%s）", why)
	}
}
