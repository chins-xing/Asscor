package topology

import "testing"

// A-4：入向策略按**会话语义**生效。B 拒绝来自 A 子网的入向流量时：
//   - A→B：请求被 B 的 INPUT 丢弃 ⇒ blocked；
//   - B→A：反向会话的回程包（A→B 方向）同样撞上 B 的 INPUT 被丢 ⇒ 也 blocked。
//
// 这修掉了旧模型"只校验目标侧"导致的非对称误报（v2.2.4 数据集 R2/R3 的 0.68–0.78）。
func TestInboundPolicySessionSemantics(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, Inbound: []PolicyRule{{From: "10.0.0.0/24", Allow: false}}},
	}
	g := BuildLayeredGraph(hosts, nil, true, true)

	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("A→B 应被 B 的入向策略阻断（reason=%s）", why)
	}
	if ok, why := g.Adjacent("B", "A"); ok {
		t.Fatalf("B→A 的回程包也会被 B 的 INPUT 丢，应 blocked（reason=%s）", why)
	}
	if got := Summary(g.HostReachable("B", "A", 2)); got != VerdictBlocked {
		t.Fatalf("B→A 应 blocked（会话双向），got %v", got)
	}
}
