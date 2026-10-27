package topology

import "testing"

// TestLayeredGraphDualHomedHostCannotRelay 钉住实测踩到的坑：
// pivot-1 也是双网卡（域B + 影子域），但它 **不转发**（ip_forward=0）。
// 如果模型只按"≥2 个子网"就允许它当中继，会凭空造出 A→pivot→shadow 的绕行路径，
// 从而把"策略阻断"误判成"可达"。
func TestLayeredGraphDualHomedHostCannotRelay(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "pivot", Subnets: []string{"172.22.10.0/24", "172.26.0.0/24"}, Forwards: false},
		{HostID: "shadow", Subnets: []string{"172.26.0.0/24"}},
	}
	policies := []PolicyRule{{From: "172.22.10.0/24", To: "172.26.0.0/24", Allow: true}}
	g := BuildLayeredGraph(hosts, policies, true, true)

	if got := Summary(g.HostReachable("A-web", "shadow", 4)); got != VerdictBlocked {
		t.Fatalf("不转发的双宿主主机不能中继，应为 blocked，got %v", got)
	}

	// 同一拓扑，一旦它真的转发（router 角色），路径应成立。
	hosts[1].Forwards = true
	g2 := BuildLayeredGraph(hosts, policies, true, true)
	if got := Summary(g2.HostReachable("A-web", "shadow", 4)); got != VerdictReachable {
		t.Fatalf("转发开启后应为 reachable，got %v", got)
	}
}

// TestLayeredGraphDenyWinsOverShorterAllowedPath 钉住"阻断优先"：
// 若到目标只有被策略阻断的路径，即使存在更短的"看起来可达"的候选，也必须判 blocked。
func TestLayeredGraphDenyWinsOverShorterAllowedPath(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "B", Subnets: []string{"172.23.10.0/24"}},
		{HostID: "r", Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{
		{From: "172.22.10.0/24", To: "172.23.10.0/24", Allow: false},
	}, true, true)

	verdicts := g.HostReachable("A", "B", 3)
	for _, v := range verdicts {
		if v.Verdict == VerdictReachable {
			t.Fatalf("不应存在 reachable 路径：%+v", v)
		}
	}
	if got := Summary(verdicts); got != VerdictBlocked {
		t.Fatalf("总结论应为 blocked，got %v", got)
	}
}
