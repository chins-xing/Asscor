package topology

import "testing"

// 分层图的验收用例直接对应第一轮实验暴露的两类错误：
//   - 策略阻断被误报为可达（c2）
//   - 不可见目标被当作不存在（c5）
func TestLayeredGraphPolicyBlockedPathIsBlocked(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}, Gateways: []string{"172.22.10.1"}},
		{HostID: "B-web", Subnets: []string{"172.23.10.0/24"}, Gateways: []string{"172.23.10.1"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{
		{From: "172.22.10.0/24", To: "172.23.10.0/24", Allow: false},
	}, true, true)

	got := Summary(g.HostReachable("A-web", "B-web", 3))
	if got != VerdictBlocked {
		t.Fatalf("策略阻断的跨域链应为 blocked，got %v", got)
	}
}

func TestLayeredGraphNoPolicyDataMeansProbable(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "B-web", Subnets: []string{"172.23.10.0/24"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, nil, false /*policyKnown*/, true)

	got := Summary(g.HostReachable("A-web", "B-web", 3))
	if got != VerdictProbable {
		t.Fatalf("没有策略数据时应为 probable（不能假设放行），got %v", got)
	}
}

func TestLayeredGraphAllowPolicyMakesReachable(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "C-mon", Subnets: []string{"100.64.0.0/24"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "100.64.0.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{
		{From: "172.22.10.0/24", To: "100.64.0.0/24", Allow: true},
	}, true, true)

	got := Summary(g.HostReachable("A-web", "C-mon", 3))
	if got != VerdictReachable {
		t.Fatalf("策略放行的跨域链应为 reachable，got %v", got)
	}
}

func TestLayeredGraphUnknownTargetIsProbable(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "172.26.0.0/24"}, Forwards: true},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{{From: "172.22.10.0/24", To: "172.26.0.0/24", Allow: true}}, true, true)

	// shadow-1 真实存在但无 agent：不在 host 集合里 ⇒ 必须 probable，而不是"不存在/不可达"
	got := Summary(g.HostReachable("A-web", "shadow-1", 3))
	if got != VerdictProbable {
		t.Fatalf("不可见目标应为 probable（可能），got %v", got)
	}
}

func TestLayeredGraphSameSubnetIsReachable(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "A-db", Subnets: []string{"172.22.10.0/24"}},
	}
	g := BuildLayeredGraph(hosts, nil, false, true)
	got := Summary(g.HostReachable("A-web", "A-db", 2))
	if got != VerdictReachable {
		t.Fatalf("同子网直连应 reachable（域内不查跨域策略），got %v", got)
	}
	if gw := g.Gateways(); len(gw) != 0 {
		t.Fatalf("单子网主机不应被识别为网关: %v", gw)
	}
}

func TestLayeredGraphMultiHopThroughTwoRouters(t *testing.T) {
	// A(172.22.10) - r1(172.22.10,172.23.10) - r2(172.23.10,172.24.10) - D(172.24.10)
	hosts := []HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "r1", Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
		{HostID: "r2", Subnets: []string{"172.23.10.0/24", "172.24.10.0/24"}, Forwards: true},
		{HostID: "D-host", Subnets: []string{"172.24.10.0/24"}},
	}
	g := BuildLayeredGraph(hosts, []PolicyRule{
		{From: "172.22.10.0/24", To: "172.23.10.0/24", Allow: true},
		{From: "172.23.10.0/24", To: "172.24.10.0/24", Allow: true},
	}, true, true)
	got := Summary(g.HostReachable("A-web", "D-host", 4))
	if got != VerdictReachable {
		t.Fatalf("两跳网关链应为 reachable，got %v", got)
	}
}
