package federation

import "testing"

// 调试：节点上报的 inbound /32 事实必须在合并图上生效。
func TestMergeInboundHostRule(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "a", IPs: []string{"172.22.10.101"}, Subnets: []string{"172.22.10.0/24"}},
			{ID: "b", IPs: []string{"172.23.10.101"}, Subnets: []string{"172.23.10.0/24"},
				Inbound: []PolicyFact{{From: "172.22.10.101/32", Allow: false}}},
			{ID: "r", IPs: []string{"172.22.10.1", "172.23.10.1"},
				Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
		}},
	}
	g := BuildMergedGraph(reports)
	res := CheckMerged(g, "a", "b", 5)
	t.Logf("verdict=%s paths=%d best=%+v", res.Verdict, res.Paths, res.Best)
	if res.Verdict != "blocked" {
		t.Fatalf("应 blocked，got %s", res.Verdict)
	}
}
