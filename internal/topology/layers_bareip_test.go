package topology

import "testing"

// 真实 agent 上报的 /32 规则会被 nft 规范化为裸 IP；模型必须能匹配。
func TestInboundBareIPRule(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"},
			Inbound: []PolicyRule{{From: "10.0.0.11", Allow: false}}}, // 裸 IP，无 /32
	}
	g := BuildLayeredGraph(hosts, nil, true, true)
	if ok, why := g.Adjacent("A", "B"); ok {
		t.Fatalf("裸 IP 入向规则应阻断，reason=%s", why)
	}
}
