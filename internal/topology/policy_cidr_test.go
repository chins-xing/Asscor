package topology

import "testing"

// agent 上报的策略地址可能是带主机位的 CIDR（172.22.10.1/24），必须与子网匹配。
func TestPolicyHostBitsCIDRMatchesSubnet(t *testing.T) {
	hosts := []HostFacts{
		{HostID: "a", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "b", Subnets: []string{"10.1.0.0/24"}, IPs: []string{"10.1.0.11"}},
		{HostID: "r", Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, Forwards: true},
	}
	policies := []PolicyRule{{From: "10.0.0.1/24", To: "10.1.0.1/24", Allow: false}}
	g := BuildLayeredGraph(hosts, policies, true, true)
	pvs := g.HostReachable("a", "b", 5)
	if len(pvs) == 0 || pvs[0].Verdict != VerdictBlocked {
		t.Fatalf("带主机位策略应阻断，got %+v", pvs)
	}
}
