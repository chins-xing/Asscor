package federation

import "testing"

// v0.2：导出必须包含节点上报与主端本地事实，且策略稳定排序。
func TestMergedTopologyExport(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "a", IPs: []string{"10.0.0.11"}, Subnets: []string{"10.0.0.0/24"}},
			{ID: "b", IPs: []string{"10.1.0.11"}, Subnets: []string{"10.1.0.0/24"}},
		}, PolicyFacts: []PolicyFact{{From: "10.0.0.0/24", To: "10.1.0.0/24", Allow: false}}},
	}
	exp := MergedTopology(reports)
	if len(exp.Hosts) < 2 {
		t.Fatalf("应导出至少 2 主机，got %d", len(exp.Hosts))
	}
	if !exp.PolicyKnown {
		t.Fatal("policy_known 应继承上报值")
	}
	found := false
	for _, p := range exp.Policies {
		if p.From == "10.0.0.0/24" && !p.Allow {
			found = true
		}
	}
	if !found {
		t.Fatalf("导出的策略缺少 deny 事实: %+v", exp.Policies)
	}
}
