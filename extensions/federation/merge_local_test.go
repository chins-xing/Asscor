package federation

import "testing"

// 进程隔离模式：本地事实由调用方注入，不依赖 topology 全局注册表。
func TestBuildMergedGraphWithLocal(t *testing.T) {
	reports := []NodeReport{{NodeID: "nk1", HostFacts: []HostFact{
		{ID: "b", IPs: []string{"10.1.0.11"}, Subnets: []string{"10.1.0.0/24"}},
	}}}
	local := []HostFact{
		{ID: "a", IPs: []string{"10.0.0.11"}, Subnets: []string{"10.0.0.0/24"}},
		{ID: "r", IPs: []string{"10.0.0.1", "10.1.0.1"}, Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, Forwards: true},
	}
	g := BuildMergedGraphWithLocal(reports, local, nil, true)
	if res := CheckMerged(g, "a", "b", 5); res.Verdict != "reachable" {
		t.Fatalf("verdict = %s, want reachable", res.Verdict)
	}
}
