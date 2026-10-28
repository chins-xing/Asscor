package federation

import (
	"testing"

	"github.com/chins-xing/asscor/internal/topology"
)

// v0.2：两个节点上报的图事实必须能被主端合并成一张跨节点图。
func TestBuildMergedGraphCrossNode(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "a1", IPs: []string{"10.0.0.11"}, Subnets: []string{"10.0.0.0/24"}},
			{ID: "r1", IPs: []string{"10.0.0.1", "10.1.0.1"}, Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, Forwards: true},
		}},
		{NodeID: "nk2", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "b1", IPs: []string{"10.1.0.11"}, Subnets: []string{"10.1.0.0/24"}},
		}},
	}
	g := BuildMergedGraph(reports)
	if g.Stats()["hosts"] != 3 {
		t.Fatalf("合并后应有 3 主机，got %v", g.Stats())
	}
	if res := CheckMerged(g, "a1", "b1", 5); res.Verdict != "reachable" {
		t.Fatalf("跨节点应 reachable，got %s (%+v)", res.Verdict, res.Best)
	}
}

// 合并后的策略事实必须生效（deny 阻断跨节点路径）。
func TestBuildMergedGraphAppliesPolicy(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "a1", IPs: []string{"10.0.0.11"}, Subnets: []string{"10.0.0.0/24"}},
			{ID: "r1", IPs: []string{"10.0.0.1", "10.1.0.1"}, Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, Forwards: true},
		}, PolicyFacts: []PolicyFact{{From: "10.0.0.0/24", To: "10.1.0.0/24", Allow: false}}},
		{NodeID: "nk2", PolicyKnown: true, HostFacts: []HostFact{
			{ID: "b1", IPs: []string{"10.1.0.11"}, Subnets: []string{"10.1.0.0/24"}},
		}},
	}
	g := BuildMergedGraph(reports)
	res := CheckMerged(g, "a1", "b1", 5)
	if res.Verdict != "blocked" {
		t.Fatalf("deny 策略应阻断，got %s (%+v)", res.Verdict, res.Best)
	}
}

// 同一主机多个节点上报时字段并集/后到优先，不应重复成两个节点。
func TestBuildMergedGraphDedupesHost(t *testing.T) {
	reports := []NodeReport{
		{NodeID: "nk1", HostFacts: []HostFact{{ID: "x", Subnets: []string{"10.0.0.0/24"}}}},
		{NodeID: "nk2", HostFacts: []HostFact{{ID: "x", Subnets: []string{"10.9.0.0/24"}, Zone: "dmz"}}},
	}
	g := BuildMergedGraph(reports)
	st := g.Stats()
	if st["hosts"] != 1 {
		t.Fatalf("同一 host 应去重，stats=%v", st)
	}
	if st["subnets"] != 2 {
		t.Fatalf("子网应取并集，stats=%v", st)
	}
	_ = topology.VerdictReachable
}
