//go:build engine

package srd

import (
	"testing"

	prismlib "github.com/chins-xing/prism"
)

// TestBuildEdgesWithTopology 钉住"真实边构造"规则：
//   - 只有共享子网才连边（不同子网无边）；
//   - 边是双向的（A→B 与 B→A）；
//   - 传输率按**源**主机 SSAM 分数加权（高分源更大）。
//
// 这是 SRD 路径识别的基础：如果这里错了，多跳路径与误判率实验全部失真。
func TestBuildEdgesWithTopology(t *testing.T) {
	topo := map[string]*TopologyInfo{
		"a":    {Subnets: []string{"172.22.10.0/24"}},
		"b":    {Subnets: []string{"172.22.10.0/24"}},
		"c":    {Subnets: []string{"172.23.10.0/24"}},
		"r":    {Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}},
		"nogo": {Subnets: []string{"172.24.0.0/24"}},
	}
	nodes := map[string]*prismlib.NodeState{
		"a":    {HostID: "a", SSAMScore: 20},
		"b":    {HostID: "b", SSAMScore: 80},
		"c":    {HostID: "c", SSAMScore: 50},
		"r":    {HostID: "r", SSAMScore: 50},
		"nogo": {HostID: "nogo", SSAMScore: 50},
	}
	edges := BuildEdgesWithTopology(topo, nodes, 0.1)

	has := func(src, dst string) *prismlib.EdgeState {
		for i := range edges {
			if edges[i].Source == src && edges[i].Target == dst {
				return &edges[i]
			}
		}
		return nil
	}

	if has("a", "b") == nil {
		t.Fatal("同子网 a→b 应有边")
	}
	if has("b", "a") == nil {
		t.Fatal("同子网边必须双向：b→a 缺失")
	}
	if has("a", "c") != nil {
		t.Fatal("不同子网 a→c 不应有边")
	}
	if has("a", "r") == nil || has("r", "c") == nil {
		t.Fatal("路由器同时属于两个子网 ⇒ a→r 与 r→c 都应有边")
	}
	if has("a", "nogo") != nil {
		t.Fatal("孤立子网 a→nogo 不应有边")
	}

	// 加权方向：**分数低（弱）的主机作为源时传输率更高**（它更容易被攻陷并扩散），
	// 分数高的主机作为源时衰减。a 分 20 < b 分 80，所以 a→b 的边传输率应大于 b→a。
	ab := has("a", "b")
	ba := has("b", "a")
	if ab == nil || ba == nil {
		t.Fatal("缺少 a/b 边")
	}
	if !(ab.RiskTransmission > ba.RiskTransmission) {
		t.Errorf("按源分数加权失败：源 a(20)=%.4f 源 b(80)=%.4f（弱源应更大）",
			ab.RiskTransmission, ba.RiskTransmission)
	}
}

// TestBuildEdgesTransmissionFallback 传输率为 0/负数时回退到 0.1（与 pipeline 一致）。
func TestBuildEdgesTransmissionFallback(t *testing.T) {
	topo := map[string]*TopologyInfo{"a": {Subnets: []string{"10.0.0.0/24"}}, "b": {Subnets: []string{"10.0.0.0/24"}}}
	nodes := map[string]*prismlib.NodeState{"a": {}, "b": {}}
	edges := BuildEdgesWithTopology(topo, nodes, 0)
	if len(edges) != 2 {
		t.Fatalf("期望 2 条双向边，got %d", len(edges))
	}
	for _, e := range edges {
		if e.RiskTransmission <= 0 {
			t.Fatalf("传输率未回退：%+v", e)
		}
	}
}

// TestBuildEdgesMissingTopologyFallsBackToCompleteGraph 钉住既有保守行为：
// 任一方没有拓扑数据时按"连通"处理（与 areConnectedLocked 一致），
// 避免把"没数据"误判成"不可达"。
func TestBuildEdgesMissingTopologyFallsBackToCompleteGraph(t *testing.T) {
	topo := map[string]*TopologyInfo{"a": {Subnets: []string{"10.0.0.0/24"}}}
	nodes := map[string]*prismlib.NodeState{"a": {}, "unknown": {}}
	edges := BuildEdgesWithTopology(topo, nodes, 0.1)
	found := false
	for _, e := range edges {
		if (e.Source == "a" && e.Target == "unknown") || (e.Source == "unknown" && e.Target == "a") {
			found = true
		}
	}
	if !found {
		t.Fatal("缺拓扑数据时应回退为连通（完全图）")
	}
}
