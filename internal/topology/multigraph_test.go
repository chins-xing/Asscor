package topology

import (
	"testing"
	"time"
)

// TestMultiGraphAddQuery: 节点/边增删查 + 分层/类型索引。
func TestMultiGraphAddQuery(t *testing.T) {
	g := NewMultiGraph()

	g.AddNode("host-a", LayerNetwork, NodeHost, map[string]string{"ip": "10.0.0.10"})
	g.AddNode("sub-1", LayerNetwork, NodeSubnet, map[string]string{"cidr": "10.0.0.0/24"})
	g.AddNode("actor-1", LayerAttacker, NodeActor, nil)

	if !g.AddEdge("host-a", "sub-1", EdgeConnects, LayerNetwork, 1) {
		t.Fatal("edge host→subnet should be added")
	}
	if g.AddEdge("host-a", "missing", EdgeConnects, LayerNetwork, 1) {
		t.Error("edge to missing node must be rejected (no dangling)")
	}

	if got := g.NodeCount(); got != 3 {
		t.Errorf("NodeCount = %d, want 3", got)
	}
	if got := g.EdgeCount(); got != 1 {
		t.Errorf("EdgeCount = %d, want 1", got)
	}
	if got := len(g.QueryByLayer(LayerNetwork)); got != 2 {
		t.Errorf("network layer nodes = %d, want 2", got)
	}
	if got := len(g.QueryByType(NodeActor)); got != 1 {
		t.Errorf("actor type nodes = %d, want 1", got)
	}
	if got := g.Neighbors("host-a", EdgeConnects); len(got) != 1 || got[0] != "sub-1" {
		t.Errorf("Neighbors = %v", got)
	}
}

// TestMultiGraphTemporal: 时序属性 — FirstSeen 保持、LastSeen 刷新、事件流。
func TestMultiGraphTemporal(t *testing.T) {
	g := NewMultiGraph()
	g.AddNode("host-a", LayerNetwork, NodeHost, nil)
	first := g.GetNode("host-a").FirstSeen

	time.Sleep(5 * time.Millisecond)
	g.AddNode("host-a", LayerNetwork, NodeHost, map[string]string{"ip": "10.0.0.11"})

	n := g.GetNode("host-a")
	if !n.FirstSeen.Equal(first) {
		t.Error("FirstSeen must be preserved on update")
	}
	if !n.LastSeen.After(first) {
		t.Error("LastSeen must refresh on update")
	}
	if n.Meta["ip"] != "10.0.0.11" {
		t.Errorf("meta not merged: %v", n.Meta)
	}

	// 事件流
	g.AppendEvent("host-a", GraphEvent{Type: "alert", Detail: "login brute force", Confidence: 0.8})
	g.AppendEvent("host-a", GraphEvent{Type: "decoy_trigger", Detail: "fake ssh"})
	n = g.GetNode("host-a")
	if len(n.Events) != 2 || n.Events[0].Type != "alert" || n.Events[1].Type != "decoy_trigger" {
		t.Errorf("event stream = %+v", n.Events)
	}
	// 未知节点事件 no-op
	g.AppendEvent("nope", GraphEvent{Type: "x"})
}

// TestMultiGraphRemove: 删节点连带删边。
func TestMultiGraphRemove(t *testing.T) {
	g := NewMultiGraph()
	g.AddNode("host-a", LayerNetwork, NodeHost, nil)
	g.AddNode("sub-1", LayerNetwork, NodeSubnet, nil)
	g.AddNode("actor-1", LayerAttacker, NodeActor, nil)
	g.AddEdge("host-a", "sub-1", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("actor-1", "host-a", EdgeTargets, LayerAttacker, 1)

	g.RemoveNode("host-a")

	if g.GetNode("host-a") != nil {
		t.Error("node must be gone")
	}
	if g.EdgeCount() != 0 {
		t.Errorf("edges touching removed node must be deleted, left %d", g.EdgeCount())
	}
	if len(g.QueryByLayer(LayerNetwork)) != 1 {
		t.Error("sub-1 must remain")
	}
	if g.GetEdge("actor-1", "host-a", EdgeTargets) != nil {
		t.Error("edge to removed node must be gone")
	}
}

// TestMultiGraphRemoveEdge: 定向删边。
func TestMultiGraphRemoveEdge(t *testing.T) {
	g := NewMultiGraph()
	g.AddNode("host-a", LayerNetwork, NodeHost, nil)
	g.AddNode("sub-1", LayerNetwork, NodeSubnet, nil)
	g.AddEdge("host-a", "sub-1", EdgeConnects, LayerNetwork, 1)

	g.RemoveEdge("host-a", "sub-1", EdgeConnects)
	if g.GetEdge("host-a", "sub-1", EdgeConnects) != nil {
		t.Error("edge must be gone")
	}
	if g.NodeCount() != 2 {
		t.Error("nodes must remain after edge removal")
	}
}

// TestMultiGraphIDempotentAdd: 重复 Add 不产生重复节点/边。
func TestMultiGraphIDempotentAdd(t *testing.T) {
	g := NewMultiGraph()
	g.AddNode("host-a", LayerNetwork, NodeHost, nil)
	g.AddNode("host-a", LayerNetwork, NodeHost, nil)
	g.AddNode("sub-1", LayerNetwork, NodeSubnet, nil)
	g.AddEdge("host-a", "sub-1", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("host-a", "sub-1", EdgeConnects, LayerNetwork, 1)

	if g.NodeCount() != 2 || g.EdgeCount() != 1 {
		t.Errorf("dup add must be idempotent: nodes=%d edges=%d", g.NodeCount(), g.EdgeCount())
	}
}

// TestRegistrySyncsMultiGraph: RecordTopology/DeleteTopology 自动同步 Network
// 层到全域图 (host + subnet 节点 + connects 边)。
func TestRegistrySyncsMultiGraph(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()
	// 全局图独立于 Registry 重置, 手动清理 Network 层测试数据。
	cleanGlobalGraph()

	RecordTopologyDetailed("host-a", []string{"10.0.0.0/24", "172.20.20.0/24"}, "internal")

	g := Graph()
	if g.GetNode("host-a") == nil {
		t.Fatal("host node must be synced to multi-graph")
	}
	if g.GetNode("subnet:10.0.0.0/24") == nil || g.GetNode("subnet:172.20.20.0/24") == nil {
		t.Fatal("subnet nodes must be synced")
	}
	if e := g.GetEdge("host-a", "subnet:10.0.0.0/24", EdgeConnects); e == nil {
		t.Error("host→subnet connects edge must exist")
	}
	if got := g.Neighbors("host-a", EdgeConnects); len(got) != 2 {
		t.Errorf("host neighbors = %v, want 2 subnets", got)
	}

	// 注销 → 全域图移除 host 及连带边。
	DeleteTopology("host-a")
	if g.GetNode("host-a") != nil {
		t.Error("host must be removed from multi-graph on delete")
	}
	if g.EdgeCount() != 0 {
		t.Errorf("edges touching removed host must be gone, left %d", g.EdgeCount())
	}
}

// cleanGlobalGraph removes all nodes from the global graph (test helper).
func cleanGlobalGraph() {
	g := Graph()
	for _, id := range g.QueryByLayer(LayerNetwork) {
		g.RemoveNode(id)
	}
}

// TestMultiGraphEdgeStatusAndMeta: 链路状态 (up/down, T18) 与属性 (T13/T14)。
func TestMultiGraphEdgeStatusAndMeta(t *testing.T) {
	g := NewMultiGraph()
	g.AddNode("r2", LayerNetwork, NodeHost, nil)
	g.AddNode("r3", LayerNetwork, NodeHost, nil)

	g.AddEdgeDetailed("r2", "r3", EdgeConnects, LayerNetwork, 1, "up", map[string]string{"delay_ms": "200", "bandwidth": "1g"})

	e := g.GetEdge("r2", "r3", EdgeConnects)
	if e.Status != "up" {
		t.Errorf("status = %s, want up", e.Status)
	}
	if e.Meta["delay_ms"] != "200" || e.Meta["bandwidth"] != "1g" {
		t.Errorf("meta = %v", e.Meta)
	}

	// 链路 down (T18 边动态变化)
	g.SetEdgeStatus("r2", "r3", EdgeConnects, "down")
	if e := g.GetEdge("r2", "r3", EdgeConnects); e.Status != "down" {
		t.Errorf("status after SetEdgeStatus = %s, want down", e.Status)
	}
	// 未知边 no-op
	g.SetEdgeStatus("r2", "r3", EdgeTargets, "down")
}

// TestMultiGraphReachability: ShortestPath/Reachable (T1 多跳 / T2 多路径)。
func TestMultiGraphReachability(t *testing.T) {
	g := NewMultiGraph()
	for _, n := range []string{"host-a", "r1", "r2", "r3", "host-b"} {
		g.AddNode(n, LayerNetwork, NodeHost, nil)
	}
	// host-a─r1─r2─r3─host-b (多跳) + r1─r3 直连 (短路径)
	g.AddEdge("host-a", "r1", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("r1", "r2", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("r2", "r3", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("r3", "host-b", EdgeConnects, LayerNetwork, 1)
	g.AddEdge("r1", "r3", EdgeConnects, LayerNetwork, 1)

	// 最短路径应走 host-a→r1→r3→host-b (3 跳, 非 4 跳)。
	path := g.ShortestPath("host-a", "host-b", EdgeConnects)
	want := []string{"host-a", "r1", "r3", "host-b"}
	if len(path) != len(want) {
		t.Fatalf("ShortestPath = %v, want %v", path, want)
	}
	for i := range want {
		if path[i] != want[i] {
			t.Fatalf("ShortestPath = %v, want %v", path, want)
		}
	}

	// 不可达 → nil。
	if p := g.ShortestPath("host-a", "nope", EdgeConnects); p != nil {
		t.Errorf("unreachable must be nil, got %v", p)
	}

	// Reachable 2 跳: r1(1跳) + r2,r3(2跳, 经 r1-r2 与 r1-r3 直连)。
	reach := g.Reachable("host-a", 2, EdgeConnects)
	want2 := []string{"r1", "r2", "r3"}
	if len(reach) != len(want2) {
		t.Fatalf("Reachable(2 hops) = %v, want %v", reach, want2)
	}
	for i := range want2 {
		if reach[i] != want2[i] {
			t.Fatalf("Reachable(2 hops) = %v, want %v", reach, want2)
		}
	}
	// 不限跳数 → 全部。
	if len(g.Reachable("host-a", 0, EdgeConnects)) != 4 {
		t.Errorf("Reachable(unlimited) = %v", g.Reachable("host-a", 0, EdgeConnects))
	}
}
