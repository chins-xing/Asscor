//go:build engine

package srd

import (
	"testing"

	prismlib "github.com/chins-xing/prism"

	"github.com/chins-xing/asscor/internal/topology"
)

// TestBuildEdgesLayeredDropsPolicyBlockedCrossing 钉住生产构边的修复点：
// 路由器同时属于 A/B 两子网，但 L4 明确 deny A→B 时，
// 路由器到 B 的边必须消失 —— 否则风险会沿 A→router→B 传播（c2 类误报）。
func TestBuildEdgesLayeredDropsPolicyBlockedCrossing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LayeredGraph = true
	p := NewPipelineWithEngine(cfg, nil)

	hosts := []topology.HostFacts{
		{HostID: "A-web", Subnets: []string{"172.22.10.0/24"}},
		{HostID: "B-web", Subnets: []string{"172.23.10.0/24"}},
		{HostID: "router", Subnets: []string{"172.22.10.0/24", "172.23.10.0/24"}, Forwards: true},
	}
	lg := topology.BuildLayeredGraph(hosts, []topology.PolicyRule{
		{From: "172.22.10.0/24", To: "172.23.10.0/24", Allow: false},
		{From: "172.23.10.0/24", To: "172.22.10.0/24", Allow: false},
	}, true, true)
	p.SetLayeredGraph(lg)

	nodes := map[string]*prismlib.NodeState{
		"A-web":  {HostID: "A-web", SSAMScore: 50},
		"B-web":  {HostID: "B-web", SSAMScore: 50},
		"router": {HostID: "router", SSAMScore: 50},
	}
	edges := p.BuildEdges(nodes)

	has := func(src, dst string) bool {
		for _, e := range edges {
			if e.Source == src && e.Target == dst {
				return true
			}
		}
		return false
	}

	if !has("A-web", "router") {
		t.Fatal("A-web→router 应保留（同子网）")
	}
	if has("router", "B-web") {
		t.Fatal("策略 deny A→B 时，router→B-web 的边必须被过滤掉")
	}
	// 任何从 A 侧到 B 侧的直达边都不应存在
	if has("A-web", "B-web") {
		t.Fatal("A-web→B-web 跨子网无边")
	}
}

// TestBuildEdgesLayeredAllowsWhenNoPolicy 未知策略时不应误删边（保持保守：保留）。
func TestBuildEdgesLayeredAllowsWhenNoPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LayeredGraph = true
	p := NewPipelineWithEngine(cfg, nil)

	hosts := []topology.HostFacts{
		{HostID: "A", Subnets: []string{"10.1.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.2.0.0/24"}},
		{HostID: "r", Subnets: []string{"10.1.0.0/24", "10.2.0.0/24"}, Forwards: true},
	}
	p.SetLayeredGraph(topology.BuildLayeredGraph(hosts, nil, false, true))
	nodes := map[string]*prismlib.NodeState{
		"A": {HostID: "A", SSAMScore: 50},
		"B": {HostID: "B", SSAMScore: 50},
		"r": {HostID: "r", SSAMScore: 50},
	}
	edges := p.BuildEdges(nodes)
	found := false
	for _, e := range edges {
		if e.Source == "r" && e.Target == "B" {
			found = true
		}
	}
	if !found {
		t.Fatal("无策略数据时 router→B 边应保留（未知不删边，由上层判 probable）")
	}
}
