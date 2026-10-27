//go:build engine

package srd

import (
	"sort"

	prismlib "github.com/chins-xing/prism"
)

// BuildEdges 按 SRD 的**真实边构造规则**生成整张拓扑的边集：
//
//	两个主机只有在**共享子网**时才连边（areConnected 的同一判定），
//	边的风险传输率按源主机 SSAM 分数加权（prismlib.WeightedTransmission）。
//
// 这个函数把"内部构边"exported 出来，是为了让实验/基准工具（cmd/srdbench、
// 离线复算）与 kernel 里 SRD 用的是**同一份规则**，避免"基准算一套、线上跑另一套"。
//
// 返回的是**有向边集合**（A→B 与 B→A 各一条），顺序按 pair 字典序遍历，
// 便于测试与稳定输出。
func (p *Pipeline) BuildEdges(allNodes map[string]*prismlib.NodeState) []prismlib.EdgeState {
	p.mu.RLock()
	topo := make(map[string]*TopologyInfo, len(p.topology))
	for k, v := range p.topology {
		topo[k] = v
	}
	transmission := p.cfg.DefaultTransmission
	p.mu.RUnlock()
	return BuildEdgesWithTopology(topo, allNodes, transmission)
}

// BuildEdgesWithTopology 是 BuildEdges 的纯函数版本（不依赖 Pipeline 实例），
// 供离线基准直接调用：给定 host→TopologyInfo 与节点集合，产出有向边集。
func BuildEdgesWithTopology(
	topology map[string]*TopologyInfo,
	allNodes map[string]*prismlib.NodeState,
	transmission float64,
) []prismlib.EdgeState {
	if transmission <= 0 {
		transmission = 0.1
	}
	ids := make([]string, 0, len(allNodes))
	for id := range allNodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	edges := make([]prismlib.EdgeState, 0, len(ids)*len(ids))
	for _, src := range ids {
		for _, dst := range ids {
			if src == dst {
				continue
			}
			if !topologyConnected(topology, src, dst) {
				continue
			}
			edges = append(edges, prismlib.EdgeState{
				Source:           src,
				Target:           dst,
				RiskTransmission: prismlib.WeightedTransmission(transmission, allNodes[src].SSAMScore),
			})
		}
	}
	return edges
}

// topologyConnected 与 Pipeline.areConnectedLocked 同一判定：
// 任一方缺拓扑数据时按"连通"处理（保守回退到完全图，保持向后兼容）。
func topologyConnected(topology map[string]*TopologyInfo, hostA, hostB string) bool {
	a, aOK := topology[hostA]
	b, bOK := topology[hostB]
	if !aOK || !bOK {
		return true
	}
	for _, sa := range a.Subnets {
		for _, sb := range b.Subnets {
			if subnetOverlap(sa, sb) {
				return true
			}
		}
	}
	return false
}
