//go:build engine

package srd

import (
	"sort"

	"github.com/chins-xing/asscor/internal/topology"
	prismlib "github.com/chins-xing/prism"
)

// BuildEdges 按 SRD 的**真实边构造规则**生成整张拓扑的边集：
//
//	两个主机只有在**共享子网**时才连边（areConnected 的同一判定），
//	边的风险传输率按源主机 SSAM 分数加权（prismlib.WeightedTransmission）。
//
// 开启 `cfg.LayeredGraph` 且注入了分层图时，改走 buildLayeredEdges：
// 额外用 L4 策略过滤"路由器跨到被阻断子网"的边（c2 类误报的修复点）。
//
// 这个函数把"内部构边"exported 出来，是为了让实验/基准工具（cmd/srdbench、
// 离线复算）与 kernel 里 SRD 用的是**同一份规则**，避免"基准算一套、线上跑另一套"。
//
// 返回的是**有向边集合**（A→B 与 B→A 各一条），顺序按 pair 字典序遍历，
// 便于测试与稳定输出。
func (p *Pipeline) BuildEdges(allNodes map[string]*prismlib.NodeState) []prismlib.EdgeState {
	p.mu.RLock()
	layered := p.layered
	transmission := p.cfg.DefaultTransmission
	useLayered := p.cfg.LayeredGraph && layered != nil
	var topo map[string]*TopologyInfo
	if !useLayered {
		topo = make(map[string]*TopologyInfo, len(p.topology))
		for k, v := range p.topology {
			topo[k] = v
		}
	}
	p.mu.RUnlock()

	if useLayered {
		return p.buildLayeredEdges(layered, allNodes, transmission)
	}
	return BuildEdgesWithTopology(topo, allNodes, transmission)
}

// SetLayeredGraph 注入分层图（srdwrapper 在拓扑事件后重建并调用）。
func (p *Pipeline) SetLayeredGraph(lg *topology.LayeredGraph) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.layered = lg
}

// buildLayeredEdges 用分层图构造边：
//   - 两台主机共享子网才连边（L3/L2 邻接）；
//   - 若**源**主机是转发者（路由器），还要求 L4 允许"从它的其它子网跨到这条边所在子网"
//     —— 这条规则把"策略阻断的跨域传播"从边集里拿掉（c2 类误报的修复点）。
func (p *Pipeline) buildLayeredEdges(lg *topology.LayeredGraph, allNodes map[string]*prismlib.NodeState, transmission float64) []prismlib.EdgeState {
	if transmission <= 0 {
		transmission = 0.1
	}
	ids := make([]string, 0, len(allNodes))
	for id := range allNodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	edges := make([]prismlib.EdgeState, 0, len(ids)*2)
	for _, src := range ids {
		for _, dst := range ids {
			if src == dst {
				continue
			}
			shared := lg.SharedSubnets(src, dst)
			if len(shared) == 0 {
				continue
			}
			if lg.Forwards(src) {
				permitted := false
				for _, sub := range shared {
					if lg.CrossingPermitted(src, sub) {
						permitted = true
						break
					}
				}
				if !permitted {
					continue
				}
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
