package kernel

import "github.com/asscor/asscor/internal/topology"

// 拓扑与传播层基础设施 — 微内核契约（M0 地基层）
//
// 本文件定义拓扑感知能力的微内核接口契约。类型定义在底层包
// internal/topology（kernel 已依赖该包，见 locator.go），此处只声明
// 接口，供 build-tag 可选模块实现与 kernel 侧消费，避免实现细节渗入
// 内核。契约先于实现落地，供社区基于接口演进（见
// docs/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md）。

// TopologyInterface 是拓扑感知能力的微内核契约。
//
// 实现约定：
//   - RecordTopologyDetailed 记录/更新节点的子网与区域（幂等，触发
//     node_added/node_updated 事件）；
//   - DeleteTopology 注销节点（触发 node_removed 事件，M1 生命周期核心）；
//   - GetTopology 返回当前全量节点子网快照（兼容现有 SRD 消费方）；
//   - ListNodes/GetNode 提供节点级查询；
//   - Subscribe 注册事件订阅，返回取消函数（多订阅者，替代单 listener）。
type TopologyInterface interface {
	RecordTopologyDetailed(hostID string, subnets []string, zone string)
	DeleteTopology(hostID string)
	GetTopology() map[string][]string
	GetNode(hostID string) *topology.TopoNode
	ListNodes() []*topology.TopoNode
	Subscribe(handler func(topology.TopoEvent)) func()
}
