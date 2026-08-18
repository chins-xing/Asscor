package topology

import (
	"sort"
	"sync"
	"time"
)

// 全域拓扑感知基础设施 — Multi-layer Temporal Graph（M2）
//
// 按《主动防御设计白皮书》(docs/ASSCOR-Research-Core/主动防御设计白皮书.md
// §5.3) 的模型：单纯 Host─connects─Host 不足以描述攻击者/身份/工具/代码/
// TTP/证据，建立 6 层时序图：
//
//	Network / Dependency / Identity / Attacker / Capability / Evidence
//
// 关系链如 ATTACKER─uses→TOOL─implements→TTP─produces→ACTION─produces→
// OBSERVATION→EVIDENCE，支持计算 Capability Centrality / TTP Sharedness /
// Actor Similarity 等。
//
// 本文件是图基础设施（类型 + 存储 + 查询 + 时序），不改变现有传播行为：
// 原 Registry（host→subnets，Network 层子网重叠）保持兼容，MultiGraph 为
// 全域视图，由后续 State/Prediction Engine 消费。

// Layer 是图的语义分层（白皮书 §5.3 六层）。
type Layer string

const (
	LayerNetwork    Layer = "network"    // Host/Service/Subnet/Gateway/Internet
	LayerDependency Layer = "dependency" // Service→Service
	LayerIdentity   Layer = "identity"   // User/Account/Credential/Role/Privilege
	LayerAttacker   Layer = "attacker"   // Actor/ActorCluster/Campaign/Infrastructure
	LayerCapability Layer = "capability" // Tool/Code/TTP/Exploit/AI Capability
	LayerEvidence   Layer = "evidence"   // Observation/Event/Alert/DecoyTrigger/Incident
)

// NodeType 是节点语义类型（按层归类，白皮书 §5.3）。
type NodeType string

const (
	// Network 层
	NodeHost      NodeType = "host"
	NodeService   NodeType = "service"
	NodeSubnet    NodeType = "subnet"
	NodeGateway   NodeType = "gateway"
	NodeInternet  NodeType = "internet"
	// Dependency 层
	NodeDependency NodeType = "dependency"
	// Identity 层
	NodeUser       NodeType = "user"
	NodeAccount    NodeType = "account"
	NodeCredential NodeType = "credential"
	NodeRole       NodeType = "role"
	NodePrivilege  NodeType = "privilege"
	// Attacker 层
	NodeActor        NodeType = "actor"
	NodeActorCluster NodeType = "actor_cluster"
	NodeCampaign     NodeType = "campaign"
	NodeInfra        NodeType = "infrastructure"
	// Capability 层
	NodeTool        NodeType = "tool"
	NodeCode        NodeType = "code"
	NodeTTP         NodeType = "ttp"
	NodeExploit     NodeType = "exploit"
	NodeAICapability NodeType = "ai_capability"
	// Evidence 层
	NodeObservation  NodeType = "observation"
	NodeEvent        NodeType = "event"
	NodeAlert        NodeType = "alert"
	NodeDecoyTrigger NodeType = "decoy_trigger"
	NodeIncident     NodeType = "incident"
)

// EdgeType 是边语义类型（白皮书关系链）。
type EdgeType string

const (
	EdgeConnects   EdgeType = "connects"    // Host─connects→Subnet/Service (Network)
	EdgeDependsOn  EdgeType = "depends_on"  // Service→Service (Dependency)
	EdgeBelongsTo  EdgeType = "belongs_to"  // 归属 (User→Role, Tool→Actor...)
	EdgeUses       EdgeType = "uses"        // ATTACKER─uses→TOOL
	EdgeImplements EdgeType = "implements"  // TOOL─implements→TTP
	EdgeProduces   EdgeType = "produces"    // TTP─produces→ACTION/OBSERVATION
	EdgeExecutes   EdgeType = "executes"    // ACTOR─executes→ACTION
	EdgeTargets    EdgeType = "targets"     // ACTOR─targets→Host
	EdgeObservedAt EdgeType = "observed_at" // EVIDENCE─observed_at→Host
)

// GraphEvent 是节点上的时序事件（白皮书 Evidence 字段子集：观察/告警/诱饵
// 触发等，带时间与置信度）。
type GraphEvent struct {
	Type       string    `json:"type"`
	At         time.Time `json:"at"`
	Detail     string    `json:"detail,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
}

// GraphNode 是全域图节点（时序：FirstSeen/LastSeen + 事件流）。
type GraphNode struct {
	ID        string
	Layer     Layer
	Type      NodeType
	Meta      map[string]string
	FirstSeen time.Time
	LastSeen  time.Time
	Events    []GraphEvent
}

// GraphEdge 是全域图边（时序：FirstSeen/LastSeen + 权重）。
type GraphEdge struct {
	Source    string
	Target    string
	Type      EdgeType
	Layer     Layer
	FirstSeen time.Time
	LastSeen  time.Time
	Weight    float64
}

// edgeKey builds a stable map key for an edge.
func edgeKey(source, target string, typ EdgeType) string {
	return source + "\x00" + string(typ) + "\x00" + target
}

// MultiGraph 是全域分层时序图存储。
//
// 基础设施约定：
//   - 节点/边按 ID/键唯一；重复 Add 视为更新（LastSeen 刷新，不重复插入）；
//   - 分层与类型索引便于按层/按类型查询；
//   - 与现有 Registry 解耦：MultiGraph 是全域视图，Registry 保留 Network
//     层子网重叠逻辑（SRD 消费方零改动）。
type MultiGraph struct {
	mu    sync.RWMutex
	nodes map[string]*GraphNode
	edges map[string]*GraphEdge

	byLayer map[Layer]map[string]bool
	byType  map[NodeType]map[string]bool
}

// NewMultiGraph creates an empty multi-layer graph.
func NewMultiGraph() *MultiGraph {
	return &MultiGraph{
		nodes:   make(map[string]*GraphNode),
		edges:   make(map[string]*GraphEdge),
		byLayer: make(map[Layer]map[string]bool),
		byType:  make(map[NodeType]map[string]bool),
	}
}

// AddNode inserts or updates a node. Existing nodes keep FirstSeen, refresh
// LastSeen, and merge Meta (new keys win).
func (g *MultiGraph) AddNode(id string, layer Layer, typ NodeType, meta map[string]string) *GraphNode {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	n, ok := g.nodes[id]
	if !ok {
		n = &GraphNode{ID: id, Layer: layer, Type: typ, FirstSeen: now}
		g.nodes[id] = n
		if g.byLayer[layer] == nil {
			g.byLayer[layer] = make(map[string]bool)
		}
		g.byLayer[layer][id] = true
		if g.byType[typ] == nil {
			g.byType[typ] = make(map[string]bool)
		}
		g.byType[typ][id] = true
	}
	n.LastSeen = now
	if len(meta) > 0 {
		if n.Meta == nil {
			n.Meta = make(map[string]string)
		}
		for k, v := range meta {
			n.Meta[k] = v
		}
	}
	return n
}

// RemoveNode deletes a node and all edges touching it.
func (g *MultiGraph) RemoveNode(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	n, ok := g.nodes[id]
	if !ok {
		return
	}
	delete(g.nodes, id)
	if s := g.byLayer[n.Layer]; s != nil {
		delete(s, id)
	}
	if s := g.byType[n.Type]; s != nil {
		delete(s, id)
	}
	// 删除与该节点相连的所有边。
	for k, e := range g.edges {
		if e.Source == id || e.Target == id {
			delete(g.edges, k)
		}
	}
}

// GetNode returns a node copy (deep-ish: Meta/Events copied), or nil.
func (g *MultiGraph) GetNode(id string) *GraphNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok {
		return nil
	}
	cp := *n
	if n.Meta != nil {
		cp.Meta = make(map[string]string, len(n.Meta))
		for k, v := range n.Meta {
			cp.Meta[k] = v
		}
	}
	cp.Events = append([]GraphEvent(nil), n.Events...)
	return &cp
}

// AddEdge inserts or updates an edge between two existing nodes. Returns false
// when either endpoint is missing (no dangling edges).
func (g *MultiGraph) AddEdge(source, target string, typ EdgeType, layer Layer, weight float64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[source]; !ok {
		return false
	}
	if _, ok := g.nodes[target]; !ok {
		return false
	}
	now := time.Now()
	key := edgeKey(source, target, typ)
	e, ok := g.edges[key]
	if !ok {
		e = &GraphEdge{Source: source, Target: target, Type: typ, Layer: layer, FirstSeen: now}
		g.edges[key] = e
	}
	e.LastSeen = now
	if weight > 0 {
		e.Weight = weight
	}
	return true
}

// RemoveEdge deletes an edge. Unknown edges are a no-op.
func (g *MultiGraph) RemoveEdge(source, target string, typ EdgeType) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.edges, edgeKey(source, target, typ))
}

// GetEdge returns an edge copy, or nil.
func (g *MultiGraph) GetEdge(source, target string, typ EdgeType) *GraphEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.edges[edgeKey(source, target, typ)]
	if !ok {
		return nil
	}
	cp := *e
	return &cp
}

// AppendEvent records an event on a node (temporal evidence stream).
// Unknown nodes are a no-op.
func (g *MultiGraph) AppendEvent(id string, ev GraphEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	if !ok {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	n.Events = append(n.Events, ev)
	n.LastSeen = ev.At
}

// QueryByLayer returns node IDs in a layer (sorted, deterministic).
func (g *MultiGraph) QueryByLayer(layer Layer) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids := make([]string, 0, len(g.byLayer[layer]))
	for id := range g.byLayer[layer] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// QueryByType returns node IDs of a type (sorted, deterministic).
func (g *MultiGraph) QueryByType(typ NodeType) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids := make([]string, 0, len(g.byType[typ]))
	for id := range g.byType[typ] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Neighbors returns node IDs directly connected to id (optionally filtered by
// edge type). Direction-insensitive: both outgoing and incoming edges count.
func (g *MultiGraph) Neighbors(id string, typ EdgeType) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	seen := make(map[string]bool)
	for _, e := range g.edges {
		if typ != "" && e.Type != typ {
			continue
		}
		if e.Source == id {
			seen[e.Target] = true
		}
		if e.Target == id {
			seen[e.Source] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// NodeCount / EdgeCount for observability.
func (g *MultiGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func (g *MultiGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// globalMultiGraph 是全域分层时序图的全局实例。原 Registry（host→subnets）
// 在 record/delete 时同步 Network 层节点/边到本图，使全域图自动获得网络
// 视图数据；Identity/Attacker/Capability/Evidence 层由后续 State/Evidence
// 引擎写入。消费方通过 Graph() 访问。
var globalMultiGraph = NewMultiGraph()

// Graph returns the global multi-layer temporal graph.
func Graph() *MultiGraph {
	return globalMultiGraph
}
