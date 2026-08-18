package topology

import (
	"sort"
	"sync"
	"time"
)

// 全域拓扑感知基础设施 — Multi-layer Temporal Graph（M2）
//
// 定位：本包是**通用**的多层时序图基础设施，服务于 ASSCOR-Research-Core
// 的全部拓扑/传播/主动防御研究方向，而非某一本设计文档的实现。
//
// 支持性设计：
//   - 任意层/类型/属性：Layer/NodeType/EdgeType 为 string，预定义常量是
//     常用语义集（含主动防御白皮书 §5.3 六层与关系链），调用方可直接使用
//     任意自定义值，无需改动引擎；
//   - 时序：节点/边带 FirstSeen/LastSeen，节点含事件流（GraphEvent，
//     含置信度）——支撑时序推理（拓扑变化、证据累积）；
//   - 链路语义：边带 Status（up/down，链路生命周期）与 Meta（延迟/带宽/
//     ACL 等属性）——支撑拓扑语义审计（T13 链路类型、T14 安全边界、T18
//     边动态变化）；
//   - 可达性：ShortestPath/Reachable（BFS，可限定边类型）——支撑多跳/
//     多路径感知（T1/T2）；
//   - 传播：边带 Weight（风险加权系数，P1-1 已接入）——支撑 SRD 传播。
//
// 消费方分层：底层图引擎（本文件）通用；主动防御白皮书（Actor/TTP/
// Evidence）、拓扑传播（可达性/路径）、身份（User/Credential）、威胁情报
// 等模型均为上层消费方，通过预定义或自定义语义接入本图。
//
// 兼容性：原 Registry（host→subnets，Network 层子网重叠）保持兼容，
// MultiGraph 为全域视图，由上层引擎消费。

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

// GraphEdge 是全域图边（时序：FirstSeen/LastSeen + 权重 + 状态 + 属性）。
// Status 表达链路生命周期（up/down，T18 边动态变化）；Meta 承载链路属性
// （延迟/带宽/ACL 边界等，T13/T14）。
type GraphEdge struct {
	Source    string
	Target    string
	Type      EdgeType
	Layer     Layer
	FirstSeen time.Time
	LastSeen  time.Time
	Weight    float64
	Status    string // up | down | unknown
	Meta      map[string]string
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
// when either endpoint is missing (no dangling edges). Status defaults to
// "up"; meta may be nil.
func (g *MultiGraph) AddEdge(source, target string, typ EdgeType, layer Layer, weight float64) bool {
	return g.AddEdgeDetailed(source, target, typ, layer, weight, "up", nil)
}

// AddEdgeDetailed inserts or updates an edge with status and attributes.
func (g *MultiGraph) AddEdgeDetailed(source, target string, typ EdgeType, layer Layer, weight float64, status string, meta map[string]string) bool {
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
	if status != "" {
		e.Status = status
	}
	if len(meta) > 0 {
		if e.Meta == nil {
			e.Meta = make(map[string]string)
		}
		for k, v := range meta {
			e.Meta[k] = v
		}
	}
	return true
}

// SetEdgeStatus updates an edge's lifecycle status (up/down) — the primitive
// for link-state changes (audit T18: edges must react to link flapping).
// Unknown edges are a no-op.
func (g *MultiGraph) SetEdgeStatus(source, target string, typ EdgeType, status string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.edges[edgeKey(source, target, typ)]
	if !ok {
		return
	}
	e.Status = status
	e.LastSeen = time.Now()
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

// ShortestPath returns the node sequence of the shortest unweighted path
// between from and to (BFS, direction-insensitive), optionally restricted to
// a single edge type. Returns nil when no path exists. Empty typ matches all
// edge types.
func (g *MultiGraph) ShortestPath(from, to string, typ EdgeType) []string {
	if from == to {
		return []string{from}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	prev := make(map[string]string)
	visited := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nb := range g.adjacentLocked(cur, typ) {
			if visited[nb] {
				continue
			}
			visited[nb] = true
			prev[nb] = cur
			if nb == to {
				return rebuildPath(prev, from, to)
			}
			queue = append(queue, nb)
		}
	}
	return nil
}

// Reachable returns all nodes reachable from start within maxHops (BFS depth
// limit, direction-insensitive), optionally restricted to an edge type.
// maxHops <= 0 means unlimited. The result excludes the start node and is
// sorted for determinism.
func (g *MultiGraph) Reachable(start string, maxHops int, typ EdgeType) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	seen := map[string]bool{start: true}
	queue := []string{start}
	hops := map[string]int{start: 0}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if maxHops > 0 && hops[cur] >= maxHops {
			continue
		}
		for _, nb := range g.adjacentLocked(cur, typ) {
			if seen[nb] {
				continue
			}
			seen[nb] = true
			hops[nb] = hops[cur] + 1
			queue = append(queue, nb)
		}
	}
	delete(seen, start)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// adjacentLocked returns neighbors of id via edges of the given type
// (empty typ = all). Caller must hold g.mu (R or W).
func (g *MultiGraph) adjacentLocked(id string, typ EdgeType) []string {
	var out []string
	for _, e := range g.edges {
		if typ != "" && e.Type != typ {
			continue
		}
		if e.Source == id {
			out = append(out, e.Target)
		}
		if e.Target == id {
			out = append(out, e.Source)
		}
	}
	return out
}

// rebuildPath reconstructs the from→to path from BFS predecessor map.
func rebuildPath(prev map[string]string, from, to string) []string {
	path := []string{to}
	for cur := to; cur != from; {
		p, ok := prev[cur]
		if !ok {
			return nil
		}
		path = append(path, p)
		cur = p
	}
	// reverse
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
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
