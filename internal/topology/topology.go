package topology

import (
	"net"
	"sync"
	"time"
	"strings"

)

// 拓扑与传播层基础设施 — 地基层（M0）
//
// 本包是拓扑感知能力的底层数据模型与实现（零依赖，被 kernel 与插件
// 消费）：类型定义 (TopoNode/TopoEdge/TopoEvent) 与 Registry 实现。
// kernel 侧只持有引用本包类型的 TopologyInterface 契约（微内核边界），
// 见 internal/kernel/topo_types.go。

// TopoEventType 描述拓扑状态变化的事件类别。事件是生命周期（M1）的
// 核心载体：节点注册/更新/注销、链路 up/down 均以事件形式发布。
type TopoEventType string

const (
	TopoNodeAdded   TopoEventType = "node_added"
	TopoNodeUpdated TopoEventType = "node_updated"
	TopoNodeRemoved TopoEventType = "node_removed"
	TopoLinkUp      TopoEventType = "link_up"
	TopoLinkDown    TopoEventType = "link_down"
	TopoLinkAdded   TopoEventType = "link_added"
	TopoLinkRemoved TopoEventType = "link_removed"
)

// TopoNode 是拓扑图中的节点模型：一台被纳入拓扑感知的主机/资产。
// Subnets 为该节点上报的可达子网（CIDR）；Zone 为安全区域
// （internal/dmz/public/...）；Status 为节点生命周期状态。
type TopoNode struct {
	HostID  string
	Subnets []string
	Zone    string
	Status  string // active | inactive | removed

	// 以下是 SRD 分层图所需的事实（来自 agent 心跳的 NetworkInfo）。
	// VLANs 为空 = L2 未知；Policies 为空且 PolicyKnown=false = L4 未知。
	VLANs       []string
	Forwards    bool // 是否真的转发（ip_forward=1）
	Policies    []TopoPolicyRule
	PolicyKnown bool
	Links       []TopoLink // L1：接口状态与所属子网
	IPs         []string   // v2.3 T1：主机地址（/32 主机级 ACL 匹配用）
	// v2.3 T2：链内存在 ct state established,related accept。
	StatefulInput  bool
	StatefulOutput bool
}

// TopoLink 是一条链路事实（L1）。
type TopoLink struct {
	Name    string
	Up      bool
	Subnets []string
	VLANs   []string
}

// TopoPolicyRule 是一条 L4 策略结论（按源/目的 CIDR）。
// Direction=="inbound" 表示主机入向策略（域内/主机级 ACL），空或 "forward" 表示转发策略。
type TopoPolicyRule struct {
	From      string
	To        string
	Allow     bool
	Direction string
}

// TopoEdge 是拓扑图中的边模型（链路）。M0 仅定义类型；边的实际构建
// （从可达性/路由推导）属于 M1/M2 语义层。Directed 表达非对称可达性，
// Weight/LinkType 承载链路质量与类型（延迟/带宽/ACL 边界等）。
type TopoEdge struct {
	Source   string
	Target   string
	Directed bool
	Weight   float64
	LinkType string
	Status   string // up | down
}

// TopoEvent 是一次拓扑状态变化的事件载荷。At 为事件发生时间。
type TopoEvent struct {
	Type    TopoEventType
	HostID  string
	Subnets []string
	Zone    string
	Status  string
	At      time.Time
}

// Registry is the shared network topology store used by the heartbeat handler
// (writer) and the SRD plugin (reader) to build real risk-diffusion edges.
//
// M0 地基层: 在原有 "hostID → subnets" 快照之上, 增加节点模型、注销
// (DeleteTopology) 与多订阅者事件 (Subscribe)。原有 RecordTopology/
// GetTopology/SetTopologyListener 保持兼容, 现有消费方 (comms/SRD/locator)
// 无需修改。
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*TopoNode

	// 单 listener 兼容层 (SetTopologyListener) 转成内部订阅。
	listeners map[uint64]func(TopoEvent)
	nextID    uint64
}

var globalTopology = &Registry{
	nodes:     make(map[string]*TopoNode),
	listeners: make(map[uint64]func(TopoEvent)),
}

// record stores/updates a node and publishes the appropriate event.
func (r *Registry) record(hostID string, subnets []string, zone string) {
	subnets = normalizeSubnets(subnets)
	now := time.Now()
	evType := TopoNodeAdded

	r.mu.Lock()
	if n, ok := r.nodes[hostID]; ok {
		evType = TopoNodeUpdated
		n.Subnets = append([]string(nil), subnets...)
		if zone != "" {
			n.Zone = zone
		}
		n.Status = "active"
	} else {
		r.nodes[hostID] = &TopoNode{
			HostID:  hostID,
			Subnets: append([]string(nil), subnets...),
			Zone:    zone,
			Status:  "active",
		}
	}
	ev := TopoEvent{
		Type:    evType,
		HostID:  hostID,
		Subnets: append([]string(nil), subnets...),
		Zone:    zone,
		Status:  "active",
		At:      now,
	}
	handlers := r.snapshotHandlers()
	r.mu.Unlock()

	// M2 全域图同步: 将 Network 层节点/边写入 MultiGraph (host + subnets,
	// host─connects→subnet)。Identity/Attacker/Capability/Evidence 层由
	// 后续引擎写入。消费方零改动 (comms/SRD 继续用 Registry)。
	syncNetworkToGraph(hostID, subnets, zone)

	r.fire(handlers, ev)
}

// syncNetworkToGraph mirrors a Registry node into the global MultiGraph's
// Network layer: the host node plus one subnet node and a connects edge per
// subnet. Never panics and never affects Registry behaviour.
func syncNetworkToGraph(hostID string, subnets []string, zone string) {
	g := globalMultiGraph
	g.AddNode(hostID, LayerNetwork, NodeHost, map[string]string{"zone": zone})
	for _, s := range subnets {
		subnetID := "subnet:" + s
		g.AddNode(subnetID, LayerNetwork, NodeSubnet, map[string]string{"cidr": s})
		g.AddEdge(hostID, subnetID, EdgeConnects, LayerNetwork, 1)
	}
}

// delete removes a node and publishes node_removed. Deleting an unknown host
// is a no-op (no spurious event).
func (r *Registry) delete(hostID string) {
	r.mu.Lock()
	n, ok := r.nodes[hostID]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.nodes, hostID)
	ev := TopoEvent{
		Type:    TopoNodeRemoved,
		HostID:  hostID,
		Subnets: append([]string(nil), n.Subnets...),
		Zone:    n.Zone,
		Status:  "removed",
		At:      time.Now(),
	}
	handlers := r.snapshotHandlers()
	r.mu.Unlock()

	// M2 全域图同步: 注销节点从 MultiGraph 移除 (连带其 subnet 节点与边)。
	globalMultiGraph.RemoveNode(hostID)

	r.fire(handlers, ev)
}

// snapshotHandlers returns the current handler list. Call with r.mu held.
func (r *Registry) snapshotHandlers() []func(TopoEvent) {
	out := make([]func(TopoEvent), 0, len(r.listeners))
	for _, h := range r.listeners {
		out = append(out, h)
	}
	return out
}

// fire dispatches an event to all handlers without holding the lock.
func (r *Registry) fire(handlers []func(TopoEvent), ev TopoEvent) {
	for _, h := range handlers {
		h(ev)
	}
}

// --- 兼容 API (原签名, 消费方无需修改) ---

// RecordTopology stores a host's subnets for SRD real-edge construction and
// notifies subscribers (the SRD plugin) so the pipeline updates in real time.
// Zone is left empty when unknown (compat behavior).
func RecordTopology(hostID string, subnets []string) {
	globalTopology.record(hostID, subnets, "")
}

// GetTopology returns a deep copy of all host subnets.
func GetTopology() map[string][]string {
	globalTopology.mu.RLock()
	defer globalTopology.mu.RUnlock()
	out := make(map[string][]string, len(globalTopology.nodes))
	for k, v := range globalTopology.nodes {
		out[k] = append([]string(nil), v.Subnets...)
	}
	return out
}

// SetTopologyListener registers a single callback fired on every topology
// update (legacy API; new subscribers should use Subscribe). Setting a new
// listener replaces the previous one.
func SetTopologyListener(cb func(hostID string, subnets []string)) {
	globalTopology.mu.Lock()
	globalTopology.listeners = make(map[uint64]func(TopoEvent))
	globalTopology.nextID = 1
	globalTopology.listeners[1] = func(ev TopoEvent) {
		cb(ev.HostID, ev.Subnets)
	}
	globalTopology.mu.Unlock()
}

// --- M0 地基层 API ---

// RecordNetworkFacts 记录一台主机的**完整网络事实**（L2/L3/L4），
// 供 SRD 分层图使用。缺失的层保持零值 = 未知（不是"放行"）。
func RecordNetworkFacts(hostID string, subnets []string, zone string,
	vlans []string, forwards bool, policies []TopoPolicyRule, policyKnown bool, links []TopoLink,
	ips []string, statefulInput, statefulOutput bool) {
	globalTopology.recordNetworkFacts(hostID, subnets, zone, vlans, forwards, policies, policyKnown, links, ips, statefulInput, statefulOutput)
}

func (r *Registry) recordNetworkFacts(hostID string, subnets []string, zone string,
	vlans []string, forwards bool, policies []TopoPolicyRule, policyKnown bool, links []TopoLink, ips []string,
	statefulInput, statefulOutput bool) {
	r.record(hostID, subnets, zone)
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[hostID]
	if !ok {
		return
	}
	n.VLANs = append([]string(nil), vlans...)
	n.Forwards = forwards
	n.Policies = append([]TopoPolicyRule(nil), policies...)
	n.PolicyKnown = policyKnown
	n.Links = append([]TopoLink(nil), links...)
	n.IPs = append([]string(nil), ips...)
	n.StatefulInput = statefulInput
	n.StatefulOutput = statefulOutput
}

// BuildLayeredFromRegistry 用当前注册表构造 SRD 分层图：
//   - 主机事实：子网（L3）、VLAN（L2，可为空）、是否转发（L3）；
//   - 策略：所有主机上报的 L4 规则合并；任一主机采集到即视为"策略已知"。
//
// 返回 nil 表示注册表为空（调用方应回退到旧模型）。
func BuildLayeredFromRegistry() *LayeredGraph {
	globalTopology.mu.RLock()
	defer globalTopology.mu.RUnlock()
	if len(globalTopology.nodes) == 0 {
		return nil
	}
	hosts := make([]HostFacts, 0, len(globalTopology.nodes))
	var policies []PolicyRule
	policyKnown := false
	for _, n := range globalTopology.nodes {
		hf := HostFacts{
			HostID:   n.HostID,
			Subnets:  append([]string(nil), n.Subnets...),
			VLANs:    append([]string(nil), n.VLANs...),
			Zone:     n.Zone,
			Forwards: n.Forwards,
			Links:    map[string]bool{},
			IPs:      append([]string(nil), n.IPs...),
			StatefulInput: n.StatefulInput,
		}
		for _, l := range n.Links {
			for _, s := range l.Subnets {
				// 同一子网多个接口时：任一条 up 即视为该子网链路可用
				hf.Links[s] = hf.Links[s] || l.Up
			}
		}
		for _, p := range n.Policies {
			switch p.Direction {
			case "inbound":
				hf.Inbound = append(hf.Inbound, PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
			case "outbound":
				hf.Outbound = append(hf.Outbound, PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
			default:
				policies = append(policies, PolicyRule{From: p.From, To: p.To, Allow: p.Allow})
			}
		}
		hosts = append(hosts, hf)
		if n.PolicyKnown {
			policyKnown = true
		}
	}
	return BuildLayeredGraph(hosts, policies, policyKnown, true)
}

// RecordTopologyDetailed// RecordTopologyDetailed records a node with zone. Publishes node_added (new)
// or node_updated (existing).
func RecordTopologyDetailed(hostID string, subnets []string, zone string) {
	globalTopology.record(hostID, subnets, zone)
}

// DeleteTopology removes a node from the topology and publishes node_removed.
// This is the missing lifecycle primitive (audit P0-1/T17: previously a
// removed host kept propagating risk forever).
func DeleteTopology(hostID string) {
	globalTopology.delete(hostID)
}

// GetNode returns a deep copy of a node, or nil when unknown.
func GetNode(hostID string) *TopoNode {
	globalTopology.mu.RLock()
	defer globalTopology.mu.RUnlock()
	n, ok := globalTopology.nodes[hostID]
	if !ok {
		return nil
	}
	cp := *n
	cp.Subnets = append([]string(nil), n.Subnets...)
	return &cp
}

// ListNodes returns deep copies of all nodes, sorted by HostID.
func ListNodes() []*TopoNode {
	globalTopology.mu.RLock()
	nodes := make([]*TopoNode, 0, len(globalTopology.nodes))
	for _, n := range globalTopology.nodes {
		cp := *n
		cp.Subnets = append([]string(nil), n.Subnets...)
		nodes = append(nodes, &cp)
	}
	globalTopology.mu.RUnlock()

	// Stable order for determinism.
	for i := 1; i < len(nodes); i++ {
		for j := i; j > 0 && nodes[j-1].HostID > nodes[j].HostID; j-- {
			nodes[j-1], nodes[j] = nodes[j], nodes[j-1]
		}
	}
	return nodes
}

// Subscribe registers an event handler and returns an unsubscribe function.
// Multiple subscribers are supported (the legacy single-listener API is a
// thin compatibility shim over this).
func Subscribe(handler func(TopoEvent)) func() {
	globalTopology.mu.Lock()
	globalTopology.nextID++
	id := globalTopology.nextID
	globalTopology.listeners[id] = handler
	globalTopology.mu.Unlock()

	return func() {
		globalTopology.mu.Lock()
		delete(globalTopology.listeners, id)
		globalTopology.mu.Unlock()
	}
}

// ResetForTesting clears all state and listeners (test helper / injector
// foundation).
func ResetForTesting() {
	globalTopology.mu.Lock()
	globalTopology.nodes = make(map[string]*TopoNode)
	globalTopology.listeners = make(map[uint64]func(TopoEvent))
	globalTopology.nextID = 0
	globalTopology.mu.Unlock()
}

// FilterExcludedSubnets returns the subnets that do not overlap any of the
// excluded CIDRs (M1 网段过滤, audit P0-2/T4: management/virtual networks
// must not make every host appear same-subnet reachable). Invalid entries in
// either list are ignored (kept / not treated as exclusions).
func FilterExcludedSubnets(subnets, excludes []string) []string {
	if len(excludes) == 0 {
		return subnets
	}
	exclNets := make([]*net.IPNet, 0, len(excludes))
	for _, e := range excludes {
		if _, n, err := net.ParseCIDR(e); err == nil {
			exclNets = append(exclNets, n)
		}
	}
	if len(exclNets) == 0 {
		return subnets
	}
	out := make([]string, 0, len(subnets))
	for _, s := range subnets {
		_, sn, err := net.ParseCIDR(s)
		if err != nil {
			out = append(out, s) // keep invalid entries
			continue
		}
		excluded := false
		for _, en := range exclNets {
			if subnetOverlapCIDR(sn, en) {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, s)
		}
	}
	return out
}

// subnetOverlapCIDR reports whether two parsed networks overlap.
func subnetOverlapCIDR(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}


// normalizeSubnets 把子网统一成网络地址形式（v2.3.7 / T4 修复）。
//
// 真实 agent 可能上报 "172.23.10.101/24"（带主机位）或裸 IP；路由器侧是
// "172.23.10.0/24"。不规范化会导致同一子网被当成两个不同子网，路径被判 probable。
func normalizeSubnets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			s = n.String()
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
