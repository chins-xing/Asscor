package topology

import (
	"net"
	"sort"
	"strings"
)

// 本文件实现 SRD 的**分层拓扑图**（quasi-3D multi-layer graph，设计见
// docs/1-current/design/SRD_LAYERED_GRAPH_DESIGN_2026-10-27.md）。
//
// 与 multigraph.go 的区别：那是"本体层"（网络/依赖/身份/攻陷/能力/证据），
// 本文件是**网络可达性语义层**：每一层只表达一件事，语义互不重复：
//
//	L1 link       链路/端口是否存在
//	L2 broadcast  同一二层广播域（VLAN）能否直接通信
//	L3 routed     三层地址与路由（主机∈子网、网关跨子网）
//	L4 policy     策略是否放行（ACL/NAT 边界）
//	L5 asset      资产角色与关键性
//
// 同一主机 ID 在多层各有一个"位置节点"（key = layer + "/" + id），
// 通过 same_identity 边互指 —— 这就是"一个节点同时存在于多张图中"。

// LayerKind 是网络可达性语义层。
type LayerKind string

const (
	LayerLink      LayerKind = "link"
	LayerBroadcast LayerKind = "broadcast"
	LayerRouted    LayerKind = "routed"
	LayerPolicy    LayerKind = "policy"
	LayerAsset     LayerKind = "asset"
)

// Verdict 是一条路径/一次判定的结论。
type Verdict string

const (
	VerdictReachable Verdict = "reachable" // 每一跳都有数据且放行
	VerdictBlocked   Verdict = "blocked"   // 某一步被策略/链路明确阻断
	VerdictProbable  Verdict = "probable"  // 缺数据（未知层），不等于放行
)

// HostFacts 是一台主机的网络事实（来自 agent 上报/配置）。
type HostFacts struct {
	HostID   string
	Subnets  []string // L3：主机所属子网（CIDR）
	Gateways []string // L3：默认网关 IP（可为空）
	VLANs    []string // L2：所属广播域（VLAN/tag）；空 = 未知
	Role     string   // L5：资产角色（web/db/mon/shadow…）
	Zone     string   // L5：安全区域（internal/dmz/public/wan/cloud），由 agent 上报
	// IPs 是主机地址（用于匹配 /32 主机级 ACL，v2.3 T1）。
	IPs []string
	// Links 是 L1 事实：子网 → 该子网上的链路是否 up（缺省视为 up）。
	Links map[string]bool
	// Inbound 是主机入向策略（域内/主机级 ACL）：From 为来源 CIDR。
	Inbound []PolicyRule
	// Outbound 是主机出向策略（OUTPUT 链）：To 为目的 CIDR（v2.3 T1）。
	Outbound []PolicyRule
	// StatefulInput 表示 INPUT 链存在 `ct state established,related accept`
	// （v2.3 T2）：回程包按已建立连接放行，无需再看静态规则。
	StatefulInput bool
	// Forwards 表示这台主机**真的会转发**（ip_forward=1 / 路由角色）。
	// 双网卡 ≠ 路由器：实测中 pivot-1 也是双宿主，但它不转发，
	// 若仅凭"≥2 个子网"就允许它中转，模型会凭空造出绕行路径。
	Forwards bool
}

// PolicyRule 是 L4 的一条策略判定（按源/目的子网表达）。
type PolicyRule struct {
	From  string // 源子网 CIDR
	To    string // 目的子网 CIDR
	Allow bool
}

// LayeredGraph 是分层图：层内节点/边语义独立，层间靠 same_identity 关联。
type LayeredGraph struct {
	hosts    map[string]*HostFacts
	subnetTo map[string][]string // subnet -> hosts
	hostSubs map[string][]string // host -> subnets
	gateways map[string][]string // gateway host -> subnets
	policies []PolicyRule
	inbound  map[string][]PolicyRule // host -> 入向规则（域内 ACL）
	outbound map[string][]PolicyRule // host -> 出向规则（v2.3 T1）
	// 已知性：false 表示该层完全没有采集数据（必须当 unknown，而不是 assume allow）
	policyKnown bool
	linkKnown   bool
}

// BuildLayeredGraph 从观测事实构建分层图。
//
// 语义约定：
//   - 主机之间"共享子网"是 L3 邻接（也是 L2 同域的必要条件）；
//   - 拥有 ≥2 个子网的主机视为网关（路由器），跨子网必须经过它；
//   - 策略只对**跨子网跳**生效（同子网直连不查跨域 ACL，域内 ACL 需 L4 细化规则，暂未建模）；
//   - policies 为空且 policyKnown=true ⇒ 无策略数据 = unknown，判 probable 而不是 reachable。
func BuildLayeredGraph(hosts []HostFacts, policies []PolicyRule, policyKnown, linkKnown bool) *LayeredGraph {
	g := &LayeredGraph{
		hosts:       map[string]*HostFacts{},
		subnetTo:    map[string][]string{},
		hostSubs:    map[string][]string{},
		gateways:    map[string][]string{},
		policies:    append([]PolicyRule(nil), policies...),
		inbound:     map[string][]PolicyRule{},
		outbound:    map[string][]PolicyRule{},
		policyKnown: policyKnown,
		linkKnown:   linkKnown,
	}
	for i := range hosts {
		h := hosts[i]
		if h.HostID == "" {
			continue
		}
		cp := h
		g.hosts[h.HostID] = &cp
		for _, s := range h.Subnets {
			c := normalizeSubnet(s)
			if c == "" {
				continue
			}
			g.hostSubs[h.HostID] = appendUnique(g.hostSubs[h.HostID], c)
			if !containsHost(g.subnetTo[c], h.HostID) {
				g.subnetTo[c] = append(g.subnetTo[c], h.HostID)
			}
		}
		if len(h.Inbound) > 0 {
			g.inbound[h.HostID] = append([]PolicyRule(nil), h.Inbound...)
		}
		if len(h.Outbound) > 0 {
			g.outbound[h.HostID] = append([]PolicyRule(nil), h.Outbound...)
		}
		if len(g.hostSubs[h.HostID]) >= 2 {
			g.gateways[h.HostID] = g.hostSubs[h.HostID]
		}
	}
	for k := range g.subnetTo {
		sort.Strings(g.subnetTo[k])
	}
	return g
}

// PathStep 是一条路径上的一步：跨到一个新主机，以及这次跨越的语义判定。
type PathStep struct {
	Host    string
	Subnet  string // 与该主机共享的子网（从上一跳进入）
	Verdict Verdict
	Reason  string
}

// PathVerdict 是一条完整路径的判定结果。
type PathVerdict struct {
	Path      []string
	Steps     []PathStep
	Verdict   Verdict
	Unknowns  []string // 缺数据的层（如 "policy"）
	BlockedAt string   // 被阻断的位置（blocked 时）
	Reason    string   // 判定理由（策略 allow/deny、缺数据等）
}

// HostReachable 计算 from→to 的所有简单路径（≤ maxHops），逐条给出判定。
//
// 跨子网跳的规则：路径 h1(s1) → gw(s1,s2) → h2(s2) 中，
// gw 处的 subnet 由 s1 变为 s2，这一跳要求 L4 对 (s1→s2) 明确 allow；
// deny ⇒ blocked；无策略数据 ⇒ probable。
func (g *LayeredGraph) HostReachable(from, to string, maxHops int) []PathVerdict {
	if maxHops <= 0 {
		maxHops = 5
	}
	if _, ok := g.hosts[from]; !ok {
		return []PathVerdict{{Path: []string{from, to}, Verdict: VerdictProbable,
			Unknowns: []string{"source_unknown"}}}
	}
	var out []PathVerdict
	visited := map[string]bool{from: true}
	var dfs func(cur string, path []string, steps []PathStep, prevSubnets []string, fromSubnet string)
	dfs = func(cur string, path []string, steps []PathStep, prevSubnets []string, fromSubnet string) {
		if cur == to && len(path) > 1 {
			pv := g.finalizePath(append([]string(nil), path...), append([]PathStep(nil), steps...))
			out = append(out, pv)
			return
		}
		if len(path)-1 >= maxHops {
			return
		}
		// 关键语义：只有**显式转发**的主机（router 角色 / ip_forward=1）能中继；
		// 双网卡但不开转发的主机（实测中的 pivot-1）只能作端点。
		// 若仅凭"≥2 个子网"判定，模型会凭空造出"经普通主机绕行"的路径。
		if cur != from {
			if h, ok := g.hosts[cur]; !ok || !h.Forwards {
				return
			}
		}
		for _, sub := range g.hostSubs[cur] {
			for _, next := range g.subnetTo[sub] {
				if visited[next] || !g.adjacentNoVisit(cur, next) {
					continue // L2 闸门：不同广播域不连通
				}
				visited[next] = true
				stepsNext := append(append([]PathStep(nil), steps...), PathStep{Host: next, Subnet: sub, Verdict: VerdictReachable})
				dfs(next, append(path, next), stepsNext, []string{sub}, fromSubnet)
				visited[next] = false
			}
		}
	}
	// 起点：从 from 的每个子网出发
	for _, sub := range g.hostSubs[from] {
		for _, next := range g.subnetTo[sub] {
			if visited[next] || !g.adjacentNoVisit(from, next) {
				continue // L2 闸门：起始跳也不能跨广播域
			}
			visited[next] = true
			dfs(next, []string{from, next}, []PathStep{{Host: next, Subnet: sub, Verdict: VerdictReachable}}, []string{sub}, sub)
			visited[next] = false
		}
	}
	if len(out) == 0 {
		// 目标主机完全未知：若其地址落在某个已知子网里，这是"可能"而不是"不存在"。
		if _, ok := g.hosts[to]; !ok {
			out = append(out, PathVerdict{Path: []string{from, to}, Verdict: VerdictProbable,
				Unknowns: []string{"target_unknown"}})
		} else {
			out = append(out, PathVerdict{Path: []string{from, to}, Verdict: VerdictBlocked,
				Reason: "no shared subnet or denied"})
		}
	}
	return out
}

// finalizePath 逐跳检查跨子网策略，给出整条路径的最终判定。
func (g *LayeredGraph) finalizePath(path []string, steps []PathStep) PathVerdict {
	pv := PathVerdict{Path: path, Steps: steps, Verdict: VerdictReachable}
	// steps[i].Subnet 是进入 steps[i].Host 时用的子网
	for i := 0; i < len(steps)-1; i++ {
		prevSub := steps[i].Subnet
		nextSub := steps[i+1].Subnet
		if prevSub == nextSub {
			continue // 同子网内移动
		}
		// 跨子网：发生在 steps[i].Host（它是两子网的共同成员=网关）
		verdict, reason := g.sessionVerdict(prevSub, nextSub)
		steps[i].Verdict = verdict
		steps[i].Reason = reason
		if verdict == VerdictBlocked {
			pv.Verdict = VerdictBlocked
			pv.BlockedAt = steps[i].Host
			pv.Reason = reason
			return pv
		}
		if verdict == VerdictProbable && pv.Verdict != VerdictBlocked {
			pv.Verdict = VerdictProbable
			pv.Unknowns = appendUnique(pv.Unknowns, "policy")
		}
	}
	// A-4：入向策略在**路径端点**也按会话语义生效（跨子网同样适用）。
	// 请求被目标 INPUT 拒 ⇒ blocked；反向会话的回程包撞上源端 INPUT ⇒ 同样 blocked。
	if len(steps) >= 2 && len(path) >= 2 {
		srcHost := path[0]
		dstHost := path[len(path)-1]
		srcSub := steps[0].Subnet
		dstSub := steps[len(steps)-1].Subnet
		// v2.3 T1/T2：端点按方向性会话判定（src → dst）。
		if !g.outboundAllowed(srcHost, dstSub, dstHost) {
			pv.Verdict = VerdictBlocked
			pv.BlockedAt = srcHost
			pv.Reason = "outbound policy denies " + srcHost + " -> " + dstHost
			return pv
		}
		if !g.inboundAllowed(dstHost, srcHost, srcSub, dstSub) {
			pv.Verdict = VerdictBlocked
			pv.BlockedAt = dstHost
			pv.Reason = "inbound policy denies " + srcSub + " -> " + dstHost
			return pv
		}
		if !g.replyAllowed(srcHost, dstHost, dstSub, srcSub) {
			pv.Verdict = VerdictBlocked
			pv.BlockedAt = srcHost
			pv.Reason = "inbound policy denies reply " + dstSub + " -> " + srcHost
			return pv
		}
	}
	return pv
}

// policyVerdict 查 L4：同子网默认放行；跨子网按策略规则；无数据 ⇒ probable。
func (g *LayeredGraph) policyVerdict(from, to string) (Verdict, string) {
	// 显式规则优先（先匹配先返回；与 nft 的 first-match 语义一致）
	for _, r := range g.policies {
		if !subnetMatch(r.From, from) || !subnetMatch(r.To, to) {
			continue
		}
		if r.Allow {
			return VerdictReachable, "policy allow " + r.From + "->" + r.To
		}
		return VerdictBlocked, "policy deny " + r.From + "->" + r.To
	}
	if !g.policyKnown {
		return VerdictProbable, "policy unknown"
	}
	return VerdictReachable, "policy allow (default)"
}

// broadcastCompatible 判断两台主机能否在二层直接通信（L2 闸门）。
//
// 语义（本层只表达这一件事）：
//   - 双方都上报了 VLAN 且没有交集 ⇒ **不同广播域**，即使 IP 同子网也不可直连
//     （这正是"重叠地址 + VLAN 隔离"场景）；
//   - 任一方 VLAN 未知 ⇒ 不阻断（未知 ≠ 拒绝），但由调用方自行标注不确定；
//   - 双方都没有 VLAN 信息 ⇒ 视为兼容（保持既有行为）。
func (g *LayeredGraph) broadcastCompatible(a, b string) bool {
	ha, hb := g.hosts[a], g.hosts[b]
	if ha == nil || hb == nil {
		return true
	}
	if len(ha.VLANs) == 0 || len(hb.VLANs) == 0 {
		return true
	}
	for _, va := range ha.VLANs {
		for _, vb := range hb.VLANs {
			if va == vb {
				return true
			}
		}
	}
	return false
}

// linkUp 判断 host 在 subnet 上的链路是否可用（无链路数据视为可用）。
func (g *LayeredGraph) linkUp(host, subnet string) bool {
	h := g.hosts[host]
	if h == nil || len(h.Links) == 0 {
		return true
	}
	up, ok := h.Links[subnet]
	if !ok {
		return true
	}
	return up
}

// inboundAllowed 判断 target 的主机入向策略是否允许来自 sourceSubnet 的流量。
// 无规则/无数据 ⇒ 允许（未知 ≠ 拒绝）。
// replyAllowed 判断发往 host 的回程包是否会被放行（v2.3 T2）。
// 有状态防火墙（ct established accept）⇒ 已建立连接的回程直接放行；
// 否则按静态 INPUT 规则判断（可能被 deny 丢弃）。
func (g *LayeredGraph) replyAllowed(host, peer, peerSubnet, ownSubnet string) bool {
	if h := g.hosts[host]; h != nil && h.StatefulInput {
		return true
	}
	return g.inboundAllowed(host, peer, peerSubnet, ownSubnet)
}

// hostInCIDR 判断主机的任一 IP 是否落在 cidr 内（用于 /32 主机级 ACL，v2.3 T1）。
func (g *LayeredGraph) hostInCIDR(host, cidr string) bool {
	h := g.hosts[host]
	if h == nil || cidr == "" {
		return false
	}
	for _, ipStr := range h.IPs {
		ip := net.ParseIP(strings.TrimSuffix(ipStr, "/32"))
		if ip == nil {
			continue
		}
		// agent 上报的 nft `ip saddr 1.2.3.4/32` 常被规范化为裸 IP（无 /32），
		// 这里必须同时支持：裸 IP 精确相等，或 CIDR 包含。
		if bare := net.ParseIP(strings.TrimSpace(cidr)); bare != nil {
			if bare.Equal(ip) {
				return true
			}
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// outboundAllowed 判断 source 的出向策略是否允许发往 destSubnet / destHost 的流量。
// 规则 To 命中目标子网或目标主机 IP 即算匹配；无数据 ⇒ 允许（未知 ≠ 拒绝）。
func (g *LayeredGraph) outboundAllowed(source, destSubnet, destHost string) bool {
	for _, r := range g.outbound[source] {
		if r.To == "" {
			return r.Allow
		}
		if subnetMatch(r.To, destSubnet) || g.hostInCIDR(destHost, r.To) {
			return r.Allow
		}
	}
	return true
}

// inboundAllowed 判断 target 的入向策略是否允许来自 sourceSubnet、送到 targetSubnet 的流量。
//
// 支持三种规则（与 agent 的解析一一对应）：
//   - From 限定来源子网（From 为空 = 任意来源）；
//   - To 限定目标子网（A-5：`ip daddr … drop` 这类规则，To 为空 = 任意目标）；
//   - 首条匹配即生效（规则顺序由解析侧保持）。
func (g *LayeredGraph) inboundAllowed(target, sourceHost, sourceSubnet, targetSubnet string) bool {
	for _, r := range g.inbound[target] {
		fromOK := r.From == "" || subnetMatch(r.From, sourceSubnet) || g.hostInCIDR(sourceHost, r.From)
		toOK := r.To == "" || subnetMatch(r.To, targetSubnet) || g.hostInCIDR(target, r.To)
		if fromOK && toOK {
			return r.Allow
		}
	}
	return true
}

// adjacentNoVisit 是 Adjacent 的轻量版本（避免重复计算 SharedSubnetsRaw）。
func (g *LayeredGraph) adjacentNoVisit(a, b string) bool {
	ok, _ := g.Adjacent(a, b)
	return ok
}

// Adjacent 判断两台主机是否存在"可直接通信"的邻接（L3 共享子网 + L2 广播域兼容）。
// 返回 (adjacent, reason)，reason 用于解释阻断原因（便于审计与测试）。
func (g *LayeredGraph) Adjacent(a, b string) (bool, string) {
	if len(g.SharedSubnetsRaw(a, b)) == 0 {
		return false, "no shared subnet"
	}
	if !g.broadcastCompatible(a, b) {
		return false, "l2 isolated (VLAN mismatch)"
	}
	subs := g.SharedSubnetsRaw(a, b)
	for _, s := range subs {
		if !g.linkUp(a, s) {
			return false, "link down on " + s + " (" + a + ")"
		}
		if !g.linkUp(b, s) {
			return false, "link down on " + s + " (" + b + ")"
		}
		// A-4：入向策略按**会话语义**双向生效。
		// 请求被目标 B 的 INPUT 拒绝 ⇒ 会话失败；反向会话（B→A）的回程包
		// 同样会撞上 B 的 INPUT 而被丢弃 ⇒ 两个方向都必须放行。
		// v2.3 T1/T2：方向性会话判定（只回答 a→b）。
		//   1) a 的 OUTPUT 允许发往 b；
		//   2) b 的 INPUT 允许来自 a 的**新连接**；
		//   3) 回程（b→a）到了 a 的 INPUT：有状态则放行，否则按静态规则。
		if !g.outboundAllowed(a, s, b) {
			return false, "outbound policy denies " + a + " -> " + b
		}
		if !g.inboundAllowed(b, a, s, s) {
			return false, "inbound policy denies " + s + " -> " + b
		}
		if !g.replyAllowed(a, b, s, s) {
			return false, "inbound policy denies reply " + s + " -> " + a
		}
	}
	return true, "adjacent"
}

// SharedSubnetsRaw 返回共同子网，不做 L2 闸门（仅供 Adjacent 内部与诊断用）。
func (g *LayeredGraph) SharedSubnetsRaw(a, b string) []string {
	var out []string
	for _, sa := range g.hostSubs[a] {
		for _, sb := range g.hostSubs[b] {
			if sa == sb {
				out = append(out, sa)
			}
		}
	}
	return out
}

// Stats 返回分层图的规模统计（用于可观测性与测试）。
func (g *LayeredGraph) Stats() map[string]int {
	subnets := map[string]bool{}
	vlans := map[string]bool{}
	for _, subs := range g.hostSubs {
		for _, s := range subs {
			subnets[s] = true
		}
	}
	for _, h := range g.hosts {
		for _, v := range h.VLANs {
			vlans[v] = true
		}
	}
	return map[string]int{
		"hosts":        len(g.hosts),
		"subnets":      len(subnets),
		"vlans":        len(vlans),
		"policies":     len(g.policies),
		"forwarding":   len(g.gateways),
		"policy_known": boolInt(g.policyKnown),
		"link_known":   boolInt(g.linkKnown),
	}
}

// CriticalityForRole 是 L5（业务角色语义）到资产关键性的映射。
// 角色来自运维配置（[srd] roles），优先级高于区域推断。
func CriticalityForRole(role string) float64 {
	switch role {
	case "db", "database", "core":
		return 0.95
	case "router", "gateway", "fw":
		return 0.90
	case "web", "app":
		return 0.70
	case "monitor", "mon", "siem":
		return 0.60
	case "shadow", "decoy", "honeypot":
		return 0.30
	default:
		return 0.50
	}
}

// CriticalityForZone 是 L5（区域语义）到资产关键性的映射。
// 只用于把"位置语义"接进风险计算，不代表真实业务重要性；可在配置/规则层再校正。
func CriticalityForZone(zone string) float64 {
	switch zone {
	case "internal":
		return 0.80
	case "dmz":
		return 0.60
	case "cloud":
		return 0.60
	case "public":
		return 0.40
	case "wan":
		return 0.30
	default:
		return 0.50
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SharedSubnets 返回两台主机共同所属的子网（同广播域的直接邻接依据）。
func (g *LayeredGraph) SharedSubnets(a, b string) []string {
	if ok, _ := g.Adjacent(a, b); !ok {
		return nil // L2/L1/入向策略任一不满足 ⇒ 不算邻接
	}
	return g.SharedSubnetsRaw(a, b)
}

// Forwards 判断主机是否真的转发（允许作为中继）。
func (g *LayeredGraph) Forwards(host string) bool {
	h, ok := g.hosts[host]
	return ok && h.Forwards
}

// CrossingPermitted 判断路由器 router 是否允许把风险从它的**其它子网**
// 跨到 toSubnet（用于 SRD 构边时过滤"策略阻断的跨域边"）。
//
// 语义：只要存在一个来源子网 s2（s2≠toSubnet）的策略判定不是 deny，就放行；
// 全部 deny 则阻断。未知策略按放行处理（保守地保留边，由上层用 probable 表达不确定）。
func (g *LayeredGraph) CrossingPermitted(router, toSubnet string) bool {
	subs := g.hostSubs[router]
	if len(subs) == 0 {
		return true
	}
	found := false
	for _, s2 := range subs {
		if s2 == toSubnet {
			continue
		}
		found = true
		if v, _ := g.sessionVerdict(s2, toSubnet); v != VerdictBlocked {
			return true
		}
	}
	if !found {
		return true // 只有这一个子网，不涉及跨域
	}
	return false
}

// PolicyKnown 表示是否采集到过策略事实。
func (g *LayeredGraph) PolicyKnown() bool { return g.policyKnown }

// sessionVerdict 是**会话语义**下的跨子网判定：一次会话要成立，
// 去程与回程必须同时被放行。
//
// 为什么必须双向：真实防火墙里 `ct state established,related accept` 往往排在
// drop 规则之后 —— 单向 deny 会让**回程包**也被丢弃，于是会话两个方向都不通。
// 实测中 `iifname eth0 oifname eth4 drop`（A→D）导致 D→A 也不可达，就是这个原因；
// 只按单方向判定会把这类对误报成"可达"（非对称误报）。
//
// 判定合并：任一方向 blocked ⇒ blocked；否则任一方向 probable ⇒ probable；
// 都 reachable ⇒ reachable。
func (g *LayeredGraph) sessionVerdict(from, to string) (Verdict, string) {
	fwdV, fwdWhy := g.policyVerdict(from, to)
	revV, revWhy := g.policyVerdict(to, from)
	switch {
	case fwdV == VerdictBlocked || revV == VerdictBlocked:
		if fwdV == VerdictBlocked {
			return VerdictBlocked, fwdWhy
		}
		return VerdictBlocked, "return path blocked: " + revWhy
	case fwdV == VerdictProbable || revV == VerdictProbable:
		return VerdictProbable, "policy partially unknown"
	default:
		return VerdictReachable, fwdWhy
	}
}

// Summary 把多条路径汇总成一个结论（只要有 reachable 就 reachable；
// 否则 blocked 优先于 probable）。
func Summary(verdicts []PathVerdict) Verdict {
	hasProbable := false
	hasBlocked := false
	for _, v := range verdicts {
		switch v.Verdict {
		case VerdictReachable:
			return VerdictReachable
		case VerdictBlocked:
			hasBlocked = true
		case VerdictProbable:
			hasProbable = true
		}
	}
	if hasProbable {
		return VerdictProbable
	}
	if hasBlocked {
		return VerdictBlocked
	}
	return VerdictBlocked
}

// Gateways 返回被识别为网关的主机（≥2 个子网）。
func (g *LayeredGraph) Gateways() []string {
	out := make([]string, 0, len(g.gateways))
	for h := range g.gateways {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// SubnetOf 返回主机所属子网（排序后）。
func (g *LayeredGraph) SubnetOf(host string) []string {
	return append([]string(nil), g.hostSubs[host]...)
}

// ---------------------------------------------------------------- helpers

func normalizeSubnet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func subnetMatch(pattern, sub string) bool {
	if pattern == sub {
		return true
	}
	// 裸 IP 模式（agent 上报 /32 时的常见形态）：与子网/主机地址直接比较。
	if bare := net.ParseIP(strings.TrimSpace(pattern)); bare != nil {
		if ip := net.ParseIP(strings.TrimSuffix(strings.TrimSpace(sub), "/32")); ip != nil {
			return bare.Equal(ip)
		}
		if _, n, err := net.ParseCIDR(sub); err == nil {
			return n.Contains(bare)
		}
		return false
	}
	if _, n, err := net.ParseCIDR(pattern); err == nil {
		if ip := net.ParseIP(strings.TrimSuffix(sub, "/32")); ip != nil {
			return n.Contains(ip)
		}
	}
	return false
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func containsHost(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
