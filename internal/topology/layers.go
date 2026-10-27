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
				if visited[next] {
					continue
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
			if visited[next] {
				continue
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
		verdict, reason := g.policyVerdict(prevSub, nextSub)
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
