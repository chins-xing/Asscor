//go:build engine

package srd

import (
	"fmt"
	"strings"

	"github.com/chins-xing/asscor/internal/topology"
)

// ReachStep 是路径上的一跳（用于 CLI 解释"在哪被拦"）。
type ReachStep struct {
	Host    string `json:"host"`
	Subnet  string `json:"subnet"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// ReachPath 是一条路径的判定结果。
type ReachPath struct {
	Nodes     []string    `json:"nodes"`
	Verdict   string      `json:"verdict"`
	BlockedAt string      `json:"blocked_at,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Unknowns  []string    `json:"unknowns,omitempty"`
	Steps     []ReachStep `json:"steps"`
}

// ReachCheck 是 `srd check <src> <dst>` 的输出（v2.3 T3）。
type ReachCheck struct {
	Src      string         `json:"src"`
	Dst      string         `json:"dst"`
	Verdict  string         `json:"verdict"` // reachable / probable / blocked
	Paths    int            `json:"paths"`
	Best     *ReachPath     `json:"best,omitempty"`
	Unknowns []string       `json:"unknowns,omitempty"`
	Layered  bool           `json:"layered"`
	Stats    map[string]int `json:"stats,omitempty"`
}

// checkGraph 是 CheckReachability 使用的图（优先 pipeline 的分层图，
// 否则回落到注册表构建）。
func (m *Manager) checkGraph() *topology.LayeredGraph {
	m.mu.RLock()
	lg := m.checkLayered
	m.mu.RUnlock()
	if lg != nil {
		return lg
	}
	return topology.BuildLayeredFromRegistry()
}

// CheckReachability 回答"src 能否到达 dst，为什么"。
// 这是 `srd check` 的唯一实现，供 CLI 与后续 API 复用。
func (m *Manager) CheckReachability(src, dst string) (*ReachCheck, error) {
	lg := m.checkGraph()
	if lg == nil {
		return nil, fmt.Errorf("分层图为空：未采集到拓扑事实（检查 agent 心跳与 [srd] layered_graph）")
	}
	verdicts := lg.HostReachable(src, dst, 5)
	out := &ReachCheck{
		Src: src, Dst: dst,
		Verdict: string(topology.Summary(verdicts)),
		Paths:   len(verdicts),
		Layered: true,
		Stats:   lg.Stats(),
	}
	// 选一条最有解释力的路径：reachable > blocked > probable。
	var best *topology.PathVerdict
	rank := func(v topology.Verdict) int {
		switch v {
		case topology.VerdictReachable:
			return 3
		case topology.VerdictBlocked:
			return 2
		default:
			return 1
		}
	}
	for i := range verdicts {
		if best == nil || rank(verdicts[i].Verdict) > rank(best.Verdict) {
			best = &verdicts[i]
		}
	}
	if best != nil {
		// 直连快捷路径可能给不出具体原因（steps 为空）：补一次 Adjacent 解释。
		if best.Verdict == topology.VerdictBlocked && len(best.Steps) == 0 && best.Reason == "" {
			if ok, why := lg.Adjacent(src, dst); !ok {
				best.Reason = why
				best.BlockedAt = dst
			}
		}
		rp := &ReachPath{
			Nodes:     append([]string(nil), best.Path...),
			Verdict:   string(best.Verdict),
			BlockedAt: best.BlockedAt,
			Reason:    best.Reason,
			Unknowns:  append([]string(nil), best.Unknowns...),
		}
		for _, s := range best.Steps {
			rp.Steps = append(rp.Steps, ReachStep{Host: s.Host, Subnet: s.Subnet, Verdict: string(s.Verdict), Reason: s.Reason})
		}
		out.Best = rp
		out.Unknowns = rp.Unknowns
	}
	return out, nil
}

// CheckReach 是 CLI 适配用的 any 版本（避免 CLI 依赖 engine 包类型）。
func (m *Manager) CheckReach(src, dst string) (any, error) {
	return m.CheckReachability(src, dst)
}


// String 渲染成人类可读的解释（CLI 文本模式）。
func (c *ReachCheck) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  srd check  %s -> %s\n", c.Src, c.Dst)
	fmt.Fprintf(&b, "  verdict : %s   (paths=%d)\n", c.Verdict, c.Paths)
	if c.Best != nil {
		fmt.Fprintf(&b, "  path    : %s\n", strings.Join(c.Best.Nodes, " -> "))
		if c.Best.BlockedAt != "" {
			fmt.Fprintf(&b, "  blocked : %s\n", c.Best.BlockedAt)
		}
		if c.Best.Reason != "" {
			fmt.Fprintf(&b, "  reason  : %s\n", c.Best.Reason)
		}
		if len(c.Best.Unknowns) > 0 {
			fmt.Fprintf(&b, "  unknown : %s\n", strings.Join(c.Best.Unknowns, ", "))
		}
		for _, s := range c.Best.Steps {
			fmt.Fprintf(&b, "    - %-14s %-18s %-10s %s\n", s.Host, s.Subnet, s.Verdict, s.Reason)
		}
	}
	if len(c.Stats) > 0 {
		fmt.Fprintf(&b, "  layers  : hosts=%d subnets=%d vlans=%d policies=%d forwarding=%d\n",
			c.Stats["hosts"], c.Stats["subnets"], c.Stats["vlans"], c.Stats["policies"], c.Stats["forwarding"])
	}
	b.WriteString("\n")
	return b.String()
}
