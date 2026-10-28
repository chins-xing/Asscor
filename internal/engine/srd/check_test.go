//go:build engine

package srd

import (
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/topology"
)

func buildCheckGraph() *topology.LayeredGraph {
	hosts := []topology.HostFacts{
		{HostID: "A", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.11"}},
		{HostID: "B", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.20"},
			Inbound: []topology.PolicyRule{{From: "10.0.0.11/32", Allow: false}}},
		{HostID: "C", Subnets: []string{"10.0.0.0/24"}, IPs: []string{"10.0.0.30"}},
	}
	return topology.BuildLayeredGraph(hosts, nil, true, true)
}

// v2.3 T3：CheckReachability 必须给出 verdict / 路径 / 阻断点 / 原因。
func TestCheckReachabilityBlocked(t *testing.T) {
	m := NewManager()
	m.SetLayeredGraph(buildCheckGraph())

	res, err := m.CheckReachability("A", "B")
	if err != nil {
		t.Fatalf("CheckReachability: %v", err)
	}
	if res.Verdict != "blocked" {
		t.Fatalf("verdict=%s want blocked", res.Verdict)
	}
	if res.Best == nil || res.Best.BlockedAt == "" {
		t.Fatalf("应给出阻断点: %+v", res.Best)
	}
	if !strings.Contains(res.Best.Reason, "inbound policy denies") {
		t.Fatalf("reason 应说明入向策略: %q", res.Best.Reason)
	}
	if !strings.Contains(res.String(), "blocked") {
		t.Fatalf("String 渲染缺少 verdict: %q", res.String())
	}
}

// 可达路径：C→A 不应被 B 的规则影响。
func TestCheckReachabilityReachable(t *testing.T) {
	m := NewManager()
	m.SetLayeredGraph(buildCheckGraph())

	res, err := m.CheckReachability("C", "A")
	if err != nil {
		t.Fatalf("CheckReachability: %v", err)
	}
	if res.Verdict != "reachable" {
		t.Fatalf("verdict=%s want reachable（%+v）", res.Verdict, res.Best)
	}
	if res.Best == nil || len(res.Best.Nodes) < 2 {
		t.Fatalf("应给出路径: %+v", res.Best)
	}
}

// 无图时必须报错而不是返回空结果。
func TestCheckReachabilityWithoutGraph(t *testing.T) {
	m := NewManager()
	if _, err := m.CheckReachability("A", "B"); err == nil {
		t.Fatal("无分层图时应返回错误")
	}
}

// CheckReach 是 CLI 用的 any 包装，结果类型必须一致。
func TestCheckReachReturnsSame(t *testing.T) {
	m := NewManager()
	m.SetLayeredGraph(buildCheckGraph())
	v, err := m.CheckReach("A", "B")
	if err != nil {
		t.Fatalf("CheckReach: %v", err)
	}
	res, ok := v.(*ReachCheck)
	if !ok || res.Verdict != "blocked" {
		t.Fatalf("CheckReach 返回类型/结果错误: %T %+v", v, v)
	}
}
