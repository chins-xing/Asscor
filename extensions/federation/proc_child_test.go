package federation

import (
	"context"
	"encoding/json"
	"testing"
)

// 子进程状态机：configure(off) → status；snapshot → check；shutdown 可重入。
func TestProcStateOffAndShutdown(t *testing.T) {
	s := NewProcState()
	raw, _ := json.Marshal(ConfigureParams{Role: "off"})
	if _, err := s.handle(methodConfigure, raw); err != nil {
		t.Fatalf("configure off: %v", err)
	}
	st := s.status()
	if st.Role != RoleOff {
		t.Fatalf("role = %s", st.Role)
	}
	if _, err := s.handle(methodShutdown, nil); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// 主端：本地事实 + 节点上报 → check/export 走"注入式"合并（不读内核注册表）。
func TestProcStateMasterCheckWithInjectedFacts(t *testing.T) {
	s := NewProcState()
	raw, _ := json.Marshal(ConfigureParams{Role: "master", ListenAddr: "127.0.0.1:0", Token: "t"})
	if _, err := s.handle(methodConfigure, raw); err != nil {
		t.Fatalf("configure master: %v", err)
	}
	snap := SnapshotParams{
		Report: NodeReport{NodeID: "nk1", HostFacts: []HostFact{
			{ID: "b", IPs: []string{"10.1.0.11"}, Subnets: []string{"10.1.0.0/24"}},
		}, PolicyKnown: true},
		Hosts: []HostFact{
			{ID: "a", IPs: []string{"10.0.0.11"}, Subnets: []string{"10.0.0.0/24"}},
			{ID: "r", IPs: []string{"10.0.0.1", "10.1.0.1"}, Subnets: []string{"10.0.0.0/24", "10.1.0.0/24"}, Forwards: true},
		},
		PolicyKnown: true,
	}
	b, _ := json.Marshal(snap)
	if _, err := s.handle(methodSnapshot, b); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// 把节点上报注入 collector（模拟 HTTP 已收到）
	_ = s.collector.Apply(snap.Report)
	chkRaw, _ := json.Marshal(CheckParams{Src: "a", Dst: "b"})
	res, err := s.handle(methodCheck, chkRaw)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	mc, ok := res.(*MergedCheck)
	if !ok || mc.Verdict != "reachable" {
		t.Fatalf("injected facts should make a→b reachable, got %+v", res)
	}
	exp, err := s.handle(methodExport, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	te := exp.(TopologyExport)
	if len(te.Hosts) < 3 {
		t.Fatalf("export hosts = %d, want >=3", len(te.Hosts))
	}
	_ = context.Background()
}
