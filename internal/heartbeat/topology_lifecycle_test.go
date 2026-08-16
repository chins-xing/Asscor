//go:build heartbeat

package heartbeat

import (
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/topology"
)

// TestTimeoutDeletesTopology: M1 生命周期 (P0-1 修复) — 心跳超时注销拓扑
// 节点, 清除其传播边; 身份绑定保留 (拓扑活性与身份锚定分离)。
func TestTimeoutDeletesTopology(t *testing.T) {
	topology.ResetForTesting()
	defer topology.ResetForTesting()

	m := New()
	m.timeout = 60 * time.Second
	m.agents = make(map[string]*kernel.AgentRecord)
	m.agents["host-a"] = &kernel.AgentRecord{
		HostID:   "host-a",
		Active:   true,
		LastSeen: time.Now().Add(-2 * m.timeout), // 超时
	}

	// 拓扑节点已注册 (模拟 comms 已 RecordTopology)。
	topology.RecordTopology("host-a", []string{"10.0.0.0/24"})
	if topology.GetNode("host-a") == nil {
		t.Fatal("precondition: node must exist in topology")
	}

	m.checkTimeouts()

	if topology.GetNode("host-a") != nil {
		t.Error("timed-out host must be removed from topology (no stale propagation)")
	}
	// 身份绑定记录保留 (Active=false 即可, 不被剪除逻辑影响)。
	if rec := m.agents["host-a"]; rec == nil || rec.Active {
		t.Errorf("agent record must remain but inactive: %+v", rec)
	}
}

// TestTimeoutDeleteUnknownHostNoop: 超时注销未知拓扑节点是 no-op (不 panic)。
func TestTimeoutDeleteUnknownHostNoop(t *testing.T) {
	topology.ResetForTesting()
	defer topology.ResetForTesting()

	m := New()
	m.timeout = 60 * time.Second
	m.agents = make(map[string]*kernel.AgentRecord)
	m.agents["host-x"] = &kernel.AgentRecord{
		HostID:   "host-x",
		Active:   true,
		LastSeen: time.Now().Add(-2 * m.timeout),
	}
	// 拓扑中无 host-x。
	m.checkTimeouts() // must not panic
}
