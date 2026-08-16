package topology

import (
	"sync"
	"testing"
)

// TestRecordAndQuery: 节点记录后可查询 (M0 注入器基础)。
func TestRecordAndQuery(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	RecordTopologyDetailed("host-a", []string{"10.0.0.0/24"}, "internal")

	if got := GetTopology(); len(got) != 1 || got["host-a"][0] != "10.0.0.0/24" {
		t.Fatalf("GetTopology = %v", got)
	}
	n := GetNode("host-a")
	if n == nil || n.HostID != "host-a" || n.Zone != "internal" || n.Status != "active" {
		t.Fatalf("GetNode = %+v", n)
	}
	if GetNode("host-nope") != nil {
		t.Error("unknown node should be nil")
	}
	nodes := ListNodes()
	if len(nodes) != 1 || nodes[0].HostID != "host-a" {
		t.Fatalf("ListNodes = %+v", nodes)
	}
}

// TestRecordUpdated: 已存在节点更新为 node_updated 事件, 子网覆盖。
func TestRecordUpdated(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	events := collectEvents(t, func() {
		RecordTopologyDetailed("host-a", []string{"10.0.0.0/24"}, "internal")
		RecordTopologyDetailed("host-a", []string{"10.0.1.0/24"}, "")
	})

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Type != TopoNodeAdded {
		t.Errorf("first event = %s, want node_added", events[0].Type)
	}
	if events[1].Type != TopoNodeUpdated {
		t.Errorf("second event = %s, want node_updated", events[1].Type)
	}
	if got := GetNode("host-a").Subnets[0]; got != "10.0.1.0/24" {
		t.Errorf("subnets not updated: %v", got)
	}
}

// TestDeleteTopology: 注销发布 node_removed, 节点从查询中消失 (P0-1 生命周期原语)。
func TestDeleteTopology(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	RecordTopologyDetailed("host-a", []string{"10.0.0.0/24"}, "internal")

	var mu sync.Mutex
	var removed []TopoEvent
	unsub := Subscribe(func(ev TopoEvent) {
		mu.Lock()
		removed = append(removed, ev)
		mu.Unlock()
	})
	defer unsub()

	DeleteTopology("host-a")

	mu.Lock()
	defer mu.Unlock()
	if len(removed) != 1 || removed[0].Type != TopoNodeRemoved || removed[0].HostID != "host-a" {
		t.Fatalf("removed events = %+v", removed)
	}
	if GetNode("host-a") != nil {
		t.Error("node must be gone after delete")
	}
	if len(GetTopology()) != 0 {
		t.Error("topology must be empty after delete")
	}

	// 删除未知节点: 无事件 (no-op)
	before := len(removed)
	DeleteTopology("host-nope")
	if len(removed) != before {
		t.Error("deleting unknown node must not emit an event")
	}
}

// TestSubscribeUnsubscribe: 订阅 + 取消订阅。
func TestSubscribeUnsubscribe(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	var mu sync.Mutex
	count := 0
	unsub := Subscribe(func(TopoEvent) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	RecordTopology("host-a", []string{"10.0.0.0/24"})
	mu.Lock()
	if count != 1 {
		t.Fatalf("subscriber should get 1 event, got %d", count)
	}
	mu.Unlock()

	unsub()
	RecordTopology("host-a", []string{"10.0.1.0/24"})
	mu.Lock()
	if count != 1 {
		t.Fatalf("unsubscribed handler must not fire, got %d", count)
	}
	mu.Unlock()
}

// TestLegacyAPICompat: 原 RecordTopology/SetTopologyListener 兼容 (消费方零改动)。
func TestLegacyAPICompat(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	got := make(chan string, 4)
	SetTopologyListener(func(hostID string, subnets []string) {
		got <- hostID
	})

	RecordTopology("host-a", []string{"10.0.0.0/24"})
	if h := <-got; h != "host-a" {
		t.Fatalf("legacy listener got %q", h)
	}
	if v := GetTopology()["host-a"]; len(v) != 1 {
		t.Fatalf("legacy record failed: %v", v)
	}
}

// TestMultipleSubscribers: 多订阅者同时收到事件。
func TestMultipleSubscribers(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	var mu sync.Mutex
	received := map[uint64]int{}
	mk := func(id uint64) func(TopoEvent) {
		return func(TopoEvent) {
			mu.Lock()
			received[id]++
			mu.Unlock()
		}
	}
	un1 := Subscribe(mk(1))
	un2 := Subscribe(mk(2))
	defer un1()
	defer un2()

	RecordTopology("host-a", []string{"10.0.0.0/24"})

	mu.Lock()
	defer mu.Unlock()
	if received[1] != 1 || received[2] != 1 {
		t.Fatalf("both subscribers must fire: %v", received)
	}
}

// collectEvents runs fn and returns all events observed by a subscriber.
func collectEvents(t *testing.T, fn func()) []TopoEvent {
	t.Helper()
	var mu sync.Mutex
	var events []TopoEvent
	unsub := Subscribe(func(ev TopoEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	defer unsub()
	fn()
	mu.Lock()
	defer mu.Unlock()
	return events
}
