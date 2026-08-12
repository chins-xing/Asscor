package srd

import (
	"context"
	"testing"
	"time"

	prismlib "github.com/chins-xing/prism"
)

// TestProcessMultipleHostsNoDeadlock guards against the RWMutex re-entrancy
// deadlock: Process holds the write lock, and buildIncomingEdges→areConnected
// used to re-acquire the read lock, deadlocking on the second host's report.
func TestProcessMultipleHostsNoDeadlock(t *testing.T) {
	p := NewPipeline(DefaultConfig())

	// Seed two hosts with overlapping subnets so areConnected returns true.
	p.SetTopology("host-a", []string{"10.0.0.0/24"}, "internal")
	p.SetTopology("host-b", []string{"10.0.0.0/24"}, "internal")

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Process(context.Background(), &ExternalAssessmentReport{
			Tool:     "test",
			HostID:   "host-a",
			Hostname: "a",
			RawScore: 50,
		})
		p.Process(context.Background(), &ExternalAssessmentReport{
			Tool:     "test",
			HostID:   "host-b",
			Hostname: "b",
			RawScore: 40,
		})
	}()

	select {
	case <-done:
		// success — no deadlock
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock detected: Process hung on second host report")
	}
}

// TestAreConnectedSubnetOverlap verifies subnet-overlap edge construction.
func TestAreConnectedSubnetOverlap(t *testing.T) {
	p := NewPipeline(DefaultConfig())
	p.SetTopology("a", []string{"10.0.0.0/24"}, "internal")
	p.SetTopology("b", []string{"10.0.0.0/24"}, "internal")
	p.SetTopology("c", []string{"192.168.0.0/24"}, "internal")

	if !p.areConnected("a", "b") {
		t.Error("same subnet should be connected")
	}
	if p.areConnected("a", "c") {
		t.Error("different subnet should not be connected")
	}
	// No topology → fallback connected (conservative)
	if !p.areConnected("a", "unknown") {
		t.Error("missing topology should fallback to connected")
	}
}

// TestGetReachableHosts verifies lateral-movement scope computation.
func TestGetReachableHosts(t *testing.T) {
	p := NewPipeline(DefaultConfig())
	p.SetTopology("a", []string{"10.0.0.0/24"}, "internal")
	p.SetTopology("b", []string{"10.0.0.0/24"}, "internal")
	p.SetTopology("c", []string{"192.168.0.0/24"}, "internal")

	// Seed snapshots so GetReachableHosts has nodes to iterate.
	p.snapshots["a"] = &prismlib.NodeState{HostID: "a", SSAMScore: 70}
	p.snapshots["b"] = &prismlib.NodeState{HostID: "b", SSAMScore: 60}
	p.snapshots["c"] = &prismlib.NodeState{HostID: "c", SSAMScore: 50}

	reachable := p.GetReachableHosts("a")
	if len(reachable) != 1 || reachable[0] != "b" {
		t.Errorf("expected [b] reachable from a, got %v", reachable)
	}
}
