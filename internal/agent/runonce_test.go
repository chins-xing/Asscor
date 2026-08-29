package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// ---------------------------------------------------------------------------
// runOnce / Run — reconnection and exit semantics (gap report §2.4), driven by
// the in-process testKernel. HeartbeatSec is shortened so retries fire fast;
// signal handling inside Run is not exercised.
// ---------------------------------------------------------------------------

// newKernelAgent wires a fresh agent to a testKernel with a tiny heartbeat
// interval and returns both. cfg is copied, so callers can pre-tweak it.
func newKernelAgent(t *testing.T, k *testKernel, cfg AgentConfig) *Agent {
	t.Helper()
	cfg.TLSEnabled = false
	cfg.KernelAddr = k.addr()
	// Force immediate timer ticks regardless of the caller's HeartbeatSec so
	// the retry loop terminates in microseconds instead of 30s per heartbeat.
	cfg.HeartbeatSec = 0
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	cfg.CheckIntervalSec = 3600
	cfg.CheckTimeoutSec = 1
	return NewAgent(cfg)
}

// TestRunOnceConsecutiveFailuresReachMaxRetries: heartbeats keep failing;
// after MaxRetries consecutive failures runOnce returns ErrKernelUnreachable.
func TestRunOnceConsecutiveFailuresReachMaxRetries(t *testing.T) {
	var hbCount atomic.Int32
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		switch env["method"] {
		case "Register":
			return okEnv(map[string]interface{}{"accepted": true, "session_id": "sess-r"})
		default: // Heartbeat
			hbCount.Add(1)
			return errEnv("kernel overloaded")
		}
	})
	cfg := DefaultConfig()
	cfg.MaxRetries = 2
	a := newKernelAgent(t, k, cfg)

	err := a.runOnce(context.Background())
	if !errors.Is(err, ErrKernelUnreachable) {
		t.Fatalf("runOnce = %v, want ErrKernelUnreachable", err)
	}
	if hbCount.Load() != 2 {
		t.Errorf("heartbeats = %d, want 2 (max retries)", hbCount.Load())
	}
	if a.sessionID != "sess-r" {
		t.Errorf("sessionID should survive until unreachable, got %q", a.sessionID)
	}
}

// TestRunOnceSuccessResetsCounter: a successful heartbeat clears the error
// counter — after fail, success, fail, fail (MaxRetries=2) the agent does NOT
// give up at the first post-success failure; it needs 2 consecutive failures.
func TestRunOnceSuccessResetsCounter(t *testing.T) {
	var hbCount atomic.Int32
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		switch env["method"] {
		case "Register":
			return okEnv(map[string]interface{}{"accepted": true, "session_id": "sess-r"})
		default: // Heartbeat
			n := hbCount.Add(1)
			if n == 2 {
				return okEnv(map[string]interface{}{"ok": true}) // success in the middle
			}
			return errEnv("kernel overloaded")
		}
	})
	cfg := DefaultConfig()
	cfg.MaxRetries = 2
	a := newKernelAgent(t, k, cfg)

	err := a.runOnce(context.Background())
	if !errors.Is(err, ErrKernelUnreachable) {
		t.Fatalf("runOnce = %v, want ErrKernelUnreachable", err)
	}
	// Sequence: fail(1), ok(2) [resets counter], fail(3), fail(4) → unreachable.
	if hbCount.Load() != 4 {
		t.Errorf("heartbeats = %d, want 4 (counter must reset on success)", hbCount.Load())
	}
}

// TestRunGracefulExitOnUnreachable: with MaxRetries=1 and a rejecting kernel,
// Run() exits gracefully (nil) instead of retrying forever.
func TestRunGracefulExitOnUnreachable(t *testing.T) {
	var hbCount atomic.Int32
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		switch env["method"] {
		case "Register":
			return okEnv(map[string]interface{}{"accepted": true, "session_id": "sess-r"})
		default:
			hbCount.Add(1)
			return errEnv("kernel overloaded")
		}
	})
	cfg := DefaultConfig()
	cfg.MaxRetries = 1
	cfg.ReconnectSec = 0
	a := newKernelAgent(t, k, cfg)

	err := a.Run()
	if err != nil {
		t.Fatalf("Run() = %v, want nil (graceful exit)", err)
	}
	if a.IsRunning() {
		t.Error("IsRunning must be false after Run exits")
	}
	if hbCount.Load() < 1 {
		t.Error("Run must have attempted at least one heartbeat")
	}
}

// TestRunResetsIncrementalStateOnSessionError: when runOnce fails with a
// non-unreachable error, Run clears the session and the incremental-send state
// (pkgSent/cpeSent/hashes) so a reconnection re-sends the full list, and the
// client is torn down for reconnect. The test goroutine flips the atomic
// running flag after the first rejected registration so the loop exits without
// racing Run's client field.
func TestRunResetsIncrementalStateOnSessionError(t *testing.T) {
	// Kernel accepts the connection but rejects registration every time →
	// runOnce returns a register error (not ErrKernelUnreachable), which sends
	// Run into the session-error reset path.
	rejected := make(chan struct{}, 1)
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		switch env["method"] {
		case "Register":
			select {
			case rejected <- struct{}{}:
			default:
			}
			return errEnv("host already registered")
		default:
			return errEnv("unexpected call")
		}
	})
	cfg := DefaultConfig()
	cfg.MaxRetries = 3
	cfg.ReconnectSec = 0 // tight retry loop so the stop lands promptly
	a := newKernelAgent(t, k, cfg)
	// sessionID starts empty so runOnce attempts registration (register is
	// skipped when a session already exists) — the rejection then drives the
	// session-error reset path.
	a.pkgSent = true
	a.cpeSent = true
	a.pkgHash = [32]byte{1}
	a.cpeHash = [32]byte{2}

	done := make(chan error, 1)
	go func() { done <- a.Run() }()

	// Wait for the first rejected registration, then stop the loop. Only the
	// atomic running flag is touched from this goroutine.
	<-rejected
	a.running.Store(false)
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v, want nil after stop", err)
	}

	if a.sessionID != "" {
		t.Errorf("sessionID must be cleared on session error, got %q", a.sessionID)
	}
	if a.pkgSent || a.cpeSent {
		t.Errorf("incremental state must reset: pkgSent=%v cpeSent=%v", a.pkgSent, a.cpeSent)
	}
	if a.pkgHash != [32]byte{} || a.cpeHash != [32]byte{} {
		t.Errorf("hashes must be zeroed after session error: pkg=%x cpe=%x", a.pkgHash, a.cpeHash)
	}
	if a.client != nil {
		t.Error("client must be torn down for reconnect")
	}
}

// TestStopClosesClient: Stop() tears down an attached client (client_test
// coverage for the Stop path with a live connection).
func TestStopClosesClient(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{})
	})
	a := &Agent{}
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	a.running.Store(true)

	a.Stop()
	if a.IsRunning() {
		t.Error("IsRunning must be false after Stop")
	}
	if a.client.Connected() {
		t.Error("client must be closed by Stop")
	}
}

// TestRegisterAcceptedStoresSession: register() stores the kernel-issued
// session ID; a rejection surfaces an error.
func TestRegisterAcceptedStoresSession(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{"accepted": true, "session_id": "sess-abc"})
	})
	a := &Agent{cfg: AgentConfig{HostID: "h1"}}
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.client.Close() })

	if err := a.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	if a.sessionID != "sess-abc" {
		t.Errorf("sessionID = %q, want sess-abc", a.sessionID)
	}
}

func TestRegisterRejectedReturnsError(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return errEnv("host already registered")
	})
	a := &Agent{cfg: AgentConfig{HostID: "h1"}}
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.client.Close() })

	err := a.register()
	if err == nil {
		t.Fatal("rejected registration must return an error")
	}
	if a.sessionID != "" {
		t.Errorf("sessionID must stay empty after rejection, got %q", a.sessionID)
	}
}

// apiv1 import kept for future envelope assertions in this file.
var _ = apiv1.HeartbeatRequest{}
