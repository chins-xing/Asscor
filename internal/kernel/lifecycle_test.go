package kernel

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// mockLocator is a controllable Locator for lifecycle tests.
type mockLocator struct {
	mu        sync.Mutex
	loc       *AttackerLocation
	active    bool
	locateCalls int
}

func (m *mockLocator) Locate(ctx context.Context, hostID string) (*AttackerLocation, error) {
	m.mu.Lock()
	m.locateCalls++
	m.mu.Unlock()
	return m.loc, nil
}

func (m *mockLocator) HasActiveThreat(ctx context.Context, hostID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *mockLocator) setActive(active bool) {
	m.mu.Lock()
	m.active = active
	m.mu.Unlock()
}

// mockGuider is a controllable Guider for lifecycle guide-first tests.
type mockGuider struct {
	calls    int
	captures int
	err      error
}

func (m *mockGuider) Guide(ctx context.Context, loc *AttackerLocation) (int, error) {
	m.calls++
	return m.captures, m.err
}

// mockBlocker counts Block invocations for fallback tests.
type mockBlocker struct {
	calls int
}

func (m *mockBlocker) Block(ctx context.Context, loc *AttackerLocation) (*BlockResult, error) {
	m.calls++
	return &BlockResult{Blocked: true, RuleID: "mock"}, nil
}
func (m *mockBlocker) Unblock(ctx context.Context, loc *AttackerLocation) error { return nil }
func (m *mockBlocker) IsBlocked(ctx context.Context, hostID string) bool       { return false }

func TestLifecycleEngineGuideSkipsBlock(t *testing.T) {
	e := NewLifecycleEngine(nil)
	e.SetLocator(&mockLocator{loc: &AttackerLocation{FootholdHost: "h"}})
	e.SetActivityStore(newInMemActivityStore())
	g := &mockGuider{captures: 1}
	b := &mockBlocker{}
	e.SetGuider(g)
	e.SetBlocker(b)

	e.Run(context.Background(), "h")

	if g.calls == 0 {
		t.Fatal("expected Guide to be called")
	}
	if b.calls != 0 {
		t.Errorf("expected Block to be skipped when guidance succeeds, got %d block calls", b.calls)
	}
}

func TestLifecycleEngineFallsBackToBlockOnGuideError(t *testing.T) {
	e := NewLifecycleEngine(nil)
	e.SetLocator(&mockLocator{loc: &AttackerLocation{FootholdHost: "h"}})
	e.SetActivityStore(newInMemActivityStore())
	g := &mockGuider{err: errors.New("deploy failed")}
	b := &mockBlocker{}
	e.SetGuider(g)
	e.SetBlocker(b)

	e.Run(context.Background(), "h")

	if b.calls == 0 {
		t.Fatal("expected Block to be called when guidance fails")
	}
}

func TestLifecycleEngineBlocksWithoutGuider(t *testing.T) {
	e := NewLifecycleEngine(nil)
	e.SetLocator(&mockLocator{loc: &AttackerLocation{FootholdHost: "h"}})
	e.SetActivityStore(newInMemActivityStore())
	b := &mockBlocker{}
	e.SetBlocker(b)

	e.Run(context.Background(), "h")

	if b.calls == 0 {
		t.Fatal("expected Block to be called when no guider is set")
	}
}

func TestLifecycleEngineRunOnce(t *testing.T) {
	e := NewLifecycleEngine(nil)
	loc := &mockLocator{loc: &AttackerLocation{FootholdHost: "h", ActiveSubnets: []string{"10.0.0.0/24"}}}
	e.SetLocator(loc)
	e.SetActivityStore(newInMemActivityStore())

	e.Run(context.Background(), "h")

	if loc.locateCalls < 1 {
		t.Fatal("expected at least one Locate call")
	}
}

func TestLifecycleEngineLoopsOnActiveThreat(t *testing.T) {
	e := NewLifecycleEngine(nil)
	loc := &mockLocator{loc: &AttackerLocation{FootholdHost: "h"}}
	loc.setActive(true)
	e.SetLocator(loc)
	e.SetActivityStore(newInMemActivityStore())

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay — Run must respect ctx.Done in its backoff.
	go func() {
		cancel()
	}()
	e.Run(ctx, "h")

	// With active threat, Run loops (bounded by maxIterations + ctx cancellation).
	// The test just asserts it terminates (no hang) — the ctx cancellation path
	// aborts the loop.
}

func TestKernelLocatorHasActiveThreat(t *testing.T) {
	// No kernel → no policy → no active threat.
	l := NewKernelLocator(nil)
	if l.HasActiveThreat(context.Background(), "h") {
		t.Error("expected no active threat with nil kernel")
	}
}

func TestLifecycleEngineStops(t *testing.T) {
	e := NewLifecycleEngine(nil)
	e.mu.Lock()
	e.state = PluginStarted
	e.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx, e.cancel = context.WithCancel(ctx)
	_ = cancel

	if err := e.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if e.State() != PluginStopped {
		t.Errorf("expected stopped, got %s", e.State())
	}
}
