//go:build resilience

package resilience

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// resetBreakers clears the global breaker/health maps so each test starts
// from a clean slate (the real code keeps them for the process lifetime).
func resetBreakers() {
	breakersMu.Lock()
	breakers = map[string]*breaker{}
	breakersMu.Unlock()
	healthMu.Lock()
	health = map[string]*ModuleHealth{}
	healthMu.Unlock()
}

// newShortBreaker installs a breaker with a tiny threshold/window/cooldown
// so state transitions can be exercised without real timeouts.
func newShortBreaker(t *testing.T, module string, threshold int, window, cooldown time.Duration) *breaker {
	t.Helper()
	b := &breaker{
		state:     StateClosed,
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
	}
	breakersMu.Lock()
	breakers[module] = b
	breakersMu.Unlock()
	return b
}

func TestCircuitOpensAfterThreshold(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-1", 3, time.Minute, time.Minute)

	for i := 0; i < 3; i++ {
		RecordFailure("test-mod-1", errors.New("boom"))
	}
	if b.state != StateOpen {
		t.Fatalf("state = %v, want open after threshold", b.state)
	}
	if b.totalTrips != 1 {
		t.Errorf("totalTrips = %d, want 1", b.totalTrips)
	}
	// While open and inside cooldown, Allow must refuse.
	if Allow("test-mod-1") {
		t.Error("Allow must be false while circuit is open")
	}
}

func TestCircuitResetOnSuccessBeforeThreshold(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-2", 5, time.Minute, time.Minute)

	RecordFailure("test-mod-2", errors.New("f1"))
	RecordFailure("test-mod-2", errors.New("f2"))
	if b.state != StateClosed {
		t.Fatalf("state = %v, want still closed", b.state)
	}
	RecordSuccess("test-mod-2") // below threshold success resets failures
	if b.failures != 0 {
		t.Errorf("failures = %d, want 0 after success", b.failures)
	}
	if b.state != StateClosed {
		t.Errorf("state = %v, want closed", b.state)
	}
}

func TestHalfOpenAllowsTrialThenClosesOnSuccess(t *testing.T) {
	resetBreakers()
	// Expire cooldown immediately by making it negative so time.Since > cooldown.
	b := newShortBreaker(t, "test-mod-3", 1, time.Minute, -time.Second)

	RecordFailure("test-mod-3", errors.New("x"))
	if b.state != StateOpen {
		t.Fatalf("state = %v, want open", b.state)
	}
	if !Allow("test-mod-3") {
		t.Fatal("Allow must transition open→half-open after cooldown and permit the trial")
	}
	if b.state != StateHalfOpen {
		t.Fatalf("state = %v, want half-open after cooldown expiry", b.state)
	}
	// Second Allow while half-open must refuse (only one trial).
	if Allow("test-mod-3") {
		t.Error("Allow must be false while half-open (single trial only)")
	}
	// Trial succeeds → close.
	RecordSuccess("test-mod-3")
	if b.state != StateClosed {
		t.Fatalf("state = %v, want closed after trial success", b.state)
	}
	if !Allow("test-mod-3") {
		t.Error("Allow must be true after circuit closes")
	}
}

func TestHalfOpenReopensOnTrialFailure(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-4", 1, time.Minute, -time.Second)

	RecordFailure("test-mod-4", errors.New("x"))
	if !Allow("test-mod-4") { // → half-open, trial allowed
		t.Fatal("trial should be allowed")
	}
	RecordFailure("test-mod-4", errors.New("still broken"))
	if b.state != StateOpen {
		t.Fatalf("state = %v, want open again after trial failure", b.state)
	}
	if b.totalTrips != 2 {
		t.Errorf("totalTrips = %d, want 2", b.totalTrips)
	}
}

func TestAllowInsideCooldownRefuses(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-5", 1, time.Minute, 10*time.Minute)

	RecordFailure("test-mod-5", errors.New("x"))
	if Allow("test-mod-5") {
		t.Error("Allow must refuse while inside a long cooldown")
	}
	if b.state != StateOpen {
		t.Fatalf("state = %v, want open (no auto half-open yet)", b.state)
	}
}

func TestResetManualClosesCircuit(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-6", 1, time.Minute, time.Hour)
	RecordFailure("test-mod-6", errors.New("x"))
	if b.state != StateOpen {
		t.Fatal("breaker should be open")
	}
	Reset("test-mod-6")
	if b.state != StateClosed || b.failures != 0 || b.successes != 0 {
		t.Errorf("after Reset: state=%v failures=%d successes=%d, want closed/0/0",
			b.state, b.failures, b.successes)
	}
	if !Allow("test-mod-6") {
		t.Error("Allow must be true after manual reset")
	}
}

func TestStatusReportsState(t *testing.T) {
	resetBreakers()
	b := newShortBreaker(t, "test-mod-7", 1, time.Minute, time.Hour)
	RecordFailure("test-mod-7", errors.New("x"))

	st, msg := Status("test-mod-7")
	if st != StateOpen {
		t.Errorf("status state = %v, want open", st)
	}
	if msg == "" {
		t.Error("status message must not be empty when open")
	}

	Reset("test-mod-7")
	st, _ = Status("test-mod-7")
	if st != StateClosed {
		t.Errorf("after reset status = %v, want closed", st)
	}
	_ = b
}

func TestGuardCatchesPanicAndRecordsFailure(t *testing.T) {
	resetBreakers()
	newShortBreaker(t, "guard-mod", 1, time.Minute, time.Hour)

	err := Guard("guard-mod", "op", func() error {
		panic("kaboom")
	})
	if err == nil {
		t.Fatal("Guard must return the panic as an error")
	}
	if !strings.Contains(err.Error(), "panicked during") {
		t.Errorf("error should describe the panic, got: %v", err)
	}
	// Panic must have tripped the failure counter toward the breaker.
	b := getBreaker("guard-mod")
	if b.failures != 1 {
		t.Errorf("failures = %d, want 1 after panic", b.failures)
	}
}

func TestGuardRecordsFailureAndSuccess(t *testing.T) {
	resetBreakers()
	newShortBreaker(t, "guard-mod2", 5, time.Minute, time.Hour)

	// fn returns error → RecordFailure
	err := Guard("guard-mod2", "op", func() error { return errors.New("call failed") })
	if err == nil {
		t.Fatal("Guard must propagate the function error")
	}
	if b := getBreaker("guard-mod2"); b.failures != 1 {
		t.Errorf("failures = %d, want 1", b.failures)
	}

	// fn succeeds → RecordSuccess resets failures
	if err := Guard("guard-mod2", "op", func() error { return nil }); err != nil {
		t.Fatalf("successful guard returned err: %v", err)
	}
	if b := getBreaker("guard-mod2"); b.failures != 0 {
		t.Errorf("failures = %d, want 0 after success", b.failures)
	}
}

func TestGuardGoBlockedWhenOpen(t *testing.T) {
	resetBreakers()
	newShortBreaker(t, "guardgo-mod", 1, time.Minute, time.Hour)
	RecordFailure("guardgo-mod", errors.New("x")) // opens

	ran := make(chan struct{}, 1)
	GuardGo("guardgo-mod", "op", func() { ran <- struct{}{} })
	// Circuit is open: GuardGo returns WITHOUT launching the goroutine. Give a
	// short grace window to catch an erroneous launch, then assert none ran.
	select {
	case <-ran:
		t.Fatal("GuardGo must not launch the goroutine while the circuit is open")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestGuardGoRunsWhenClosed(t *testing.T) {
	resetBreakers()
	ran := make(chan struct{})
	GuardGo("guardgo-ok", "op", func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("GuardGo should have launched the goroutine (circuit closed)")
	}
}

func TestErrorRateLimiter(t *testing.T) {
	rl := NewErrorRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.AllowError() {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	if rl.AllowError() {
		t.Error("4th call within the minute must be dropped")
	}
	// Window rollover: force a fresh window and confirm the budget resets.
	rl.window = time.Now().Add(-2 * time.Minute)
	if !rl.AllowError() {
		t.Error("call after window rollover must be allowed again")
	}
}

func TestHealthTracking(t *testing.T) {
	resetBreakers()
	if !IsHealthy() {
		t.Error("empty health map must be healthy")
	}
	ReportHealth("mod-a", true, "ok")
	ReportHealth("mod-b", false, "down")
	if IsHealthy() {
		t.Error("IsHealthy must be false when a module reports unhealthy")
	}
	ReportPanic("mod-c")
	ReportRestart("mod-c")
	summary := HealthSummary()
	if len(summary) != 3 {
		t.Fatalf("HealthSummary length = %d, want 3", len(summary))
	}
	found := false
	for _, h := range summary {
		if h.Name == "mod-c" {
			found = true
			if h.Panics != 1 || h.Restarts != 1 || h.Healthy {
				t.Errorf("mod-c health = %+v, want 1 panic 1 restart unhealthy", h)
			}
		}
	}
	if !found {
		t.Error("mod-c missing from health summary")
	}
}
