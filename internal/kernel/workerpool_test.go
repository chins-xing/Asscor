package kernel

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerPoolDefaultConcurrency: NewWorkerPool(0 / negative) falls back to
// 10 (default).
func TestWorkerPoolDefaultConcurrency(t *testing.T) {
	for _, n := range []int{0, -1} {
		p := NewWorkerPool(n)
		if got := p.MaxConcurrency(); got != 10 {
			t.Errorf("NewWorkerPool(%d).MaxConcurrency() = %d, want 10", n, got)
		}
	}
}

// TestWorkerPoolTaskErrorCountsFailed: a task returning an error increments
// totalFailed.
func TestWorkerPoolTaskErrorCountsFailed(t *testing.T) {
	p := NewWorkerPool(2)
	p.Submit(func() error { return errors.New("boom") })
	p.Submit(func() error { return nil })
	p.Wait()

	m := p.Metrics()
	if m.totalFailed != 1 {
		t.Errorf("totalFailed = %d, want 1", m.totalFailed)
	}
	if m.totalCompleted != 1 {
		t.Errorf("totalCompleted = %d, want 1", m.totalCompleted)
	}
}

// TestWorkerPoolPanicCountsFailed: a panicking task is recovered and counted
// as failed; Wait must not deadlock.
func TestWorkerPoolPanicCountsFailed(t *testing.T) {
	p := NewWorkerPool(2)
	p.Submit(func() error { panic("kaboom") })
	p.Submit(func() error { return nil })
	p.Wait()

	m := p.Metrics()
	if m.totalFailed != 1 {
		t.Errorf("totalFailed = %d, want 1 after panic", m.totalFailed)
	}
}

// TestWorkerPoolSubmitAfterShutdown: submitting after Shutdown() must not run
// the task and Wait must return promptly (no goroutine leak, no deadlock).
func TestWorkerPoolSubmitAfterShutdown(t *testing.T) {
	p := NewWorkerPool(2)
	ran := int32(0)
	p.Shutdown()

	p.Submit(func() error { atomic.StoreInt32(&ran, 1); return nil })
	p.Wait() // must return immediately

	if atomic.LoadInt32(&ran) != 0 {
		t.Error("task must not run after Shutdown")
	}
}

// TestWorkerPoolActiveAvailableSlots: with the pool saturated, active workers
// equal the cap and available slots are zero; after completion they drain.
func TestWorkerPoolActiveAvailableSlots(t *testing.T) {
	p := NewWorkerPool(2)
	release := make(chan struct{})

	p.Submit(func() error { <-release; return nil })
	p.Submit(func() error { <-release; return nil })

	// Wait for both to acquire the semaphore.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.ActiveWorkers() == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := p.ActiveWorkers(); got != 2 {
		t.Errorf("ActiveWorkers() = %d, want 2 (saturated)", got)
	}
	if got := p.AvailableSlots(); got != 0 {
		t.Errorf("AvailableSlots() = %d, want 0 (saturated)", got)
	}

	close(release)
	p.Wait()
	if got := p.ActiveWorkers(); got != 0 {
		t.Errorf("ActiveWorkers() after drain = %d, want 0", got)
	}
}

// TestWorkerPoolOnTaskTimeoutCallback: the timeout callback fires when a task
// exceeds its deadline.
func TestWorkerPoolOnTaskTimeoutCallback(t *testing.T) {
	p := NewWorkerPool(2)
	called := int32(0)
	p.SetOnTaskTimeout(func() { atomic.AddInt32(&called, 1) })

	p.SubmitWithTimeout(func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}, 20*time.Millisecond)

	time.Sleep(250 * time.Millisecond)
	p.Wait()
	if atomic.LoadInt32(&called) == 0 {
		t.Error("onTaskTimeout callback must fire on task timeout")
	}
	if m := p.Metrics(); m.totalTimeout == 0 {
		t.Error("totalTimeout must be > 0")
	}
}

// TestWorkerPoolPeakActiveWorkers: the peak metric must reflect the real
// high-water mark of concurrent tasks (regression for the field that was
// declared and read but never updated).
func TestWorkerPoolPeakActiveWorkers(t *testing.T) {
	p := NewWorkerPool(3)
	release := make(chan struct{})

	for i := 0; i < 3; i++ {
		p.Submit(func() error { <-release; return nil })
	}
	// Wait until all three hold a slot, then release.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.ActiveWorkers() == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	p.Wait()

	if m := p.Metrics(); m.peakActiveWorkers != 3 {
		t.Errorf("peakActiveWorkers = %d, want 3", m.peakActiveWorkers)
	}
}

// TestWorkerPoolMetricsResetRoundTrip: Metrics snapshot + ResetMetrics clears
// counters but the pool keeps working afterwards.
func TestWorkerPoolMetricsResetRoundTrip(t *testing.T) {
	p := NewWorkerPool(2)
	p.Submit(func() error { return errors.New("x") })
	p.Wait()

	m := p.Metrics()
	if m.totalFailed != 1 {
		t.Fatalf("pre-reset totalFailed = %d, want 1", m.totalFailed)
	}
	if m.lastReset.IsZero() {
		t.Error("lastReset must be set")
	}

	p.ResetMetrics()
	m2 := p.Metrics()
	if m2.totalFailed != 0 || m2.totalCompleted != 0 || m2.totalTimeout != 0 {
		t.Errorf("post-reset counters not zero: %+v", m2)
	}

	// Pool still functional after reset.
	p.Submit(func() error { return nil })
	p.Wait()
	if m3 := p.Metrics(); m3.totalCompleted != 1 {
		t.Errorf("post-reset totalCompleted = %d, want 1", m3.totalCompleted)
	}
}
