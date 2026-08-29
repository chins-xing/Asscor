package agent

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/model"
)

// TestRunChecksConcurrencyLimit: with more than checkConcurrency (10) blocking
// checkers, runChecks never runs more than 10 concurrently — the semaphore
// bounds parallelism and the slow checkers do not block the rest of the set.
func TestRunChecksConcurrencyLimit(t *testing.T) {
	const total = 15 // > checkConcurrency

	var running, maxRunning int32
	gate := make(chan struct{})
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	defer release() // never leave blocked checkers behind on failure

	checkers := make([]model.CheckItem, total)
	for i := range checkers {
		checkers[i] = model.CheckItem{
			ID:     fmt.Sprintf("CC-%03d", i),
			Domain: model.DomainAttackSurface,
			Name:   fmt.Sprintf("blocking check %d", i),
			Delta:  -1,
			Check: func() (bool, string) {
				cur := atomic.AddInt32(&running, 1)
				for {
					m := atomic.LoadInt32(&maxRunning)
					if cur <= m || atomic.CompareAndSwapInt32(&maxRunning, m, cur) {
						break
					}
				}
				<-gate // block until the test releases everyone
				atomic.AddInt32(&running, -1)
				return true, "ok"
			},
		}
	}
	a := &Agent{cfg: AgentConfig{CheckTimeoutSec: 5}, checkers: checkers}

	done := make(chan []model.CheckResult, 1)
	go func() { done <- a.runChecks() }()

	// Wait until the worker pool is saturated (all 10 slots busy).
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&running) < checkConcurrency {
		if time.Now().After(deadline) {
			release()
			t.Fatalf("checks never saturated the pool: running=%d", atomic.LoadInt32(&running))
		}
		time.Sleep(2 * time.Millisecond)
	}

	// While blocked, no more than checkConcurrency may be in flight.
	if m := atomic.LoadInt32(&maxRunning); m > checkConcurrency {
		release()
		t.Fatalf("max concurrent = %d, want <= %d", m, checkConcurrency)
	}
	if m := atomic.LoadInt32(&maxRunning); m != checkConcurrency {
		release()
		t.Fatalf("pool should saturate at %d, got max %d", checkConcurrency, m)
	}

	release()
	results := <-done

	if len(results) != total {
		t.Fatalf("results = %d, want %d", len(results), total)
	}
	// Result order must be preserved (checker order).
	for i, r := range results {
		if want := fmt.Sprintf("CC-%03d", i); r.CheckID != want {
			t.Errorf("results[%d].CheckID = %q, want %q", i, r.CheckID, want)
		}
	}
	if m := atomic.LoadInt32(&maxRunning); m > checkConcurrency {
		t.Errorf("max concurrent = %d, want <= %d", m, checkConcurrency)
	}
}
