package kernel

import (
	"testing"
	"time"
)

func TestCircuitBreaker_AllowInitially(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureRatio: 0.5,
		MinRequests:  5,
		Timeout:      100 * time.Millisecond,
		WindowSize:   10 * time.Second,
	})
	defer cb.Stop()

	if !cb.Allow("svc", "op") {
		t.Fatal("expected Allow to return true for fresh circuit")
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureRatio: 0.1,
		MinRequests:  3,
		Timeout:      500 * time.Second,
		WindowSize:   60 * time.Second,
	})
	defer cb.Stop()

	for i := 0; i < 10; i++ {
		cb.RecordFailure("svc", "op")
	}

	if cb.Allow("svc", "op") {
		t.Fatal("expected circuit to open after exceeding failure ratio")
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureRatio: 0.1,
		MinRequests:  3,
		Timeout:      50 * time.Millisecond,
		WindowSize:   60 * time.Second,
	})
	defer cb.Stop()

	for i := 0; i < 10; i++ {
		cb.RecordFailure("svc", "op")
	}
	if cb.Allow("svc", "op") {
		t.Fatal("expected open initially")
	}

	time.Sleep(100 * time.Millisecond)

	if !cb.Allow("svc", "op") {
		t.Fatal("expected half-open (Allow=true) after timeout")
	}
	// After a successful trial in half-open, circuit closes.
	cb.RecordSuccess("svc", "op")
	if !cb.Allow("svc", "op") {
		t.Fatal("expected closed after successful half-open trial")
	}
}

func TestCircuitBreaker_ClosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureRatio: 0.1,
		MinRequests:  3,
		Timeout:      30 * time.Millisecond,
		WindowSize:   60 * time.Second,
	})
	defer cb.Stop()

	for i := 0; i < 10; i++ {
		cb.RecordFailure("svc", "op")
	}
	time.Sleep(50 * time.Millisecond)
	cb.Allow("svc", "op")
	cb.RecordSuccess("svc", "op")

	if !cb.Allow("svc", "op") {
		t.Fatal("expected circuit to close after successful half-open trial")
	}
}

func TestCircuitBreaker_ServiceIsolation(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureRatio: 0.1,
		MinRequests:  3,
		Timeout:      500 * time.Second,
		WindowSize:   60 * time.Second,
	})
	defer cb.Stop()

	for i := 0; i < 10; i++ {
		cb.RecordFailure("svc-a", "op")
	}

	if !cb.Allow("svc-b", "op") {
		t.Fatal("expected service isolation: svc-b should be unaffected by svc-a failures")
	}
}
