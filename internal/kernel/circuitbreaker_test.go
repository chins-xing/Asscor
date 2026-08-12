package kernel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreakerInitialState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	defer cb.Stop()

	if st := cb.State("svc", "method"); st != StateClosed {
		t.Fatalf("expected StateClosed, got %s", st)
	}
	if !cb.Allow("svc", "method") {
		t.Fatal("expected Allow to return true for closed circuit")
	}
}

func TestCircuitBreakerOpensAfterFailures(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  3,
		WindowSize:   10 * time.Second,
		Timeout:      100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}

	if st := cb.State("s", "m"); st != StateOpen {
		t.Fatalf("expected StateOpen after 5 failures (ratio=1.0 > 0.3), got %s", st)
	}
	if cb.Allow("s", "m") {
		t.Fatal("expected Allow to return false for open circuit")
	}
}

func TestCircuitBreakerHalfOpenAfterTimeout(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  3,
		WindowSize:   10 * time.Second,
		Timeout:      50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}
	if st := cb.State("s", "m"); st != StateOpen {
		t.Fatalf("expected StateOpen, got %s", st)
	}

	time.Sleep(100 * time.Millisecond)

	if st := cb.State("s", "m"); st != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after timeout, got %s", st)
	}
	if !cb.Allow("s", "m") {
		t.Fatal("expected Allow to return true for half-open circuit")
	}
}

func TestCircuitBreakerClosesOnSuccessInHalfOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  3,
		WindowSize:   10 * time.Second,
		Timeout:      50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}
	if st := cb.State("s", "m"); st != StateOpen {
		t.Fatalf("expected StateOpen, got %s", st)
	}

	time.Sleep(100 * time.Millisecond)

	if st := cb.State("s", "m"); st != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after timeout, got %s", st)
	}

	for i := 0; i < 3; i++ {
		cb.RecordSuccess("s", "m")
	}

	st := cb.State("s", "m")
	if st != StateClosed {
		t.Fatalf("expected StateClosed after success in half-open, got %s", st)
	}
}

func TestCircuitBreakerReopensOnFailureInHalfOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  3,
		WindowSize:   10 * time.Second,
		Timeout:      50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}
	if st := cb.State("s", "m"); st != StateOpen {
		t.Fatalf("expected StateOpen, got %s", st)
	}

	time.Sleep(100 * time.Millisecond)

	if st := cb.State("s", "m"); st != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after timeout, got %s", st)
	}

	for i := 0; i < 3; i++ {
		cb.RecordFailure("s", "m")
	}

	st := cb.State("s", "m")
	if st != StateOpen {
		t.Fatalf("expected StateOpen after 3 failures in half-open, got %s", st)
	}
}

func TestCircuitBreakerOnStateChangeCallback(t *testing.T) {
	stateChanges := make(chan string, 4)
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  3,
		WindowSize:   10 * time.Second,
		Timeout:      50 * time.Millisecond,
		OnStateChange: func(service, method string) {
			stateChanges <- method
		},
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}

	select {
	case change := <-stateChanges:
		if change != "opened" {
			t.Errorf("expected 'opened', got %s", change)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for state change callback")
	}
}

func TestCircuitBreakerInterceptor(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  1,
		WindowSize:   10 * time.Second,
		Timeout:      1 * time.Hour,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	interceptor := cb.Interceptor()
	ctx := context.Background()

	successHandler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return []byte("ok"), nil
	}

	resp, err := interceptor(ctx, "svc", "ok", nil, successHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "ok" {
		t.Errorf("expected 'ok', got %s", resp)
	}
	if st := cb.State("svc", "ok"); st != StateClosed {
		t.Errorf("expected StateClosed after success, got %s", st)
	}

	failHandler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return nil, errors.New("fail")
	}

	for i := 0; i < 5; i++ {
		interceptor(ctx, "svc", "fail", nil, failHandler)
	}

	if st := cb.State("svc", "fail"); st != StateOpen {
		t.Fatalf("expected StateOpen after failures, got %s", st)
	}

	_, err = interceptor(ctx, "svc", "fail", nil, failHandler)
	if err == nil {
		t.Fatal("expected circuit breaker open error")
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureRatio: 0.3,
		MinRequests:  1,
		WindowSize:   10 * time.Second,
		Timeout:      1 * time.Hour,
	}
	cb := NewCircuitBreaker(cfg)
	defer cb.Stop()

	for i := 0; i < 5; i++ {
		cb.RecordFailure("s", "m")
	}
	if st := cb.State("s", "m"); st != StateOpen {
		t.Fatalf("expected StateOpen, got %s", st)
	}

	cb.Reset("s", "m")

	if st := cb.State("s", "m"); st != StateClosed {
		t.Fatalf("expected StateClosed after reset, got %s", st)
	}
	if !cb.Allow("s", "m") {
		t.Fatal("expected Allow after reset")
	}
}
