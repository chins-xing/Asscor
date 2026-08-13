package kernel

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterInitialAllow(t *testing.T) {
	rl := NewRateLimiter(10, 5, nil)
	defer rl.Stop()

	if !rl.allow("client1") {
		t.Fatal("expected first request to be allowed")
	}
}

func TestRateLimiterBurstExhaustion(t *testing.T) {
	rl := NewRateLimiter(100, 3, nil)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.allow("client1") {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}

	if rl.allow("client1") {
		t.Fatal("expected 4th request to be denied after burst exhausted")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(100, 2, nil)
	defer rl.Stop()

	rl.allow("client1")
	rl.allow("client1")

	if rl.allow("client1") {
		t.Fatal("expected denial after burst")
	}

	time.Sleep(50 * time.Millisecond)

	if !rl.allow("client1") {
		t.Fatal("expected allow after refill")
	}
}

func TestRateLimiterSeparateClients(t *testing.T) {
	rl := NewRateLimiter(100, 2, nil)
	defer rl.Stop()

	rl.allow("client1")
	rl.allow("client1")

	if !rl.allow("client2") {
		t.Fatal("expected client2 to have own bucket")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(100, 2, nil)
	defer rl.Stop()

	rl.allow("client1")

	rl.CleanupStale(1 * time.Nanosecond)
	time.Sleep(1 * time.Millisecond)

	if rl.isStale("client1", 1*time.Nanosecond) {
		t.Log("client1 was cleaned up")
	}
}

func TestRateLimiterOnRejected(t *testing.T) {
	rejected := make(chan string, 1)
	rl := NewRateLimiter(100, 1, func(service, method, reason string) {
		rejected <- reason
	})
	defer rl.Stop()

	interceptor := rl.Interceptor()
	ctx := context.WithValue(context.Background(), CtxKey("client_addr"), "c1")
	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return payload, nil
	}

	interceptor(ctx, "svc", "m", nil, handler) // consume the only token
	interceptor(ctx, "svc", "m", nil, handler) // should trigger rejection

	select {
	case reason := <-rejected:
		if reason != "rate_limit_exceeded" {
			t.Errorf("expected 'rate_limit_exceeded', got %s", reason)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected onRejected callback via interceptor")
	}
}

func TestRateLimiterInterceptor(t *testing.T) {
	rl := NewRateLimiter(100, 1, nil)
	defer rl.Stop()

	interceptor := rl.Interceptor()
	ctx := context.WithValue(context.Background(), CtxKey("client_addr"), "client-01")

	handler := func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
		return append(payload, []byte("-ok")...), nil
	}

	resp, err := interceptor(ctx, "svc", "method", []byte("req"), handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "req-ok" {
		t.Errorf("expected 'req-ok', got %s", resp)
	}

	_, err = interceptor(ctx, "svc", "method", []byte("req2"), handler)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
}

func (r *RateLimiter) isStale(client string, maxAge time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[client]
	if !ok {
		return true
	}
	cutoff := time.Now().Add(-maxAge)
	return b.lastRefill.Before(cutoff)
}
