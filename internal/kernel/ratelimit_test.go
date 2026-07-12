package kernel

import "testing"

func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := NewRateLimiter(100, 5, nil)

	for i := 0; i < 5; i++ {
		if !rl.allow("client-a") {
			t.Fatalf("expected allow=true for request %d within burst", i+1)
		}
	}
}

func TestRateLimiter_BlocksBeyondBurst(t *testing.T) {
	rl := NewRateLimiter(0.1, 2, nil)

	for i := 0; i < 2; i++ {
		rl.allow("client-a")
	}
	if rl.allow("client-a") {
		t.Fatal("expected allow=false after burst exhausted")
	}
}

func TestRateLimiter_ClientsIsolated(t *testing.T) {
	rl := NewRateLimiter(0.1, 2, nil)

	for i := 0; i < 2; i++ {
		rl.allow("client-a")
	}
	if !rl.allow("client-b") {
		t.Fatal("expected client-b unaffected by client-a limits")
	}
}

func TestRateLimiter_StopDoubleCall(t *testing.T) {
	rl := NewRateLimiter(100, 5, nil)
	rl.Stop()
	rl.Stop() // double-stop must not panic
}
