package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type RateLimiter struct {
	rate       float64
	burst      int
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
	onRejected func(service, method, reason string)
}

func NewRateLimiter(ratePerSec float64, burst int, onRejected func(service, method, reason string)) *RateLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 100
	}
	if burst <= 0 {
		burst = int(ratePerSec)
	}
	return &RateLimiter{
		rate:       ratePerSec,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
		onRejected: onRejected,
	}
}

func (r *RateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	if elapsed > 0 {
		refill := elapsed * r.rate
		r.tokens += refill
		if r.tokens > float64(r.burst) {
			r.tokens = float64(r.burst)
		}
	}
	r.lastRefill = now

	if r.tokens >= 1.0 {
		r.tokens -= 1.0
		return true
	}
	return false
}

func (r *RateLimiter) Interceptor() Interceptor {
	return func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		if !r.allow() {
			if r.onRejected != nil {
				r.onRejected(service, method, "rate_limit_exceeded")
			}
			return nil, fmt.Errorf("rate limit exceeded: %s/%s", service, method)
		}
		return handler(ctx, service, method, payload)
	}
}