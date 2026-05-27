package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

type RateLimiter struct {
	rate        float64
	burst       int
	mu          sync.Mutex
	buckets     map[string]*clientBucket
	onRejected  func(service, method, reason string)
	cleanupTick *time.Ticker
	stopCleanup chan struct{}
	stopped     bool
}

func NewRateLimiter(ratePerSec float64, burst int, onRejected func(service, method, reason string)) *RateLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 100
	}
	if burst <= 0 {
		burst = int(ratePerSec)
	}
	rl := &RateLimiter{
		rate:       ratePerSec,
		burst:      burst,
		buckets:    make(map[string]*clientBucket),
		onRejected: onRejected,
		stopCleanup: make(chan struct{}),
	}
	rl.startAutoCleanup()
	return rl
}

func (r *RateLimiter) startAutoCleanup() {
	r.cleanupTick = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-r.cleanupTick.C:
				r.CleanupStale(30 * time.Minute)
			case <-r.stopCleanup:
				return
			}
		}
	}()
}

func (r *RateLimiter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleanupTick != nil {
		r.cleanupTick.Stop()
	}
	if !r.stopped {
		r.stopped = true
		close(r.stopCleanup)
	}
}

func (r *RateLimiter) allow(clientAddr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[clientAddr]
	if !ok {
		b = &clientBucket{
			tokens:     float64(r.burst),
			lastRefill: time.Now(),
		}
		r.buckets[clientAddr] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > float64(r.burst) {
			b.tokens = float64(r.burst)
		}
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

func (r *RateLimiter) CleanupStale(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for addr, b := range r.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(r.buckets, addr)
		}
	}
}

func (r *RateLimiter) Interceptor() Interceptor {
	return func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		clientAddr, _ := ctx.Value(ctxKey("client_addr")).(string)
		if clientAddr == "" {
			clientAddr = "unknown"
		}
		if !r.allow(clientAddr) {
			if r.onRejected != nil {
				r.onRejected(service, method, "rate_limit_exceeded")
			}
			return nil, fmt.Errorf("rate limit exceeded: %s/%s (client: %s)", service, method, clientAddr)
		}
		return handler(ctx, service, method, payload)
	}
}
