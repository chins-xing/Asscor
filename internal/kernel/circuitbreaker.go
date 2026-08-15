package kernel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type CircuitState int32

const (
	StateClosed   CircuitState = 0
	StateOpen     CircuitState = 1
	StateHalfOpen CircuitState = 2
)

const maxWindowSize = 1000

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

type CircuitBreakerConfig struct {
	FailureRatio     float64
	MinRequests      int
	Timeout          time.Duration
	WindowSize       time.Duration
	OnStateChange    func(service, method string)
	Extensions       ModuleExtensions
	HalfOpenMaxFails int
}

type windowEntry struct {
	timestamp time.Time
	success   bool
}

type circuitRecord struct {
	state           int32
	lastStateChange time.Time
	mu              sync.Mutex
	window          []windowEntry
	halfOpenFails   int
}

func (cb *CircuitBreaker) fireBreakerExtension(k, state string) {
	if cb.cfg.Extensions == nil {
		return
	}
	parts := strings.IndexByte(k, '/')
	svc, method := k, ""
	if parts >= 0 {
		svc, method = k[:parts], k[parts+1:]
	}
	cb.cfg.Extensions.Execute(context.Background(), "breaker.state_changed", map[string]interface{}{
		"service": svc, "method": method, "state": state,
	})
}

func (r *circuitRecord) addEntry(success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.window = append(r.window, windowEntry{
		timestamp: time.Now(),
		success:   success,
	})
	if len(r.window) > maxWindowSize {
		r.window = r.window[len(r.window)-maxWindowSize:]
	}
}

func (r *circuitRecord) pruneWindow(windowSize time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-windowSize)
	idx := 0
	for idx < len(r.window) && r.window[idx].timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		r.window = r.window[idx:]
	}
}

func (r *circuitRecord) stats(windowSize time.Duration) (failures, successes int) {
	r.pruneWindow(windowSize)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.window {
		if e.success {
			successes++
		} else {
			failures++
		}
	}
	return
}

type CircuitBreaker struct {
	mu            sync.RWMutex
	records       map[string]*circuitRecord
	cfg           CircuitBreakerConfig
	stopCleanup   chan struct{}
	cleanupTicker *time.Ticker
}

func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureRatio <= 0 {
		cfg.FailureRatio = 0.5
	}
	if cfg.MinRequests <= 0 {
		cfg.MinRequests = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 60 * time.Second
	}
	cb := &CircuitBreaker{
		records:       make(map[string]*circuitRecord),
		cfg:           cfg,
		stopCleanup:   make(chan struct{}),
		cleanupTicker: time.NewTicker(5 * time.Minute),
	}
	go cb.cleanupLoop()
	return cb
}

func (cb *CircuitBreaker) cleanupLoop() {
	for {
		select {
		case <-cb.cleanupTicker.C:
			cb.cleanupStaleRecords()
		case <-cb.stopCleanup:
			return
		}
	}
}

func (cb *CircuitBreaker) cleanupStaleRecords() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	staleThreshold := 15 * time.Minute
	now := time.Now()
	for k, rec := range cb.records {
		rec.mu.Lock()
		lastChange := rec.lastStateChange
		rec.mu.Unlock()
		if now.Sub(lastChange) > staleThreshold {
			state := CircuitState(atomic.LoadInt32(&rec.state))
			if state == StateClosed {
				delete(cb.records, k)
			}
		}
	}
}

func (cb *CircuitBreaker) Stop() {
	close(cb.stopCleanup)
	cb.cleanupTicker.Stop()
}

func (cb *CircuitBreaker) Allow(service, method string) bool {
	s := cb.state(key(service, method))
	return s == StateClosed || s == StateHalfOpen
}

func (cb *CircuitBreaker) RecordSuccess(service, method string) {
	cb.recordSuccess(key(service, method))
}

func (cb *CircuitBreaker) RecordFailure(service, method string) {
	cb.recordFailure(key(service, method))
}

func key(service, method string) string {
	return service + "/" + method
}

func (cb *CircuitBreaker) getRecord(k string) *circuitRecord {
	cb.mu.RLock()
	rec, ok := cb.records[k]
	cb.mu.RUnlock()
	if !ok {
		cb.mu.Lock()
		rec, ok = cb.records[k]
		if !ok {
			rec = &circuitRecord{}
			cb.records[k] = rec
		}
		cb.mu.Unlock()
	}
	return rec
}

func (cb *CircuitBreaker) state(k string) CircuitState {
	rec := cb.getRecord(k)
	state := CircuitState(atomic.LoadInt32(&rec.state))

	if state == StateOpen {
		rec.mu.Lock()
		lastChange := rec.lastStateChange
		rec.mu.Unlock()
		if time.Since(lastChange) > cb.cfg.Timeout {
			if atomic.CompareAndSwapInt32(&rec.state, int32(StateOpen), int32(StateHalfOpen)) {
				rec.lastStateChange = time.Now()
				if cb.cfg.OnStateChange != nil {
					cb.cfg.OnStateChange(k, "state_change_to_half_open")
				}
				cb.fireBreakerExtension(k, "half_open")
			}
			return StateHalfOpen
		}
	}

	return state
}

func (cb *CircuitBreaker) recordFailure(k string) {
	rec := cb.getRecord(k)
	rec.addEntry(false)

	state := CircuitState(atomic.LoadInt32(&rec.state))

	switch state {
	case StateClosed:
		failures, successes := rec.stats(cb.cfg.WindowSize)
		total := failures + successes
		if total >= cb.cfg.MinRequests && total > 0 {
			ratio := float64(failures) / float64(total)
			if ratio >= cb.cfg.FailureRatio {
				if atomic.CompareAndSwapInt32(&rec.state, int32(StateClosed), int32(StateOpen)) {
					rec.mu.Lock()
					rec.lastStateChange = time.Now()
					rec.mu.Unlock()
					if cb.cfg.OnStateChange != nil {
						cb.cfg.OnStateChange(k, "opened")
					}
					cb.fireBreakerExtension(k, "open")
				}
			}
		}
	case StateHalfOpen:
		rec.halfOpenFails++
		maxFails := cb.cfg.HalfOpenMaxFails
		if maxFails <= 0 {
			maxFails = 3
		}
		if rec.halfOpenFails >= maxFails {
			if atomic.CompareAndSwapInt32(&rec.state, int32(StateHalfOpen), int32(StateOpen)) {
				rec.halfOpenFails = 0
				rec.mu.Lock()
				rec.lastStateChange = time.Now()
				rec.mu.Unlock()
				if cb.cfg.OnStateChange != nil {
					cb.cfg.OnStateChange(k, "reopened")
				}
				cb.fireBreakerExtension(k, "open")
			}
		}
	}
}

func (cb *CircuitBreaker) recordSuccess(k string) {
	rec := cb.getRecord(k)
	rec.addEntry(true)
	rec.pruneWindow(cb.cfg.WindowSize)

	state := CircuitState(atomic.LoadInt32(&rec.state))

	switch state {
	case StateHalfOpen:
		if atomic.CompareAndSwapInt32(&rec.state, int32(StateHalfOpen), int32(StateClosed)) {
			rec.halfOpenFails = 0
			rec.mu.Lock()
			rec.window = rec.window[:0]
			rec.lastStateChange = time.Now()
			rec.mu.Unlock()
			if cb.cfg.OnStateChange != nil {
				cb.cfg.OnStateChange(k, "closed")
			}
			cb.fireBreakerExtension(k, "closed")
		}
	}
}

func (cb *CircuitBreaker) Interceptor() Interceptor {
	return func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		k := key(service, method)
		st := cb.state(k)

		if st == StateOpen {
			return nil, fmt.Errorf("circuit breaker open: %s", k)
		}

		resp, err := handler(ctx, service, method, payload)

		if err != nil {
			cb.recordFailure(k)
		} else {
			cb.recordSuccess(k)
		}

		return resp, err
	}
}

func (cb *CircuitBreaker) State(service, method string) CircuitState {
	return cb.state(key(service, method))
}

func (cb *CircuitBreaker) Reset(service, method string) {
	k := key(service, method)
	cb.mu.Lock()
	rec, ok := cb.records[k]
	if ok {
		atomic.StoreInt32(&rec.state, int32(StateClosed))
		rec.mu.Lock()
		rec.window = rec.window[:0]
		rec.mu.Unlock()
	}
	cb.mu.Unlock()
}

func (cb *CircuitBreaker) Stats(service, method string) (CircuitState, int, int) {
	k := key(service, method)
	rec := cb.getRecord(k)
	state := CircuitState(atomic.LoadInt32(&rec.state))
	failures, successes := rec.stats(cb.cfg.WindowSize)
	return state, failures, successes
}
