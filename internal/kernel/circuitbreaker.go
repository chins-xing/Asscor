package kernel

import (
	"context"
	"fmt"
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
	FailureRatio  float64
	MinRequests   int
	Timeout       time.Duration
	OnStateChange func(service, method string)
}

type circuitRecord struct {
	state         int32
	failures      int32
	successes     int32
	lastStateChange time.Time
}

type CircuitBreaker struct {
	mu      sync.RWMutex
	records map[string]*circuitRecord
	cfg     CircuitBreakerConfig
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
	return &CircuitBreaker{
		records: make(map[string]*circuitRecord),
		cfg:     cfg,
	}
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
		if time.Since(rec.lastStateChange) > cb.cfg.Timeout {
			if atomic.CompareAndSwapInt32(&rec.state, int32(StateOpen), int32(StateHalfOpen)) {
				rec.lastStateChange = time.Now()
				if cb.cfg.OnStateChange != nil {
					cb.cfg.OnStateChange(k, "state_change_to_half_open")
				}
			}
			return StateHalfOpen
		}
	}

	return state
}

func (cb *CircuitBreaker) recordFailure(k string) {
	rec := cb.getRecord(k)
	atomic.AddInt32(&rec.failures, 1)

	state := CircuitState(atomic.LoadInt32(&rec.state))

	switch state {
	case StateClosed:
		failures := atomic.LoadInt32(&rec.failures)
		successes := atomic.LoadInt32(&rec.successes)
		total := failures + successes
		if total >= int32(cb.cfg.MinRequests) && float64(total) > 0 {
			ratio := float64(failures) / float64(total)
			if ratio >= cb.cfg.FailureRatio {
				if atomic.CompareAndSwapInt32(&rec.state, int32(StateClosed), int32(StateOpen)) {
					rec.lastStateChange = time.Now()
					if cb.cfg.OnStateChange != nil {
						cb.cfg.OnStateChange(k, "opened")
					}
				}
			}
		}
	case StateHalfOpen:
		if atomic.CompareAndSwapInt32(&rec.state, int32(StateHalfOpen), int32(StateOpen)) {
			rec.lastStateChange = time.Now()
			if cb.cfg.OnStateChange != nil {
				cb.cfg.OnStateChange(k, "reopened")
			}
		}
	}
}

func (cb *CircuitBreaker) recordSuccess(k string) {
	rec := cb.getRecord(k)
	atomic.AddInt32(&rec.successes, 1)

	state := CircuitState(atomic.LoadInt32(&rec.state))

	switch state {
	case StateHalfOpen:
		if atomic.CompareAndSwapInt32(&rec.state, int32(StateHalfOpen), int32(StateClosed)) {
			atomic.StoreInt32(&rec.failures, 0)
			atomic.StoreInt32(&rec.successes, 0)
			rec.lastStateChange = time.Now()
			if cb.cfg.OnStateChange != nil {
				cb.cfg.OnStateChange(k, "closed")
			}
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
		atomic.StoreInt32(&rec.failures, 0)
		atomic.StoreInt32(&rec.successes, 0)
	}
	cb.mu.Unlock()
}

func (cb *CircuitBreaker) Stats(service, method string) (CircuitState, int32, int32) {
	k := key(service, method)
	rec := cb.getRecord(k)
	state := CircuitState(atomic.LoadInt32(&rec.state))
	failures := atomic.LoadInt32(&rec.failures)
	successes := atomic.LoadInt32(&rec.successes)
	return state, failures, successes
}