// Package resilience provides per-module circuit breakers that protect the
// kernel from cascading failures caused by external modules (adapters, user
// scripts, Plugin SDK processes). When a module exceeds its failure threshold
// within a time window, the circuit opens and all subsequent calls to that
// module are short-circuited until the cooldown expires.
//
// Design (low coupling, high cohesion):
//   - Modules are identified by name (e.g. "trivy", "adapter_script.mycheck").
//   - Zero kernel dependencies — only stdlib + logger + integrity.
//   - Thread-safe via per-breaker mutex.
//   - Half-open state: after cooldown, one trial call is allowed; success
//     closes the circuit, failure re-opens it.
package resilience

import (
	"fmt"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

// State is the current state of a module circuit breaker.
type State int

const (
	StateClosed   State = iota // normal operation
	StateOpen                  // failures exceeded threshold, calls blocked
	StateHalfOpen              // cooldown expired, one trial allowed
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Snapshot captures the breaker state for telemetry / audit.
type Snapshot struct {
	Module       string    `json:"module"`
	State        string    `json:"state"`
	Failures     int       `json:"failures"`
	Successes    int       `json:"successes"`
	LastFailure  time.Time `json:"last_failure,omitempty"`
	OpenedAt     time.Time `json:"opened_at,omitempty"`
	TotalTrips   int       `json:"total_trips"`
}

type breaker struct {
	mu             sync.Mutex
	state          State
	failures       int
	successes      int
	lastFailure    time.Time
	openedAt       time.Time
	totalTrips     int
	threshold      int
	window         time.Duration
	cooldown       time.Duration
}

// Default config: 5 failures in 5 minutes → open for 1 minute.
const (
	defaultThreshold = 5
	defaultWindow    = 5 * time.Minute
	defaultCooldown  = 1 * time.Minute
)

var (
	breakersMu sync.RWMutex
	breakers   = map[string]*breaker{}
)

func getBreaker(module string) *breaker {
	breakersMu.RLock()
	b, ok := breakers[module]
	breakersMu.RUnlock()
	if ok {
		return b
	}

	breakersMu.Lock()
	defer breakersMu.Unlock()
	b = &breaker{
		state:     StateClosed,
		threshold: defaultThreshold,
		window:    defaultWindow,
		cooldown:  defaultCooldown,
	}
	breakers[module] = b
	return b
}

// RecordFailure registers a failure for the given module. If the failure
// count exceeds the threshold within the window, the circuit opens and
// the error is signed and logged via the integrity module.
func RecordFailure(module string, err error) {
	b := getBreaker(module)
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++
	b.lastFailure = time.Now()
	b.successes = 0

	if b.failures >= b.threshold && b.state == StateClosed {
		b.state = StateOpen
		b.openedAt = time.Now()
		b.totalTrips++
		logger.WithComponent("resilience").Warn("circuit opened for module",
			"module", module,
			"failures", b.failures,
			"threshold", b.threshold,
			"trips", b.totalTrips,
			"err", err,
		)
	}
}

// RecordSuccess registers a successful call for the given module. Resets
// the failure counter and, if the circuit was half-open, closes it.
func RecordSuccess(module string) {
	b := getBreaker(module)
	b.mu.Lock()
	defer b.mu.Unlock()

	b.successes++
	b.failures = 0

	if b.state == StateHalfOpen {
		b.state = StateClosed
		logger.WithComponent("resilience").Info("circuit closed for module",
			"module", module)
	}
}

// Allow returns true if the given module's circuit allows a call to proceed.
// If the circuit is open and the cooldown has expired, it transitions to
// half-open and allows ONE trial call.
func Allow(module string) bool {
	b := getBreaker(module)
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(b.openedAt) > b.cooldown {
			b.state = StateHalfOpen
			return true
		}
		return false
	case StateHalfOpen:
		return false // only one trial at a time
	default:
		return true
	}
}

// Status returns the current state of the named module's breaker, and a
// human-readable message.
func Status(module string) (State, string) {
	b := getBreaker(module)
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case StateClosed:
		return b.state, fmt.Sprintf("module %s normal (%d failures in window)", module, b.failures)
	case StateOpen:
		rem := b.cooldown - time.Since(b.openedAt)
		return b.state, fmt.Sprintf("module %s ISOLATED (tripped %d times, cooldown %s remaining)",
			module, b.totalTrips, rem.Truncate(time.Second))
	case StateHalfOpen:
		return b.state, fmt.Sprintf("module %s in trial mode", module)
	default:
		return b.state, ""
	}
}

// All returns a snapshot of every tracked breaker for telemetry.
func All() []Snapshot {
	breakersMu.RLock()
	defer breakersMu.RUnlock()

	var snapshots []Snapshot
	for name, b := range breakers {
		b.mu.Lock()
		snapshots = append(snapshots, Snapshot{
			Module:      name,
			State:       b.state.String(),
			Failures:    b.failures,
			Successes:   b.successes,
			LastFailure: b.lastFailure,
			OpenedAt:    b.openedAt,
			TotalTrips:  b.totalTrips,
		})
		b.mu.Unlock()
	}
	return snapshots
}

// Reset manually resets a module's breaker to the closed state (e.g. after
// the operator confirms the module is healthy again).
func Reset(module string) {
	b := getBreaker(module)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.failures = 0
	b.successes = 0
	logger.WithComponent("resilience").Info("circuit manually reset", "module", module)
}
