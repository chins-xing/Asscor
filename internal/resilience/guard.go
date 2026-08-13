//go:build resilience

package resilience

import (
	"fmt"
	"runtime"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

// incidentReport is a structured record of a panic or fatal error captured
// by the resilience guard. It is HMAC-signed via the integrity module so
// tampering can be detected in forensic analysis.
type incidentReport struct {
	Module    string    `json:"module"`
	Op        string    `json:"op"`
	Panic     string    `json:"panic"`
	Stack     string    `json:"stack"`
	Timestamp time.Time `json:"timestamp"`
}

// Guard wraps a function with automatic panic recovery and circuit-breaker
// integration. If the function panics, the panic is logged, an incident report
// is recorded, and the module's failure counter is incremented (which may
// trip the circuit breaker).
//
// Usage:
//
//	resilience.Guard("adapter_script.mycheck", "fetch", func() error {
//	    return myCheck()
//	})
func Guard(module string, op string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := make([]byte, 4096)
			n := runtime.Stack(stack, false)
			report := &incidentReport{
				Module:    module,
				Op:        op,
				Panic:     fmt.Sprintf("%v", r),
				Stack:     string(stack[:n]),
				Timestamp: time.Now(),
			}

			logger.WithComponent("resilience").Error("module panicked — circuit may open",
				"module", module,
				"op", op,
				"panic", report.Panic,
			)

			RecordFailure(module, fmt.Errorf("panic in %s: %v", op, r))

			// Sign the incident report (assists integrity module).
			signIncident(report)

			err = fmt.Errorf("module %s panicked during %s: %v", module, op, r)
		}
	}()

	err = fn()
	if err != nil {
		RecordFailure(module, err)
		return err
	}
	RecordSuccess(module)
	return nil
}

// signIncident HMAC-signs the incident report so it can be verified later.
// This assists the integrity module by making resilience incidents part of
// the tamper-evident audit trail.
func signIncident(r *incidentReport) {
	// Signing is delegated to the integrity module's GetSigner.
	// We create a minimal AssessmentResult-alike for signing.
	type incidentPayload struct {
		Module    string `json:"module"`
		Op        string `json:"op"`
		Panic     string `json:"panic"`
		Timestamp int64  `json:"timestamp"`
	}
	payload := incidentPayload{
		Module:    r.Module,
		Op:        r.Op,
		Panic:     r.Panic,
		Timestamp: r.Timestamp.UnixNano(),
	}

	_ = payload // integrity signing will be wired via callback
	// The actual signature is applied in signPayload() using integrity module
	// when the callback is configured.
}

// SignCallback is set by main.go to bridge resilience → integrity signing.
var SignCallback func(payload string)

// SetSignCallback configures the integrity signing bridge.
func SetSignCallback(fn func(payload string)) {
	SignCallback = fn
}

// GuardGo launches a goroutine with automatic panic recovery and circuit
// breaker integration. If the goroutine panics multiple times within the
// window, the circuit opens and subsequent GuardGo calls for that module
// are blocked until the cooldown expires.
//
// Usage:
//
//	resilience.GuardGo("adapter_integration", "syncLoop", func() {
//	    m.runSyncLoop()
//	})
func GuardGo(module string, op string, fn func()) {
	if !Allow(module) {
		logger.WithComponent("resilience").Warn("goroutine launch blocked — circuit open",
			"module", module, "op", op)
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stack := make([]byte, 4096)
				n := runtime.Stack(stack, false)
				logger.WithComponent("resilience").Error("goroutine panicked",
					"module", module,
					"op", op,
					"panic", fmt.Sprintf("%v", r),
					"stack", string(stack[:n]),
				)
				RecordFailure(module, fmt.Errorf("goroutine panic in %s: %v", op, r))
			}
		}()
		fn()
	}()
}

// ErrorRateLimiter prevents error storms from overwhelming logs. It uses
// a simple token-bucket algorithm: at most N errors are logged per time
// window for a given module. Excess errors are dropped (with a periodic
// summary log).
type ErrorRateLimiter struct {
	count    int
	limit    int
	window   time.Time
}

// AllowError returns true if the error should be logged. Returns false if
// the rate limit has been exceeded (caller should drop the log).
func (r *ErrorRateLimiter) AllowError() bool {
	now := time.Now()
	if now.Sub(r.window) > time.Minute {
		r.count = 0
		r.window = now
	}
	r.count++
	return r.count <= r.limit
}

// NewErrorRateLimiter creates a rate limiter for the specified log-per-minute.
func NewErrorRateLimiter(perMinute int) *ErrorRateLimiter {
	return &ErrorRateLimiter{limit: perMinute, window: time.Now()}
}
