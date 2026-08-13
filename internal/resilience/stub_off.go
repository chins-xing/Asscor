//go:build !resilience

package resilience

import "time"

// No-op resilience stubs. When the resilience module is disabled (build tag
// off), all guard/circuit-breaker/health operations degrade to pass-through
// so consumers (comms, adapter) compile and behave without fault isolation.

// Guard runs fn without panic recovery or circuit tracking.
func Guard(module string, op string, fn func() error) error { return fn() }

// GuardGo runs fn in a goroutine without panic recovery.
func GuardGo(module string, op string, fn func()) { go fn() }

// SignCallback is unused in the no-op build.
var SignCallback func(payload string)

// SetSignCallback is a no-op.
func SetSignCallback(fn func(payload string)) {}

// RecordFailure is a no-op.
func RecordFailure(module string, err error) {}

// RecordSuccess is a no-op.
func RecordSuccess(module string) {}

// Allow always returns true.
func Allow(module string) bool { return true }

// State is a stub circuit state.
type State int

// Status always reports closed.
func Status(module string) (State, string) { return 0, "" }

// Snapshot is a stub telemetry record.
type Snapshot struct {
	Module string `json:"module"`
	State  string `json:"state"`
}

// All returns no snapshots.
func All() []Snapshot { return nil }

// Reset is a no-op.
func Reset(module string) {}

// ModuleHealth is a stub health record.
type ModuleHealth struct {
	Name    string
	Healthy bool
}

// ReportHealth is a no-op.
func ReportHealth(name string, healthy bool, msg string) {}

// ReportPanic is a no-op.
func ReportPanic(name string) {}

// ReportRestart is a no-op.
func ReportRestart(name string) {}

// HealthSummary returns no health records.
func HealthSummary() []ModuleHealth { return nil }

// IsHealthy always returns true.
func IsHealthy() bool { return true }

// ErrorRateLimiter is a stub that always allows.
type ErrorRateLimiter struct{}

// AllowError always returns true.
func (r *ErrorRateLimiter) AllowError() bool { return true }

// NewErrorRateLimiter returns a stub limiter.
func NewErrorRateLimiter(perMinute int) *ErrorRateLimiter { return &ErrorRateLimiter{} }

var _ = time.Now
