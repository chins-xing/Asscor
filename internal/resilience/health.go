//go:build resilience

package resilience

import (
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

// ModuleHealth tracks the health status of a named module for aggregation
// and reporting. Assists the observability module by providing structured
// health data that can be queried via CLI (`diag`) or API.
type ModuleHealth struct {
	Name       string
	Healthy    bool
	LastCheck  time.Time
	Message    string
	Panics     int
	Restarts   int
}

var (
	healthMu sync.RWMutex
	health   = map[string]*ModuleHealth{}
)

// ReportHealth records a health check result for the named module.
func ReportHealth(name string, healthy bool, msg string) {
	healthMu.Lock()
	defer healthMu.Unlock()

	h, ok := health[name]
	if !ok {
		h = &ModuleHealth{Name: name}
		health[name] = h
	}
	h.Healthy = healthy
	h.LastCheck = time.Now()
	h.Message = msg
	if !healthy {
		logger.WithComponent("resilience").Warn("module unhealthy",
			"module", name, "message", msg)
	}
}

// ReportPanic records that a module experienced a panic.
func ReportPanic(name string) {
	healthMu.Lock()
	defer healthMu.Unlock()

	h, ok := health[name]
	if !ok {
		h = &ModuleHealth{Name: name}
		health[name] = h
	}
	h.Panics++
	h.Healthy = false
	h.LastCheck = time.Now()
}

// ReportRestart records that a module was restarted.
func ReportRestart(name string) {
	healthMu.Lock()
	defer healthMu.Unlock()

	h, ok := health[name]
	if !ok {
		h = &ModuleHealth{Name: name}
		health[name] = h
	}
	h.Restarts++
	h.LastCheck = time.Now()
}

// HealthSummary returns the health status of all tracked modules.
// Assists the observability module (logger.Metrics) and CLI `diag`.
func HealthSummary() []ModuleHealth {
	healthMu.RLock()
	defer healthMu.RUnlock()

	var result []ModuleHealth
	for _, h := range health {
		result = append(result, *h)
	}
	return result
}

// IsHealthy returns true if every tracked module is healthy.
func IsHealthy() bool {
	healthMu.RLock()
	defer healthMu.RUnlock()

	if len(health) == 0 {
		return true
	}
	for _, h := range health {
		if !h.Healthy {
			return false
		}
	}
	return true
}
