package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// ObsMetrics exposes runtime observability counters for the kernel.
// Zero external dependencies — pure atomic counters.
type ObsMetrics struct {
	AssessmentsStarted    int64
	AssessmentsCompleted  int64
	AssessmentsFailed     int64
	HeartbeatsReceived    int64
	HeartbeatsFailed      int64
	CommandsDispatched    int64
	SPCFetchesCompleted   int64
	SPCFetchesFailed      int64
	BusMessagesPublished  int64
	BusMessagesDropped    int64
	ExtensionsExecuted    int64
	ExtensionsFailed      int64
}

var globalMetrics = &ObsMetrics{}

func Metrics() *ObsMetrics { return globalMetrics }

func (m *ObsMetrics) IncAssessments()    { atomic.AddInt64(&m.AssessmentsStarted, 1) }
func (m *ObsMetrics) IncAssessmentsOK()  { atomic.AddInt64(&m.AssessmentsCompleted, 1) }
func (m *ObsMetrics) IncAssessmentsErr() { atomic.AddInt64(&m.AssessmentsFailed, 1) }
func (m *ObsMetrics) IncHeartbeats()     { atomic.AddInt64(&m.HeartbeatsReceived, 1) }
func (m *ObsMetrics) IncHeartbeatsErr()  { atomic.AddInt64(&m.HeartbeatsFailed, 1) }
func (m *ObsMetrics) IncCommands()       { atomic.AddInt64(&m.CommandsDispatched, 1) }
func (m *ObsMetrics) IncSPCFetchOK()     { atomic.AddInt64(&m.SPCFetchesCompleted, 1) }
func (m *ObsMetrics) IncSPCFetchErr()    { atomic.AddInt64(&m.SPCFetchesFailed, 1) }
func (m *ObsMetrics) IncBusPublished()   { atomic.AddInt64(&m.BusMessagesPublished, 1) }
func (m *ObsMetrics) IncBusDropped()     { atomic.AddInt64(&m.BusMessagesDropped, 1) }

func (m *ObsMetrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"assessments_started":   atomic.LoadInt64(&m.AssessmentsStarted),
		"assessments_completed": atomic.LoadInt64(&m.AssessmentsCompleted),
		"assessments_failed":    atomic.LoadInt64(&m.AssessmentsFailed),
		"heartbeats_received":   atomic.LoadInt64(&m.HeartbeatsReceived),
		"heartbeats_failed":     atomic.LoadInt64(&m.HeartbeatsFailed),
		"commands_dispatched":   atomic.LoadInt64(&m.CommandsDispatched),
		"spc_fetches_ok":        atomic.LoadInt64(&m.SPCFetchesCompleted),
		"spc_fetches_err":       atomic.LoadInt64(&m.SPCFetchesFailed),
		"bus_published":         atomic.LoadInt64(&m.BusMessagesPublished),
		"bus_dropped":           atomic.LoadInt64(&m.BusMessagesDropped),
		"extensions_executed":   atomic.LoadInt64(&m.ExtensionsExecuted),
		"extensions_failed":     atomic.LoadInt64(&m.ExtensionsFailed),
	}
}

// NewTrace generates a random 8-byte trace ID for request correlation.
func NewTrace() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TraceContext returns a new context with a trace ID. If the parent context
// already has one, it is reused (no nested trace IDs).
func TraceContext(parent context.Context) context.Context {
	if TraceID(parent) != "" {
		return parent
	}
	return NewContext(parent, NewTrace())
}

// LatencyTracker records operation duration for observability.
type LatencyTracker struct {
	mu       sync.Mutex
	latencies map[string][]time.Duration
}

var globalLatency = &LatencyTracker{latencies: make(map[string][]time.Duration)}

func RecordLatency(op string, d time.Duration) {
	globalLatency.mu.Lock()
	if len(globalLatency.latencies[op]) > 100 {
		globalLatency.latencies[op] = globalLatency.latencies[op][1:]
	}
	globalLatency.latencies[op] = append(globalLatency.latencies[op], d)
	globalLatency.mu.Unlock()
}

func LatencySnapshot() map[string]time.Duration {
	globalLatency.mu.Lock()
	defer globalLatency.mu.Unlock()
	result := make(map[string]time.Duration)
	for op, samples := range globalLatency.latencies {
		if len(samples) == 0 {
			continue
		}
		var sum time.Duration
		for _, s := range samples {
			sum += s
		}
		result[op] = sum / time.Duration(len(samples))
	}
	return result
}
