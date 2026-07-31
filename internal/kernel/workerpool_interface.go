package kernel

import (
	"context"
	"time"
)

type ConcurrencyInterface interface {
	Submit(task func() error)
	SubmitWithTimeout(task func() error, timeout time.Duration)
	Wait()
	Pool() *WorkerPool
	HealthCheck(ctx context.Context) *ConcurrencyStatus
	CheckAlerts() []string
}

type WorkerPoolInterface interface {
	Submit(task func() error)
	SubmitWithTimeout(task func() error, timeout time.Duration)
	Wait()
	ActiveWorkers() int
	AvailableSlots() int
	MaxConcurrency() int
}
