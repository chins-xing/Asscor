package kernel

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type WorkerPool struct {
	semaphore     chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	metrics       *WorkerPoolMetrics
	onTaskTimeout func() // called when a task times out (optional)
}

type WorkerPoolMetrics struct {
	mu                sync.Mutex
	totalSubmitted    int64
	totalCompleted    int64
	totalFailed       int64
	totalTimeout      int64
	peakActiveWorkers int
	lastReset         time.Time
}

func NewWorkerPool(maxConcurrency int) *WorkerPool {
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		semaphore: make(chan struct{}, maxConcurrency),
		ctx:       ctx,
		cancel:    cancel,
		metrics: &WorkerPoolMetrics{
			lastReset: time.Now(),
		},
	}
}

func (p *WorkerPool) Submit(task func() error) {
	p.SubmitWithTimeout(task, 30*time.Minute)
}

func (p *WorkerPool) SubmitWithTimeout(task func() error, timeout time.Duration) {
	p.metrics.mu.Lock()
	p.metrics.totalSubmitted++
	p.metrics.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.WithComponent("workerpool").Error("panic recovered", "panic", r)
				p.metrics.mu.Lock()
				p.metrics.totalFailed++
				p.metrics.mu.Unlock()
			}
		}()

		select {
		case p.semaphore <- struct{}{}:
			defer func() { <-p.semaphore }()

			taskCtx, taskCancel := context.WithTimeout(context.Background(), timeout)
			defer taskCancel()

			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logger.WithComponent("workerpool").Error("task panic recovered", "panic", r)
						done <- fmt.Errorf("panic: %v", r)
					}
				}()
				done <- task()
			}()

			select {
			case err := <-done:
				if err != nil {
					p.metrics.mu.Lock()
					p.metrics.totalFailed++
					p.metrics.mu.Unlock()
				} else {
					p.metrics.mu.Lock()
					p.metrics.totalCompleted++
					p.metrics.mu.Unlock()
				}
			case <-taskCtx.Done():
				p.metrics.mu.Lock()
				p.metrics.totalTimeout++
				p.metrics.mu.Unlock()
				logger.WithComponent("workerpool").Warn("task timed out, cancelling", "timeout", timeout)
				if p.onTaskTimeout != nil {
					p.onTaskTimeout()
				}
				taskCancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					logger.WithComponent("workerpool").Error("task did not complete after timeout + drain period, goroutine may leak")
				case <-p.ctx.Done():
				}
			}
		case <-p.ctx.Done():
			return
		}
	}()
}

func (p *WorkerPool) Wait() {
	p.wg.Wait()
}

func (p *WorkerPool) Shutdown() {
	p.cancel()
	p.Wait()
}

func (p *WorkerPool) ActiveWorkers() int {
	return len(p.semaphore)
}

func (p *WorkerPool) AvailableSlots() int {
	return cap(p.semaphore) - len(p.semaphore)
}

func (p *WorkerPool) MaxConcurrency() int {
	return cap(p.semaphore)
}

func (p *WorkerPool) Metrics() WorkerPoolMetrics {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()
	return WorkerPoolMetrics{
		totalSubmitted:    p.metrics.totalSubmitted,
		totalCompleted:    p.metrics.totalCompleted,
		totalFailed:       p.metrics.totalFailed,
		totalTimeout:      p.metrics.totalTimeout,
		peakActiveWorkers: p.metrics.peakActiveWorkers,
		lastReset:         p.metrics.lastReset,
	}
}

func (p *WorkerPool) ResetMetrics() {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()
	p.metrics.totalSubmitted = 0
	p.metrics.totalCompleted = 0
	p.metrics.totalFailed = 0
	p.metrics.totalTimeout = 0
	p.metrics.peakActiveWorkers = 0
	p.metrics.lastReset = time.Now()
}

type ConcurrencyStatus struct {
	GoroutineCount   int       `json:"goroutine_count"`
	HeapAllocMB      uint64    `json:"heap_alloc_mb"`
	WorkerPoolActive int       `json:"worker_pool_active"`
	WorkerPoolQueued int       `json:"worker_pool_queued"`
	BusTopics        []string  `json:"bus_topics"`
	AgentCount       int       `json:"agent_count"`
	Timestamp        time.Time `json:"timestamp"`
}

type ConcurrencyModule struct {
	kernel     KernelContext
	workerPool *WorkerPool
	state      PluginState
	stateMu    sync.RWMutex
}

func NewConcurrencyModule(maxWorkers int) *ConcurrencyModule {
	return &ConcurrencyModule{
		workerPool: NewWorkerPool(maxWorkers),
	}
}

func (m *ConcurrencyModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "concurrency",
		Version:     "1.2.0",
		Description: "Concurrency controller — WorkerPool with semaphore-based throttling, health checks, metrics",
		Author:      "ASSCOR Core Team",
	}
}

func (m *ConcurrencyModule) Dependencies() []PluginDependency {
	return nil
}

func (m *ConcurrencyModule) Priority() int {
	return 2
}

func (m *ConcurrencyModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.stateMu.Lock()
	m.state = PluginInitialized
	m.stateMu.Unlock()

	if m.workerPool == nil {
		m.workerPool = NewWorkerPool(10)
	}

	kc.Container().Bind((*ConcurrencyInterface)(nil), m)
	kc.Container().Bind((*WorkerPoolInterface)(nil), m.workerPool)

	return nil
}

func (m *ConcurrencyModule) Start(ctx context.Context) error {
	m.stateMu.Lock()
	m.state = PluginStarted
	m.stateMu.Unlock()

	if m.kernel != nil && m.kernel.Extensions() != nil {
		m.workerPool.SetOnTaskTimeout(func() {
			m.kernel.Extensions().Execute(m.kernel.Context(), "workerpool.task_timed_out", nil)
		})
	}

	logger.WithComponent("concurrency").Info("started", "max_workers", m.workerPool.MaxConcurrency())
	return nil
}

func (m *ConcurrencyModule) Stop(ctx context.Context) error {
	m.stateMu.Lock()
	m.state = PluginStopping
	m.stateMu.Unlock()
	m.workerPool.Shutdown()
	m.stateMu.Lock()
	m.state = PluginStopped
	m.stateMu.Unlock()
	logger.WithComponent("concurrency").Info("stopped")
	return nil
}

func (m *ConcurrencyModule) State() PluginState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

func (m *ConcurrencyModule) Submit(task func() error) {
	m.workerPool.Submit(task)
}

func (m *ConcurrencyModule) SubmitWithTimeout(task func() error, timeout time.Duration) {
	m.workerPool.SubmitWithTimeout(task, timeout)
}

func (m *ConcurrencyModule) Wait() {
	m.workerPool.Wait()
}

func (m *ConcurrencyModule) Pool() *WorkerPool {
	return m.workerPool
}

func (m *ConcurrencyModule) HealthCheck(ctx context.Context) *ConcurrencyStatus {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	agentCount := 0
	hb, _ := m.kernel.GetPlugin("heartbeat")
	if hb != nil {
		if mi, ok := hb.(HeartbeatInterface); ok {
			agentCount = len(mi.ListAgents())
		}
	}

	busTopics := m.kernel.Bus().Topics()

	return &ConcurrencyStatus{
		GoroutineCount:   runtime.NumGoroutine(),
		HeapAllocMB:      memStats.Alloc / 1024 / 1024,
		WorkerPoolActive: m.workerPool.ActiveWorkers(),
		WorkerPoolQueued: m.workerPool.AvailableSlots(),
		BusTopics:        busTopics,
		AgentCount:       agentCount,
		Timestamp:        time.Now(),
	}
}

func (m *ConcurrencyModule) CheckAlerts() []string {
	status := m.HealthCheck(context.Background())
	metrics := m.workerPool.Metrics()

	var alerts []string

	if status.GoroutineCount > 500 {
		alerts = append(alerts, "high goroutine count")
	}
	if status.HeapAllocMB > 500 {
		alerts = append(alerts, "high memory usage")
	}
	if metrics.totalTimeout > 5 {
		alerts = append(alerts, "frequent task timeouts")
	}
	if metrics.totalFailed > metrics.totalCompleted && metrics.totalCompleted > 0 {
		alerts = append(alerts, "high failure rate")
	}

	return alerts
}

func (p *WorkerPool) SetOnTaskTimeout(cb func()) {
	p.onTaskTimeout = cb
}
