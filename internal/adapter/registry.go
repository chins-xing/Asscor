package adapter

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

var registry = struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}{adapters: make(map[string]Adapter)}

func Register(a Adapter) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.adapters[a.ID()]; exists {
		logger.WithComponent("adapter").Warn("overwriting adapter", "adapter_id", a.ID())
	}
	registry.adapters[a.ID()] = a
}

func Get(id string) (Adapter, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	a, ok := registry.adapters[id]
	return a, ok
}

func List() []Adapter {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	list := make([]Adapter, 0, len(registry.adapters))
	for _, a := range registry.adapters {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID() < list[j].ID()
	})
	return list
}

func ListByCategory(category string) []Adapter {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	var list []Adapter
	for _, a := range registry.adapters {
		if a.Category() == category {
			list = append(list, a)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID() < list[j].ID()
	})
	return list
}

func ResetRegistryForTesting() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.adapters = make(map[string]Adapter)
}

type PipelineResult struct {
	AdapterID   string
	AdapterName string
	Findings    []*NormalizedFinding
	Error       error
}

type Pipeline struct {
	adapters   []Adapter
	config     map[string]string
	maxWorkers int
}

func NewPipeline(config map[string]string) *Pipeline {
	return &Pipeline{
		config:     config,
		maxWorkers: 10,
	}
}

func (p *Pipeline) WithAdapters(adapters ...Adapter) *Pipeline {
	p.adapters = adapters
	return p
}

func (p *Pipeline) RunAll(ctx context.Context) []PipelineResult {
	enabled := p.filterEnabled()
	if len(enabled) == 0 {
		return nil
	}

	sem := make(chan struct{}, p.maxWorkers)
	var wg sync.WaitGroup
	resultsCh := make(chan PipelineResult, len(enabled))

	for _, a := range enabled {
		wg.Add(1)
		go func(adapter Adapter) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			adapterTimeout := 60 * time.Second
			if t, ok := adapter.(interface{ Timeout() time.Duration }); ok {
				adapterTimeout = t.Timeout()
			}
			actx, cancel := context.WithTimeout(ctx, adapterTimeout)
			defer cancel()

			findings, err := ExecuteAdapter(actx, adapter, p.config)
			if err != nil {
				logger.WithComponent("adapter").Error("adapter execution failed", "adapter_id", adapter.ID(), "error", err)
			}
			resultsCh <- PipelineResult{
				AdapterID:   adapter.ID(),
				AdapterName: adapter.Name(),
				Findings:    findings,
				Error:       err,
			}
		}(a)
	}

	wg.Wait()
	close(resultsCh)

	var results []PipelineResult
	for r := range resultsCh {
		results = append(results, r)
	}
	return results
}

func (p *Pipeline) filterEnabled() []Adapter {
	var enabled []Adapter
	for _, a := range p.adapters {
		if a.IsEnabled(p.config) {
			enabled = append(enabled, a)
		}
	}
	return enabled
}

func Summary(results []PipelineResult) string {
	if len(results) == 0 {
		return "[adapter] no adapters enabled or executed"
	}

	totalFindings := 0
	failureCount := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
		if r.Error != nil {
			failureCount++
		}
	}

	summary := fmt.Sprintf("[adapter] %d adapters executed, %d findings, %d failures",
		len(results), totalFindings, failureCount)
	return summary
}
