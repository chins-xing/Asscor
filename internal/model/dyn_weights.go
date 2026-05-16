package model

import "sync"

type DynamicWeights struct {
	mu      sync.RWMutex
	weights map[string]float64
}

func NewDynamicWeights() *DynamicWeights {
	return &DynamicWeights{
		weights: make(map[string]float64),
	}
}

func (w *DynamicWeights) Set(domain string, weight float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.weights[domain] = weight
}

func (w *DynamicWeights) Get(domain string) float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if v, ok := w.weights[domain]; ok {
		return v
	}
	return 0
}

func (w *DynamicWeights) GetAll() map[string]float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	cp := make(map[string]float64, len(w.weights))
	for k, v := range w.weights {
		cp[k] = v
	}
	return cp
}

func (w *DynamicWeights) Total() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	sum := 0.0
	for _, v := range w.weights {
		sum += v
	}
	return sum
}

func (w *DynamicWeights) Normalize(targetTotal float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sum := 0.0
	for _, v := range w.weights {
		sum += v
	}
	if sum == 0 || sum == targetTotal {
		return
	}
	ratio := targetTotal / sum
	for k := range w.weights {
		w.weights[k] *= ratio
	}
}

func (w *DynamicWeights) ApplyDefaults(metas []DomainMeta) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range metas {
		if _, exists := w.weights[m.ID]; !exists {
			w.weights[m.ID] = m.DefaultWeight
		}
	}
}

func (w *DynamicWeights) FromLegacy(legacy Weights) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.weights[DomainAttackSurface] = legacy.AttackSurface
	w.weights[DomainBusinessContinuity] = legacy.BusinessContinuity
	w.weights[DomainOperationTrust] = legacy.OperationTrust
	w.weights[DomainResilience] = legacy.Resilience
	if legacy.KernelSecurity != 0 {
		w.weights[DomainKernelSecurity] = legacy.KernelSecurity
	}
}

func (w *DynamicWeights) ToLegacy() Weights {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return Weights{
		AttackSurface:      w.weights[DomainAttackSurface],
		BusinessContinuity: w.weights[DomainBusinessContinuity],
		OperationTrust:     w.weights[DomainOperationTrust],
		Resilience:         w.weights[DomainResilience],
		KernelSecurity:     w.weights[DomainKernelSecurity],
	}
}
