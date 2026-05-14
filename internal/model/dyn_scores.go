package model

import (
	"encoding/json"
	"math"
	"sync"
)

type DynamicDomainScores struct {
	mu     sync.RWMutex
	scores map[string]float64
}

func NewDynamicDomainScores() *DynamicDomainScores {
	return &DynamicDomainScores{
		scores: make(map[string]float64),
	}
}

func (d *DynamicDomainScores) Set(domain string, score float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	score = math.Max(0, math.Min(100, score))
	d.scores[domain] = score
}

func (d *DynamicDomainScores) Get(domain string) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if v, ok := d.scores[domain]; ok {
		return v
	}
	return 100.0
}

func (d *DynamicDomainScores) Has(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.scores[domain]
	return ok
}

func (d *DynamicDomainScores) Add(domain string, delta float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current := 100.0
	if v, ok := d.scores[domain]; ok {
		current = v
	}
	current = math.Max(0, math.Min(100, current+delta))
	d.scores[domain] = current
}

func (d *DynamicDomainScores) GetAll() map[string]float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cp := make(map[string]float64, len(d.scores))
	for k, v := range d.scores {
		cp[k] = v
	}
	return cp
}

func (d *DynamicDomainScores) Keys() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	keys := make([]string, 0, len(d.scores))
	for k := range d.scores {
		keys = append(keys, k)
	}
	return keys
}

func (d *DynamicDomainScores) Clone() *DynamicDomainScores {
	d.mu.RLock()
	defer d.mu.RUnlock()
	clone := NewDynamicDomainScores()
	for k, v := range d.scores {
		clone.scores[k] = v
	}
	return clone
}

func (d *DynamicDomainScores) MarshalJSON() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return json.Marshal(d.scores)
}

func (d *DynamicDomainScores) UnmarshalJSON(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return json.Unmarshal(data, &d.scores)
}

func (d *DynamicDomainScores) FillFromLegacy(legacy DomainScores) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scores[DomainAttackSurface] = legacy.AttackSurface
	d.scores[DomainBusinessContinuity] = legacy.BusinessContinuity
	d.scores[DomainOperationTrust] = legacy.OperationTrust
	d.scores[DomainResilience] = legacy.Resilience
	if legacy.KernelSecurity != 0 {
		d.scores[DomainKernelSecurity] = legacy.KernelSecurity
	}
}

func (d *DynamicDomainScores) ToLegacy() DomainScores {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return DomainScores{
		AttackSurface:      getOr(d.scores, DomainAttackSurface, 100),
		BusinessContinuity: getOr(d.scores, DomainBusinessContinuity, 100),
		OperationTrust:     getOr(d.scores, DomainOperationTrust, 100),
		Resilience:         getOr(d.scores, DomainResilience, 100),
		KernelSecurity:     getOr(d.scores, DomainKernelSecurity, 100),
	}
}

func getOr(m map[string]float64, key string, defaultVal float64) float64 {
	if v, ok := m[key]; ok {
		return v
	}
	return defaultVal
}
