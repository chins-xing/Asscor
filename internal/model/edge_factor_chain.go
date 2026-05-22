package model

import (
	"sort"
	"sync"
)

type EdgeFactor struct {
	ID          string
	Name        string
	Description string
	Factor      float64
	Active      bool
	Priority    int
}

type EdgeFactorChain struct {
	mu      sync.RWMutex
	factors map[string]*EdgeFactor
}

var globalEdgeFactorChain = &EdgeFactorChain{
	factors: make(map[string]*EdgeFactor),
}

func RegisterEdgeFactor(ef EdgeFactor) {
	globalEdgeFactorChain.mu.Lock()
	defer globalEdgeFactorChain.mu.Unlock()
	copy := ef
	globalEdgeFactorChain.factors[ef.ID] = &copy
}

func UnregisterEdgeFactor(id string) {
	globalEdgeFactorChain.mu.Lock()
	defer globalEdgeFactorChain.mu.Unlock()
	delete(globalEdgeFactorChain.factors, id)
}

func SetEdgeFactorActive(id string, active bool) {
	globalEdgeFactorChain.mu.Lock()
	defer globalEdgeFactorChain.mu.Unlock()
	if f, ok := globalEdgeFactorChain.factors[id]; ok {
		f.Active = active
	}
}

func SetEdgeFactorValue(id string, factor float64) {
	globalEdgeFactorChain.mu.Lock()
	defer globalEdgeFactorChain.mu.Unlock()
	if f, ok := globalEdgeFactorChain.factors[id]; ok {
		f.Factor = factor
		f.Active = factor < 1.0
	}
}

func GetEdgeFactor(id string) (*EdgeFactor, bool) {
	globalEdgeFactorChain.mu.RLock()
	defer globalEdgeFactorChain.mu.RUnlock()
	f, ok := globalEdgeFactorChain.factors[id]
	return f, ok
}

func ListEdgeFactors() []EdgeFactor {
	globalEdgeFactorChain.mu.RLock()
	defer globalEdgeFactorChain.mu.RUnlock()
	result := make([]EdgeFactor, 0, len(globalEdgeFactorChain.factors))
	for _, f := range globalEdgeFactorChain.factors {
		result = append(result, *f)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})
	return result
}

func ActiveEdgeFactors() []float64 {
	globalEdgeFactorChain.mu.RLock()
	defer globalEdgeFactorChain.mu.RUnlock()
	var result []float64
	sorted := make([]*EdgeFactor, 0, len(globalEdgeFactorChain.factors))
	for _, f := range globalEdgeFactorChain.factors {
		sorted = append(sorted, f)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	for _, f := range sorted {
		if f.Active {
			result = append(result, f.Factor)
		}
	}
	return result
}

func ResetAllEdgeFactors() {
	globalEdgeFactorChain.mu.Lock()
	defer globalEdgeFactorChain.mu.Unlock()
	for _, f := range globalEdgeFactorChain.factors {
		f.Factor = 1.0
		f.Active = false
	}
}

func init() {
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-002FA",
		Name:        "2FA Missing",
		Description: "Dual-factor authentication not enforced",
		Factor:      0.85,
		Active:      false,
		Priority:    10,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-SYNCOOKIE",
		Name:        "SYN Cookie Disabled",
		Description: "SYN Cookie not enabled (net.ipv4.tcp_syncookies=0)",
		Factor:      0.75,
		Active:      false,
		Priority:    20,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-SELINUX",
		Name:        "SELinux Disabled",
		Description: "Mandatory Access Control (SELinux) not enforcing",
		Factor:      0.80,
		Active:      false,
		Priority:    30,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-APPARMOR",
		Name:        "AppArmor Disabled",
		Description: "AppArmor not enforcing",
		Factor:      0.82,
		Active:      false,
		Priority:    31,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-NO-SIEM",
		Name:        "SIEM Integration Missing",
		Description: "No SIEM/SOAR integration for centralized log monitoring",
		Factor:      0.90,
		Active:      false,
		Priority:    40,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-NO-IDS",
		Name:        "IDS/IPS Missing",
		Description: "No intrusion detection/prevention system deployed",
		Factor:      0.88,
		Active:      false,
		Priority:    50,
	})
	RegisterEdgeFactor(EdgeFactor{
		ID:          "EF-3FA",
		Name:        "3FA Not Met",
		Description: "Three-factor authentication not achieved (Level 4 override)",
		Factor:      0.82,
		Active:      false,
		Priority:    5,
	})
}
