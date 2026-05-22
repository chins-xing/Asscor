package model

import "sync"

type DomainCategory string

const (
	CategoryCore      DomainCategory = "core"
	CategoryExtension DomainCategory = "extension"
)

type DomainMeta struct {
	ID          string
	Label       string
	Description string
	Category    DomainCategory
	DefaultWeight float64
}

type DomainRegistry struct {
	mu       sync.RWMutex
	domains  map[string]DomainMeta
}

var globalDomainRegistry = &DomainRegistry{
	domains: map[string]DomainMeta{
		DomainAttackSurface: {
			ID:            DomainAttackSurface,
			Label:         "Attack Surface",
			Description:   "Attacksurface management: unused services, open ports, strong auth, SSH config",
			Category:      CategoryCore,
			DefaultWeight: 35,
		},
		DomainBusinessContinuity: {
			ID:            DomainBusinessContinuity,
			Label:         "Business Continuity",
			Description:   "Business continuity: critical services, backup, resource adequacy",
			Category:      CategoryCore,
			DefaultWeight: 25,
		},
		DomainOperationTrust: {
			ID:            DomainOperationTrust,
			Label:         "Operation Trust",
			Description:   "Operation trust: file permissions, audit logs, command history, supply chain, MAC",
			Category:      CategoryCore,
			DefaultWeight: 25,
		},
		DomainResilience: {
			ID:            DomainResilience,
			Label:         "Resilience",
			Description:   "Resilience: auto-block precision, SYN cookie, connection limits, ACI",
			Category:      CategoryCore,
			DefaultWeight: 15,
		},
		DomainKernelSecurity: {
			ID:            DomainKernelSecurity,
			Label:         "Kernel Security",
			Description:   "Kernel security: CVE check, module signing, KASLR, hardening sysctls",
			Category:      CategoryExtension,
			DefaultWeight: 10,
		},
	},
}

func RegisterDomain(meta DomainMeta) {
	globalDomainRegistry.mu.Lock()
	defer globalDomainRegistry.mu.Unlock()
	globalDomainRegistry.domains[meta.ID] = meta
}

func UnregisterDomain(id string) {
	globalDomainRegistry.mu.Lock()
	defer globalDomainRegistry.mu.Unlock()
	delete(globalDomainRegistry.domains, id)
}

func GetDomainMeta(id string) (DomainMeta, bool) {
	globalDomainRegistry.mu.RLock()
	defer globalDomainRegistry.mu.RUnlock()
	m, ok := globalDomainRegistry.domains[id]
	return m, ok
}

func ListDomains() []DomainMeta {
	globalDomainRegistry.mu.RLock()
	defer globalDomainRegistry.mu.RUnlock()
	result := make([]DomainMeta, 0, len(globalDomainRegistry.domains))
	for _, m := range globalDomainRegistry.domains {
		result = append(result, m)
	}
	return result
}

func ListDomainIDs() []string {
	globalDomainRegistry.mu.RLock()
	defer globalDomainRegistry.mu.RUnlock()
	ids := make([]string, 0, len(globalDomainRegistry.domains))
	for id := range globalDomainRegistry.domains {
		ids = append(ids, id)
	}
	return ids
}

func ListDomainsByCategory(cat DomainCategory) []DomainMeta {
	globalDomainRegistry.mu.RLock()
	defer globalDomainRegistry.mu.RUnlock()
	var result []DomainMeta
	for _, m := range globalDomainRegistry.domains {
		if m.Category == cat {
			result = append(result, m)
		}
	}
	return result
}

func ListDomainIDsByCategory(cat DomainCategory) []string {
	globalDomainRegistry.mu.RLock()
	defer globalDomainRegistry.mu.RUnlock()
	var result []string
	for _, m := range globalDomainRegistry.domains {
		if m.Category == cat {
			result = append(result, m.ID)
		}
	}
	return result
}

func GetDomainLabel(id string) string {
	if meta, ok := GetDomainMeta(id); ok {
		return meta.Label
	}
	return id
}

func ResetDomainsForTesting() {
	globalDomainRegistry.mu.Lock()
	defer globalDomainRegistry.mu.Unlock()
	globalDomainRegistry.domains = map[string]DomainMeta{
		DomainAttackSurface: {
			ID:            DomainAttackSurface,
			Label:         "Attack Surface",
			Description:   "Attacksurface management: unused services, open ports, strong auth, SSH config",
			Category:      CategoryCore,
			DefaultWeight: 35,
		},
		DomainBusinessContinuity: {
			ID:            DomainBusinessContinuity,
			Label:         "Business Continuity",
			Description:   "Business continuity: critical services, backup, resource adequacy",
			Category:      CategoryCore,
			DefaultWeight: 25,
		},
		DomainOperationTrust: {
			ID:            DomainOperationTrust,
			Label:         "Operation Trust",
			Description:   "Operation trust: file permissions, audit logs, command history, supply chain, MAC",
			Category:      CategoryCore,
			DefaultWeight: 25,
		},
		DomainResilience: {
			ID:            DomainResilience,
			Label:         "Resilience",
			Description:   "Resilience: auto-block precision, SYN cookie, connection limits, ACI",
			Category:      CategoryCore,
			DefaultWeight: 15,
		},
		DomainKernelSecurity: {
			ID:            DomainKernelSecurity,
			Label:         "Kernel Security",
			Description:   "Kernel security: CVE check, module signing, KASLR, hardening sysctls",
			Category:      CategoryExtension,
			DefaultWeight: 10,
		},
	}
}
