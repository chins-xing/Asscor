package checks

import (
	"sync"

	"github.com/asscor/asscor/internal/model"
)

var (
	registry   []model.CheckItem
	registryMu sync.RWMutex
	idIndex    = make(map[string]int)
)

func Register(items ...model.CheckItem) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, item := range items {
		if !item.MatchesPlatform() {
			continue
		}
		idx := len(registry)
		registry = append(registry, item)
		if item.ID != "" {
			idIndex[item.ID] = idx
		}
	}
}

func Unregister(checkIDs ...string) int {
	registryMu.Lock()
	defer registryMu.Unlock()
	toRemove := make(map[string]bool, len(checkIDs))
	for _, id := range checkIDs {
		toRemove[id] = true
	}
	removed := 0
	filtered := make([]model.CheckItem, 0, len(registry))
	for _, item := range registry {
		if toRemove[item.ID] {
			removed++
			continue
		}
		filtered = append(filtered, item)
	}
	registry = filtered
	for i, item := range registry {
		if item.ID != "" {
			idIndex[item.ID] = i
		}
	}
	return removed
}

func GetByID(id string) (model.CheckItem, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if idx, ok := idIndex[id]; ok && idx < len(registry) {
		return registry[idx], true
	}
	return model.CheckItem{}, false
}

func GetByDomain(domain string) []model.CheckItem {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var result []model.CheckItem
	for _, item := range registry {
		if item.Domain == domain {
			result = append(result, item)
		}
	}
	return result
}

func GetAll() []model.CheckItem {
	registryMu.RLock()
	defer registryMu.RUnlock()
	cp := make([]model.CheckItem, len(registry))
	copy(cp, registry)
	return cp
}

func Count() int {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(registry)
}

func DomainCounts() map[string]int {
	registryMu.RLock()
	defer registryMu.RUnlock()
	counts := make(map[string]int)
	for _, item := range registry {
		counts[item.Domain]++
	}
	return counts
}
