package kernel

import "sync"

// topologyRegistry is the shared network topology store used by the heartbeat
// handler (writer) and the SRD plugin (reader) to build real risk-diffusion edges.
type topologyRegistry struct {
	mu       sync.RWMutex
	data     map[string][]string // hostID → subnets
	onUpdate func(hostID string, subnets []string)
}

var globalTopology = &topologyRegistry{data: make(map[string][]string)}

// RecordTopology stores a host's subnets for SRD real-edge construction and
// notifies any registered listener (the SRD plugin) so the pipeline updates
// in real time instead of a one-shot snapshot.
func RecordTopology(hostID string, subnets []string) {
	// Defensive copy — avoid sharing the caller's slice.
	cp := append([]string(nil), subnets...)

	globalTopology.mu.Lock()
	globalTopology.data[hostID] = cp
	cb := globalTopology.onUpdate
	globalTopology.mu.Unlock()

	if cb != nil {
		cb(hostID, cp)
	}
}

// getTopology returns a deep copy of all host subnets.
func getTopology() map[string][]string {
	globalTopology.mu.RLock()
	defer globalTopology.mu.RUnlock()
	out := make(map[string][]string, len(globalTopology.data))
	for k, v := range globalTopology.data {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// setTopologyListener registers a callback fired on every topology update.
// The SRD plugin uses this to keep its pipeline topology in sync with the
// kernel's heartbeat-driven topology registry.
func setTopologyListener(cb func(hostID string, subnets []string)) {
	globalTopology.mu.Lock()
	globalTopology.onUpdate = cb
	globalTopology.mu.Unlock()
}
