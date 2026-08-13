package topology

import "sync"

// Registry is the shared network topology store used by the heartbeat handler
// (writer) and the SRD plugin (reader) to build real risk-diffusion edges.
type Registry struct {
	mu       sync.RWMutex
	data     map[string][]string
	onUpdate func(hostID string, subnets []string)
}

var globalTopology = &Registry{data: make(map[string][]string)}

// RecordTopology stores a host's subnets for SRD real-edge construction and
// notifies any registered listener (the SRD plugin) so the pipeline updates
// in real time instead of a one-shot snapshot.
func RecordTopology(hostID string, subnets []string) {
	cp := append([]string(nil), subnets...)

	globalTopology.mu.Lock()
	globalTopology.data[hostID] = cp
	cb := globalTopology.onUpdate
	globalTopology.mu.Unlock()

	if cb != nil {
		cb(hostID, cp)
	}
}

// GetTopology returns a deep copy of all host subnets.
func GetTopology() map[string][]string {
	globalTopology.mu.RLock()
	defer globalTopology.mu.RUnlock()
	out := make(map[string][]string, len(globalTopology.data))
	for k, v := range globalTopology.data {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// SetTopologyListener registers a callback fired on every topology update.
func SetTopologyListener(cb func(hostID string, subnets []string)) {
	globalTopology.mu.Lock()
	globalTopology.onUpdate = cb
	globalTopology.mu.Unlock()
}
