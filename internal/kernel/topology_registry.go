package kernel

import "sync"

// topologyRegistry is the shared network topology store used by the heartbeat
// handler (writer) and the SRD plugin (reader) to build real risk-diffusion edges.
var topologyRegistry = struct {
	sync.RWMutex
	data map[string][]string // hostID → subnets
}{
	data: make(map[string][]string),
}

// recordTopology stores a host's subnets for SRD real-edge construction.
func recordTopology(hostID string, subnets []string) {
	topologyRegistry.Lock()
	topologyRegistry.data[hostID] = subnets
	topologyRegistry.Unlock()
}

// getTopology returns a snapshot of all host subnets.
func getTopology() map[string][]string {
	topologyRegistry.RLock()
	defer topologyRegistry.RUnlock()
	out := make(map[string][]string, len(topologyRegistry.data))
	for k, v := range topologyRegistry.data {
		out[k] = v
	}
	return out
}
