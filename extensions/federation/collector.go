package federation

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrMissingNodeID rejects a report that cannot be attributed to a node.
var ErrMissingNodeID = errors.New("federation: report has empty node_id")

// Collector is the master-side in-memory node registry. It is safe for
// concurrent use: the HTTP handlers write it while the CLI reads it.
//
// Update semantics: one entry per node_id — a later report from the same node
// replaces the earlier one (dedup + refresh), it never appends a duplicate.
type Collector struct {
	mu        sync.RWMutex
	nodes     map[string]NodeReport
	updatedAt time.Time
}

// NewCollector returns an empty collector.
func NewCollector() *Collector {
	return &Collector{nodes: make(map[string]NodeReport)}
}

// MasterState is the master-side collected federation state (the name used in
// the T4 design/task wording). It is the same type as Collector; both names
// are exported so callers can use either.
type MasterState = Collector

// NewMasterState returns an empty master-side state.
func NewMasterState() *MasterState { return NewCollector() }

// GetNodes is the task-wording alias for Nodes (returns the collected reports,
// sorted by node_id).
func (c *Collector) GetNodes() []NodeReport { return c.Nodes() }

// Apply stores/updates one node report. It validates the node identity and
// stamps ReceivedAt (master clock) so a node with a skewed clock cannot hide
// when the master last heard from it.
func (c *Collector) Apply(r NodeReport) error {
	r.NodeID = strings.TrimSpace(r.NodeID)
	if r.NodeID == "" {
		return ErrMissingNodeID
	}
	now := time.Now().UTC()
	if r.ReportedAt.IsZero() {
		r.ReportedAt = now
	}
	r.ReceivedAt = now

	c.mu.Lock()
	c.nodes[r.NodeID] = r
	c.updatedAt = now
	c.mu.Unlock()
	return nil
}

// Get returns a copy of one node's latest report.
func (c *Collector) Get(nodeID string) (NodeReport, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.nodes[nodeID]
	return r, ok
}

// Nodes returns a deep-ish copy of all node reports, sorted by node_id for
// deterministic CLI/HTTP output.
func (c *Collector) Nodes() []NodeReport {
	c.mu.RLock()
	out := make([]NodeReport, 0, len(c.nodes))
	for _, r := range c.nodes {
		cp := r
		cp.Params = cloneMap(r.Params)
		cp.Zones = cloneZones(r.Zones)
		out = append(out, cp)
	}
	c.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Count returns the number of distinct nodes seen.
func (c *Collector) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.nodes)
}

// LastUpdated returns the master-clock time of the most recent applied report.
func (c *Collector) LastUpdated() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updatedAt
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneZones(in map[string]ZoneSummary) map[string]ZoneSummary {
	if in == nil {
		return nil
	}
	out := make(map[string]ZoneSummary, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
