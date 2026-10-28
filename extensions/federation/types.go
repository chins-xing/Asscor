package federation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ZoneSummary aggregates one network zone's SSAM scores in a node report.
//
// Hosts is every host the node kernel currently knows in that zone; Scored is
// the subset that already has an assessment result (a freshly started kernel
// legitimately has hosts but no scores yet). AvgSSAM is the arithmetic mean
// over the scored hosts only, so a zone does not look healthier merely because
// its new hosts have not been assessed.
type ZoneSummary struct {
	Hosts   int     `json:"hosts"`
	Scored  int     `json:"scored"`
	AvgSSAM float64 `json:"avg_ssam"`
}

// NodeReport is the aggregate summary a node kernel POSTs to the master.
//
// It intentionally carries aggregates only — no host IDs, no check details:
// the demo master must not become a second copy of the node's inventory.
type NodeReport struct {
	NodeID     string                 `json:"node_id"`
	ConfigHash string                 `json:"config_hash"`
	Params     map[string]string      `json:"params,omitempty"`
	Hosts      int                    `json:"hosts"`
	Zones      map[string]ZoneSummary `json:"zones,omitempty"`
	// AvgSSAM is the overall (scored-host weighted) average; the master CLI
	// shows it directly and the per-zone breakdown explains it.
	AvgSSAM float64 `json:"avg_ssam"`
	// v0.2：图事实上报（主端可合并成一张跨节点分层图）。
	HostFacts   []HostFact   `json:"host_facts,omitempty"`
	PolicyFacts []PolicyFact `json:"policy_facts,omitempty"`
	PolicyKnown bool         `json:"policy_known,omitempty"`
	ReportedAt  time.Time    `json:"reported_at"`
	// ReceivedAt is stamped by the master collector; it is zero on the node
	// side and after JSON round-trips through /federation/nodes it is the
	// authoritative "last heard from" timestamp.
	ReceivedAt time.Time `json:"received_at,omitempty"`
}

// OverallAvgSSAM recomputes the scored-host weighted average over Zones.
// It returns 0 when no host has been scored.
func (r NodeReport) OverallAvgSSAM() float64 {
	var sum float64
	var n int
	for _, z := range r.Zones {
		sum += z.AvgSSAM * float64(z.Scored)
		n += z.Scored
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// ConfigHash computes a stable fingerprint over the effective key parameters
// (the [prism]/[srd] parameter map). Two nodes with identical model parameters
// produce the same hash; any changed key/value (including a removed key)
// changes it. The hash is what lets the master prove "one network, many
// configuration profiles" at a glance.
func ConfigHash(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	fmt.Fprintf(h, "asscor-federation-config-v1\n")
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, params[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ShortHash truncates a config hash for terminal display (16 hex chars = 64
// bits, plenty for a demo table). Full hashes stay in --json output.
func ShortHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16]
}

// FormatParams renders a parameter map as one "k=v, k=v" line (sorted,
// stable). Used by the CLI node view and by logs.
func FormatParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return strings.Join(parts, ", ")
}
