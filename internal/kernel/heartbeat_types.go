package kernel

import "time"

// AgentRecord tracks a registered agent's identity and liveness.
// CertFingerprint binds the agent's mTLS certificate (SHA-256, hex) to its
// host_id after first registration: a legal agent certificate cannot be used
// to impersonate a different host (identity hardening, audit I-01).
type AgentRecord struct {
	HostID          string
	Hostname        string
	Version         string
	LastSeen        time.Time
	Registered      time.Time
	Connections     int64
	Active          bool
	CertFingerprint string
}

type HeartbeatInterface interface {
	RecordHeartbeat(hostID string)
	RegisterAgent(hostID, hostname, version string)
	GetAgent(hostID string) *AgentRecord
	ListAgents() []*AgentRecord
	IsAlive(hostID string) bool
	// BindAgentCert binds hostID to the presented mTLS cert fingerprint on
	// first registration. Returns false when hostID is already bound to a
	// different fingerprint, or when the fingerprint is already bound to a
	// different hostID (one certificate, one identity).
	BindAgentCert(hostID, fingerprint string) bool
	// VerifyAgentCert checks that the connecting fingerprint matches the
	// fingerprint bound to hostID. Returns true when hostID has no binding
	// yet (first contact) or the fingerprints match.
	VerifyAgentCert(hostID, fingerprint string) bool
}
