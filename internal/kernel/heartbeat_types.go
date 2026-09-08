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

// RevokedCertInfo records a revoked certificate fingerprint (audit I-03).
// Revocation is keyed by the mTLS cert SHA-256 fingerprint, which is the same
// granularity the identity bindings use, so a single compromised certificate
// can be revoked without touching the CA or other hosts.
type RevokedCertInfo struct {
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason,omitempty"`
	RevokedAt   time.Time `json:"revoked_at"`
}

type HeartbeatInterface interface {
	RecordHeartbeat(hostID string)
	RegisterAgent(hostID, hostname, version string)
	GetAgent(hostID string) *AgentRecord
	ListAgents() []*AgentRecord
	IsAlive(hostID string) bool
	// BindAgentCert binds hostID to the presented mTLS cert fingerprint on
	// first registration. Returns false when hostID is already bound to a
	// different fingerprint, when the fingerprint is already bound to a
	// different hostID (one certificate, one identity), or when the
	// fingerprint has been revoked.
	BindAgentCert(hostID, fingerprint string) bool
	// VerifyAgentCert checks that the connecting fingerprint matches the
	// fingerprint bound to hostID. Returns true when hostID has no binding
	// yet (first contact) or the fingerprints match. Always returns false
	// for a revoked fingerprint.
	VerifyAgentCert(hostID, fingerprint string) bool
	// IsCertRevoked reports whether the certificate fingerprint has been
	// revoked. An empty fingerprint (mTLS disabled) is never revoked.
	IsCertRevoked(fingerprint string) bool
	// RevokeCert revokes a certificate fingerprint and unbinds any host
	// currently bound to it (so the host can re-register with a freshly
	// issued certificate). Returns an error when already revoked.
	RevokeCert(fingerprint, reason string) error
	// UnrevokeCert removes a fingerprint from the revocation list — the
	// recovery path for a mistaken revocation. Returns an error when the
	// fingerprint is not revoked.
	UnrevokeCert(fingerprint string) error
	// ListRevokedCerts returns all revoked fingerprints, oldest first.
	ListRevokedCerts() []RevokedCertInfo
	// ResetIdentityBindings clears every host↔certificate-fingerprint binding
	// and persists the empty state — the recovery path for a certificate-fleet
	// rebuild (CA replacement / mass rotation) where stale bindings block
	// re-registration with freshly issued certificates. Revocations are kept.
	// Returns the number of bindings cleared.
	ResetIdentityBindings() (int, error)
}
