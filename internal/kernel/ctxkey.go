package kernel

import "context"

type CtxKey string

// Context keys for connection-level identity propagated from the transport
// layer into service handlers.
const (
	// CtxClientAddr is the remote address of the connected peer.
	CtxClientAddr CtxKey = "client_addr"
	// CtxPeerCertFingerprint is the SHA-256 fingerprint of the mTLS peer
	// certificate presented by the connecting agent (hex-encoded). Empty when
	// mTLS is disabled (development only).
	CtxPeerCertFingerprint CtxKey = "peer_cert_fingerprint"
	// CtxPeerCertCommonName is the peer certificate Subject.CommonName.
	// Agent certificates use "ASSCOR Agent <hostID>"; handlers use it to
	// scope an agent to its own host (audit D-03/D-04).
	CtxPeerCertCommonName CtxKey = "peer_cert_common_name"
)

// PeerCertFingerprintFromContext returns the mTLS peer certificate fingerprint
// recorded for this connection, or "" when unavailable (no mTLS).
func PeerCertFingerprintFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(CtxPeerCertFingerprint).(string); ok {
		return v
	}
	return ""
}

// PeerCertCommonNameFromContext returns the mTLS peer certificate CommonName,
// or "" when unavailable (no mTLS).
func PeerCertCommonNameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(CtxPeerCertCommonName).(string); ok {
		return v
	}
	return ""
}
