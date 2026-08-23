package securemode

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentSecret is the kernel-side record of an agent's ephemeral unlock
// secret. The agent's password is a TEMPORARY unlock secret (spec §3.1/P1-1),
// not a long-term credential.
type AgentSecret struct {
	AgentID   string    `json:"agent_id"`
	Password  string    `json:"password"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretRegistry maps mTLS client-cert fingerprint -> agent secret. The
// fingerprint is the PRIMARY KEY (spec §10.1): even if an attacker forges an
// agent_id, the fingerprint mismatch is rejected at the transport layer.
type SecretRegistry struct {
	mu      sync.RWMutex
	entries map[string]AgentSecret
}

// NewSecretRegistry creates an empty registry.
func NewSecretRegistry() *SecretRegistry {
	return &SecretRegistry{entries: make(map[string]AgentSecret)}
}

// Register records/updates the secret for a fingerprint. It enforces the
// one-certificate-one-identity constraint: registering a DIFFERENT agent_id
// under an already-bound fingerprint is rejected (the fingerprint check the
// transport layer performs before this call is authoritative; this is the
// application-level backstop).
func (r *SecretRegistry) Register(fingerprint, agentID, password string) error {
	if fingerprint == "" || agentID == "" || password == "" {
		return fmt.Errorf("fingerprint, agent_id and password are all required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.entries[fingerprint]; ok {
		if existing.AgentID != agentID {
			return fmt.Errorf("fingerprint %q is bound to agent %q, refusing agent %q (one certificate, one identity)",
				fingerprint, existing.AgentID, agentID)
		}
		// Same identity: password rotation / re-registration.
		existing.Password = password
		existing.UpdatedAt = time.Now()
		r.entries[fingerprint] = existing
		return nil
	}
	r.entries[fingerprint] = AgentSecret{
		AgentID:   agentID,
		Password:  password,
		UpdatedAt: time.Now(),
	}
	return nil
}

// Lookup returns the secret for a fingerprint (used to unlock on agent
// restart and to issue mode-exit decryption).
func (r *SecretRegistry) Lookup(fingerprint string) (AgentSecret, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.entries[fingerprint]
	return s, ok
}

// LookupByAgent returns the first entry matching agentID (CLI display).
func (r *SecretRegistry) LookupByAgent(agentID string) (AgentSecret, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.entries {
		if s.AgentID == agentID {
			return s, true
		}
	}
	return AgentSecret{}, false
}

// Remove deletes the fingerprint entry.
func (r *SecretRegistry) Remove(fingerprint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, fingerprint)
}

// Size returns the number of registered agents.
func (r *SecretRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// List returns all entries (CLI status).
func (r *SecretRegistry) List() []AgentSecret {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AgentSecret, 0, len(r.entries))
	for _, s := range r.entries {
		out = append(out, s)
	}
	return out
}

// Marshal serializes the registry (plaintext; callers encrypt with the
// kernel run-mode key before persisting — spec §10.1).
func (r *SecretRegistry) Marshal() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.Marshal(r.entries)
}

// Unmarshal restores the registry from Marshal output.
func (r *SecretRegistry) Unmarshal(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var entries map[string]AgentSecret
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("registry unmarshal: %w", err)
	}
	// JSON "null" decodes into a nil map without error; accepting it would
	// silently wipe the registry and make the next Register panic on a nil
	// map (crafted/corrupt payload -> crash). Fail closed instead (spec §11).
	if entries == nil {
		return fmt.Errorf("registry unmarshal: null payload is not a registry")
	}
	r.entries = entries
	return nil
}
