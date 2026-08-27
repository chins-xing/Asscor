package securemode

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	s, ok := r.Lookup("fp1")
	if !ok || s.AgentID != "host-a" || s.Password != "pw1" {
		t.Fatalf("lookup = %+v ok=%v", s, ok)
	}
}

func TestRegistryFingerprintKeyed(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("fp2", "host-b", "pw2"); err != nil {
		t.Fatal(err)
	}
	if r.Size() != 2 {
		t.Errorf("size = %d, want 2", r.Size())
	}
	// host-a's password is only reachable via fp1, not via fp2.
	if s, _ := r.Lookup("fp2"); s.AgentID == "host-a" {
		t.Error("fingerprint fp2 must map only to host-b")
	}
}

func TestRegistryFakeAgentIDRejected(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	// Attacker forges agent_id for a fingerprint that is already bound to
	// host-a: must be rejected at the transport layer (one cert, one identity).
	err := r.Register("fp1", "host-evil", "pw-evil")
	if err == nil {
		t.Fatal("registering a different agent_id under an existing fingerprint must be rejected")
	}
	// The original binding must survive.
	if s, _ := r.Lookup("fp1"); s.AgentID != "host-a" {
		t.Errorf("binding must stay host-a, got %+v", s)
	}
}

func TestRegistryAgentRotateUpdatesPassword(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "old-pw"); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("fp1", "host-a", "new-pw"); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Lookup("fp1"); s.Password != "new-pw" {
		t.Errorf("password = %q, want new-pw after rotate", s.Password)
	}
}

func TestRegistryRemove(t *testing.T) {
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "pw")
	r.Remove("fp1")
	if _, ok := r.Lookup("fp1"); ok {
		t.Error("entry must be gone after Remove")
	}
}

func TestRegistryMarshalRoundTrip(t *testing.T) {
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "pw1")
	r.Register("fp2", "host-b", "pw2")

	data, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r2 := NewSecretRegistry()
	if err := r2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if r2.Size() != 2 {
		t.Fatalf("restored size = %d, want 2", r2.Size())
	}
	if s, _ := r2.Lookup("fp1"); s.AgentID != "host-a" || s.Password != "pw1" {
		t.Errorf("restored fp1 = %+v", s)
	}
	// Unmarshal must fail on garbage.
	if err := r2.Unmarshal([]byte("garbage")); err == nil {
		t.Error("garbage data must fail Unmarshal")
	}
	// JSON "null" is garbage for a registry: it must be rejected, not silently
	// wipe the entries (which would also turn the next Register into a nil-map
	// panic).
	if err := r2.Unmarshal([]byte("null")); err == nil {
		t.Error("null payload must fail Unmarshal")
	}
	if r2.Size() != 2 {
		t.Error("failed Unmarshal must not clobber existing entries")
	}
}

func TestRegistryPersistenceEncrypted(t *testing.T) {
	// Persistence contract (spec §10.1): this layer serializes the registry as
	// PLAINTEXT JSON; the CALLER encrypts the blob with the kernel run-mode key
	// before persisting. (The plan's original raw-probe assertion is impossible
	// under plaintext JSON — values must be recoverable for the round-trip —
	// so this test locks the actual contract instead.)
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "super-secret-pw")
	data, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Marshal must emit valid JSON — never an encrypted/base64 blob, which
	// would double-encrypt in Task 8's run-mode-key persistence wrapper.
	if !json.Valid(data) {
		t.Errorf("wire format must be plaintext JSON (caller encrypts), got %q", data)
	}
	// Unmarshal must reject garbage (second line of defense on the decrypt path).
	if err := r.Unmarshal([]byte("garbage")); err == nil {
		t.Error("garbage data must fail Unmarshal")
	}
}

func TestRegistryUpdatedAt(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw"); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Lookup("fp1")
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt must be set")
	}
	// rotate updates timestamp
	old := s.UpdatedAt
	time.Sleep(2 * time.Millisecond)
	r.Register("fp1", "host-a", "pw2")
	s2, _ := r.Lookup("fp1")
	if !s2.UpdatedAt.After(old) {
		t.Error("rotate must bump UpdatedAt")
	}
}

// TestRegistryListEntries (review M5): the status display must be able to
// show the fingerprint PRIMARY KEY of each registration — ListEntries returns
// display-only entries (fingerprint + identity + timestamp) that structurally
// cannot carry the secret.
func TestRegistryListEntries(t *testing.T) {
	r := NewSecretRegistry()
	longFP := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := r.Register(longFP, "host-a", "secret-pw-a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("fp2", "host-b", "secret-pw-b"); err != nil {
		t.Fatal(err)
	}
	entries := r.ListEntries()
	if len(entries) != 2 {
		t.Fatalf("ListEntries len = %d, want 2", len(entries))
	}
	byFP := make(map[string]AgentSecretEntry, len(entries))
	for _, e := range entries {
		byFP[e.Fingerprint] = e
	}
	e1, ok := byFP[longFP]
	if !ok {
		t.Fatalf("ListEntries must carry the fingerprint primary key, got %+v", entries)
	}
	if e1.AgentID != "host-a" || e1.UpdatedAt.IsZero() {
		t.Errorf("longFP entry = %+v, want host-a with UpdatedAt", e1)
	}
	if e2 := byFP["fp2"]; e2.AgentID != "host-b" {
		t.Errorf("fp2 entry = %+v, want host-b", e2)
	}
	// List() must stay available for callers that need the full records.
	if list := r.List(); len(list) != 2 {
		t.Errorf("List() len = %d, want 2", len(list))
	}
}
