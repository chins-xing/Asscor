//go:build linux

package agent

import (
	"os/user"
	"strconv"
	"testing"
)

// TestLookupUIDFailsClosed covers audit C-2: a user lookup that cannot be
// resolved must return an error, never a silent 0 (root), because the caller
// feeds the result into verifyPeer's UID check.
func TestLookupUIDFailsClosed(t *testing.T) {
	if _, err := LookupUID(""); err == nil {
		t.Error("LookupUID(\"\") must fail")
	}
	if _, err := LookupUID("definitely-no-such-user-asscor-audit"); err == nil {
		t.Error("LookupUID(nonexistent) must fail, not silently return UID 0")
	}

	// Root exists on every Linux system; the resolver must return root's real
	// UID (0) with no error — the fail-closed guard lives in verifyPeer (which
	// refuses AllowedPeerUID <= 0) and in runPrivileged (which refuses to
	// start on lookup failure).
	u, err := user.Lookup("root")
	if err != nil {
		t.Skip("no root account resolvable on this system")
	}
	wantUID, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse root uid: %v", err)
	}
	got, err := LookupUID("root")
	if err != nil {
		t.Fatalf("LookupUID(root) failed: %v", err)
	}
	if got != wantUID {
		t.Fatalf("LookupUID(root) = %d, want %d", got, wantUID)
	}
}
