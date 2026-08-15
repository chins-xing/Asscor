package common

import "testing"

// TestAddAllowedCommands verifies runtime extension of the execution
// allowlist: added commands become executable, additions are idempotent, and
// blank entries are ignored. The built-in baseline is never removed.
func TestAddAllowedCommands(t *testing.T) {
	const extra = "zx-auditctl-test-cmd"

	// Must not be allowed before extension.
	if IsCommandAllowed(extra) {
		t.Fatalf("%q should not be allowed before AddAllowedCommands", extra)
	}

	AddAllowedCommands(extra, "  ", "", "zx-another-test-cmd")

	if !IsCommandAllowed(extra) {
		t.Errorf("%q should be allowed after AddAllowedCommands", extra)
	}
	if !IsCommandAllowed("zx-another-test-cmd") {
		t.Error("second command should be allowed")
	}

	// Idempotent: adding again must not error or corrupt the map.
	AddAllowedCommands(extra)
	if !IsCommandAllowed(extra) {
		t.Error("idempotent re-add must keep the command allowed")
	}

	// Builtin baseline must survive extension.
	for _, builtin := range []string{"systemctl", "ss", "iptables"} {
		if !IsCommandAllowed(builtin) {
			t.Errorf("builtin command %q must remain allowed", builtin)
		}
	}

	// ParseCommand must accept the extended command.
	if _, _, ok := ParseCommand(extra + " --status"); !ok {
		t.Error("ParseCommand should accept an extended command")
	}
}
