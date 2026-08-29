package agent

import (
	"strings"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/model"
)

// ---------------------------------------------------------------------------
// executePendingCommands — pending command queue draining
// ---------------------------------------------------------------------------

func TestExecutePendingCommandsEmpty(t *testing.T) {
	a := &Agent{}
	a.executePendingCommands() // must be a no-op
	if len(a.pendingCmd) != 0 {
		t.Errorf("pendingCmd should stay empty, got %v", a.pendingCmd)
	}
}

func TestExecutePendingCommandsSkipsBadSignature(t *testing.T) {
	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	a.pendingCmd = []*apiv1.Command{
		{CommandId: "bad", Command: "go version"}, // no signature at all
	}
	a.executePendingCommands()
	if len(a.pendingCmd) != 0 {
		t.Errorf("pendingCmd should be drained even for rejected commands, got %v", a.pendingCmd)
	}
}

func TestExecutePendingCommandsRejectsTampered(t *testing.T) {
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")
	cmd.Command = "go version" // tampered after signing

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	a.pendingCmd = []*apiv1.Command{cmd}
	a.executePendingCommands()
	if len(a.pendingCmd) != 0 {
		t.Errorf("pendingCmd should be drained after rejected command, got %v", a.pendingCmd)
	}
}

func TestExecutePendingCommandsRunsValid(t *testing.T) {
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	a.pendingCmd = []*apiv1.Command{cmd}
	a.executePendingCommands() // must not panic; "systemctl is-active sshd" may fail on this host but is allowlisted
	if len(a.pendingCmd) != 0 {
		t.Errorf("pendingCmd should be drained after execution, got %v", a.pendingCmd)
	}
}

// ---------------------------------------------------------------------------
// runCommand — allowlist enforcement and delegation
// ---------------------------------------------------------------------------

func TestRunCommandRejectsNotAllowlisted(t *testing.T) {
	a := &Agent{}
	cmd := &apiv1.Command{CommandId: "c1", Command: "rm -rf /tmp/x"}
	a.runCommand(cmd) // must not panic, must not execute
}

func TestRunCommandAllowlistedRuns(t *testing.T) {
	// "go" is on PATH in the test environment; extend the allowlist to it so
	// we exercise the real execution path (ParseCommand + RunCmdTimeout).
	common.AddAllowedCommands("go")
	a := &Agent{}
	cmd := &apiv1.Command{CommandId: "c2", Command: "go version"}
	a.runCommand(cmd) // must not panic
}

func TestRunCommandShellMetacharRejected(t *testing.T) {
	a := &Agent{}
	// Pipe metacharacters are rejected by ParseCommand before execution.
	cmd := &apiv1.Command{CommandId: "c3", Command: "go version | head -1"}
	a.runCommand(cmd)
}

// ---------------------------------------------------------------------------
// delegateRootCommand — privileged agent forwarding
// ---------------------------------------------------------------------------

func TestDelegateRootCommandNoClient(t *testing.T) {
	a := &Agent{privClient: nil}
	cmd := &apiv1.Command{CommandId: "c4", Command: "isolate_host"}
	a.delegateRootCommand(cmd) // must log an error, not panic
}

func TestDelegateRootCommandWithClient(t *testing.T) {
	a := &Agent{privClient: NewPrivilegedClient("/nonexistent/priv.sock")}
	cmd := &apiv1.Command{CommandId: "c5", Command: "isolate_host", Params: map[string]string{"host_id": "web-01"}}
	a.delegateRootCommand(cmd) // stub client fails on non-Linux; must not panic
}

// ---------------------------------------------------------------------------
// runCommand — isolate/deisolate routing through delegateRootCommand
// ---------------------------------------------------------------------------

func TestRunCommandRoutesIsolationToPrivileged(t *testing.T) {
	a := &Agent{privClient: nil}
	for _, name := range []string{"isolate_host", "deisolate_host"} {
		cmd := &apiv1.Command{CommandId: "c-" + name, Command: name}
		a.runCommand(cmd) // routed to delegateRootCommand; nil client → error log only
	}
}

// ---------------------------------------------------------------------------
// runRootChecks — root check delegation with graceful degradation
// ---------------------------------------------------------------------------

func TestRunRootChecksNoRootRegistered(t *testing.T) {
	// In a plain test build (no checks tag) the root registry is empty, so
	// runRootChecks returns nil without touching the privileged agent.
	a := &Agent{}
	if res := a.runRootChecks(); len(res) != 0 {
		t.Errorf("no root checks registered: got %d results, want 0", len(res))
	}
}

func TestRunRootChecksSkippedWithoutClient(t *testing.T) {
	const rootID = "RT-TEST-001"
	checks.Register(model.CheckItem{
		ID:        rootID,
		Domain:    model.DomainKernelSecurity,
		Name:      "root test check",
		Delta:     -2,
		Privilege: model.PrivRoot,
		Check:     func() (bool, string) { return true, "root-only" },
	})
	t.Cleanup(func() { checks.Unregister(rootID) })

	a := &Agent{privClient: nil}
	res := a.runRootChecks()
	found := false
	for _, r := range res {
		if r.CheckID == rootID {
			found = true
			if r.Passed != true {
				t.Errorf("skipped root check should be Passed=true (neutral), got %+v", r)
			}
			if r.Delta != 0 {
				t.Errorf("skipped root check should carry Delta=0 (no score impact), got %+v", r)
			}
			if !strings.Contains(r.Detail, "skipped") {
				t.Errorf("detail should mention skipped, got %q", r.Detail)
			}
		}
	}
	if !found {
		t.Errorf("root check %s missing from results: %+v", rootID, res)
	}
}

func TestRunRootChecksWithStubClient(t *testing.T) {
	const rootID = "RT-TEST-002"
	checks.Register(model.CheckItem{
		ID:        rootID,
		Domain:    model.DomainKernelSecurity,
		Name:      "root test check 2",
		Privilege: model.PrivRoot,
		Check:     func() (bool, string) { return true, "x" },
	})
	t.Cleanup(func() { checks.Unregister(rootID) })

	// Stub client on non-Linux always fails, so results fall back to skipped.
	a := &Agent{privClient: NewPrivilegedClient("/nonexistent/priv.sock")}
	res := a.runRootChecks()
	for _, r := range res {
		if r.CheckID == rootID && r.Passed != true {
			t.Errorf("unavailable privileged client should yield neutral skip, got %+v", r)
		}
	}
}

// ---------------------------------------------------------------------------
// runChecks — full pipeline with root checks appended
// ---------------------------------------------------------------------------

func TestRunChecksAppendsRootResults(t *testing.T) {
	const rootID = "RT-TEST-003"
	checks.Register(model.CheckItem{
		ID:        rootID,
		Domain:    model.DomainKernelSecurity,
		Name:      "root test check 3",
		Privilege: model.PrivRoot,
		Check:     func() (bool, string) { return true, "x" },
	})
	t.Cleanup(func() { checks.Unregister(rootID) })

	a := &Agent{
		checkers: []model.CheckItem{
			testCheckItem("N-001", func() (bool, string) { return true, "ok" }),
		},
	}
	res := a.runChecks()
	// Normal check + (skipped) root check.
	if len(res) < 2 {
		t.Fatalf("expected normal + root results, got %d: %+v", len(res), res)
	}
	if res[0].CheckID != "N-001" {
		t.Errorf("first result should be the normal check, got %+v", res[0])
	}
	// Root check must be present with neutral skip semantics.
	found := false
	for _, r := range res[1:] {
		if r.CheckID == rootID {
			found = true
			if r.Delta != 0 {
				t.Errorf("skipped root check delta = %v, want 0", r.Delta)
			}
		}
	}
	if !found {
		t.Errorf("root check %s not appended: %+v", rootID, res)
	}
}

// ---------------------------------------------------------------------------
// runCommand — securemode_* routing (RC-specific: these branches do not exist
// in main's agent_command_test.go, gap report ① tail)
// ---------------------------------------------------------------------------

// TestRunCommandRoutesSecureModeCommands: securemode_exit/rotate/unlock/enter
// are dispatched to executeSecureModeCommand, never to the shell allowlist —
// they are not shell commands, so they must not be rejected as non-allowlisted.
func TestRunCommandRoutesSecureModeCommands(t *testing.T) {
	a := &Agent{}
	for _, name := range []string{"securemode_exit", "securemode_rotate", "securemode_unlock", "securemode_enter"} {
		cmd := &apiv1.Command{CommandId: "c-" + name, Command: name, Params: map[string]string{"password": "x"}}
		a.runCommand(cmd) // no secure state → ignored via executeSecureModeCommand, must not panic
	}
}

// TestRunCommandSecureModeExitDecrypts: a signed securemode_exit routed through
// runCommand reaches executeSecureModeCommand and actually decrypts the .enc —
// proving the routing lands in the secure handler (not the shell path).
func TestRunCommandSecureModeExitDecrypts(t *testing.T) {
	v, _ := newSecureTestVault(t)
	a := NewAgent(DefaultConfig())
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if err := a.secureMaybeBootstrap(); err != nil {
		t.Fatal(err)
	}
	pw := a.secure.password
	if !v.IsEncrypted() {
		t.Fatal("test setup must leave the config encrypted")
	}

	cmd := &apiv1.Command{
		CommandId: "c-sec-exit",
		Command:   "securemode_exit",
		Params:    map[string]string{"password": pw},
	}
	a.runCommand(cmd)

	if !v.HasPlaintext() || v.IsEncrypted() {
		t.Errorf("securemode_exit via runCommand must decrypt: plain=%v enc=%v", v.HasPlaintext(), v.IsEncrypted())
	}
	if a.secure.password != "" {
		t.Errorf("ephemeral password must be cleared after exit, got %q", a.secure.password)
	}
}

// ---------------------------------------------------------------------------
// verifyCommandSignature — timestamp edge case through executePendingCommands
// ---------------------------------------------------------------------------

func TestExecutePendingCommandsRejectsExpired(t *testing.T) {
	cmd := &apiv1.Command{
		CommandId: "cmd-stale",
		Command:   "go version",
		Params: map[string]string{
			"_timestamp": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		},
	}
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	a.pendingCmd = []*apiv1.Command{cmd}
	a.executePendingCommands()
	if len(a.pendingCmd) != 0 {
		t.Errorf("stale command should be rejected and queue drained, got %v", a.pendingCmd)
	}
}
