//go:build comms && heartbeat

package comms

import (
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/heartbeat"
	"github.com/asscor/asscor/internal/securemode"
)

// TestHeartbeatSecureModeRegistrationPersists (spec §10.1 P0-1): a heartbeat
// registration while the kernel is in run mode must persist the registry
// (encrypted under the kernel run-mode password), so a later kernel restart
// can recover it. In default mode the registration stays in memory only.
func TestHeartbeatSecureModeRegistrationPersists(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(cfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vault := &securemode.Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: "[bootstrap]"}
	ctrl := securemode.NewController(dir, []*securemode.Vault{vault})
	if err := ctrl.EnterRun("kernel-pw"); err != nil {
		t.Fatalf("enter run: %v", err)
	}

	svc := &KernelServiceImpl{heartbeat: heartbeat.New()}
	svc.SetSecureMode(ctrl)
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := svc.Heartbeat(ctxWithFP("fp-a"), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: "agent-ephemeral-pw"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("heartbeat with secure-mode report failed (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}

	// The registry file must exist (encrypted) after the registration.
	if _, err := os.Stat(securemode.SecretsFilePath(dir)); err != nil {
		t.Fatalf("registration must persist the registry in run mode: %v", err)
	}
	// A fresh controller over the same dir must recover the registration.
	ctrl2 := securemode.NewController(dir, []*securemode.Vault{vault})
	if err := ctrl2.LoadSecrets("kernel-pw"); err != nil {
		t.Fatalf("recover registry after restart: %v", err)
	}
	s, ok := ctrl2.Secrets.Lookup("fp-a")
	if !ok || s.Password != "agent-ephemeral-pw" || s.AgentID != "host-a" {
		t.Fatalf("recovered registration = %+v ok=%v", s, ok)
	}
}
