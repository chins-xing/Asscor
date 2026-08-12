package mitreengage

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

func TestHoneypotDetectsConnection(t *testing.T) {
	hitCh := make(chan honeypotHit, 1)
	h := NewHoneypot(func(hit honeypotHit) { hitCh <- hit })
	defer h.Stop()

	if err := h.Start([]int{0}); err != nil { // port 0 = ephemeral
		t.Fatalf("Start failed: %v", err)
	}
	// Find the actual bound port
	h.mu.Lock()
	var port int
	for p := range h.ports {
		port = p
	}
	ln := h.ports[port]
	h.mu.Unlock()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close()

	select {
	case hit := <-hitCh:
		if hit.LocalPort != port {
			t.Errorf("expected port %d, got %d", port, hit.LocalPort)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected honeypot hit")
	}
}

func TestHoneytokenDeploy(t *testing.T) {
	dir := t.TempDir()
	d := NewHoneytokenDeployer(dir, nil)
	specs := []DecoySpec{
		{Path: ".ssh/id_rsa.bak", Content: "decoy key", Kind: "credential"},
		{Path: "backup/db.txt", Content: "decoy db", Kind: "credential"},
	}
	if err := d.Deploy(specs); err != nil {
		t.Fatalf("Deploy failed: %v", err)
	}
	got := d.Decoys()
	if len(got) != 2 {
		t.Fatalf("expected 2 decoys, got %d", len(got))
	}
	d.Remove()
	if len(d.Decoys()) != 0 {
		t.Fatal("expected decoys removed")
	}
}

func TestEngageBlockerBlockUnblock(t *testing.T) {
	b := NewEngageBlocker(t.TempDir())
	b.SetPorts([]int{0}) // ephemeral port to avoid conflicts
	loc := &kernel.AttackerLocation{FootholdHost: "host-01", ActiveSubnets: []string{"10.0.0.0/24"}}

	res, err := b.Block(context.Background(), loc)
	if err != nil || res == nil || !res.Blocked {
		t.Fatalf("Block failed: res=%v err=%v", res, err)
	}
	if !b.IsBlocked(context.Background(), "host-01") {
		t.Fatal("expected blocked")
	}
	if err := b.Unblock(context.Background(), loc); err != nil {
		t.Fatalf("Unblock failed: %v", err)
	}
	if b.IsBlocked(context.Background(), "host-01") {
		t.Fatal("expected unblocked")
	}
}

func TestEngageBlockerGuideDeploysLateralDecoy(t *testing.T) {
	root := t.TempDir()
	b := NewEngageBlocker(root)
	// Neutralize the honeypot to avoid binding real attack ports in tests.
	b.intentGuider.honey.Stop()
	b.intentGuider.honey = NewHoneypot(nil)
	defer b.intentGuider.RemoveAll()

	loc := &kernel.AttackerLocation{FootholdHost: "host-01", LateralPath: []string{"host-02"}}
	n, err := b.Guide(context.Background(), loc)
	if err != nil {
		t.Fatalf("Guide error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 captures initially, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(root, ".ssh", "id_rsa.bak")); err != nil {
		t.Errorf("lateral-movement decoy not deployed: %v", err)
	}
}

func TestEngageBlockerGuideNilLocation(t *testing.T) {
	b := NewEngageBlocker(t.TempDir())
	n, err := b.Guide(context.Background(), nil)
	if err != nil || n != 0 {
		t.Fatalf("expected 0, nil for nil location, got %d, %v", n, err)
	}
}

func TestInferIntent(t *testing.T) {
	if got := inferIntent(&kernel.AttackerLocation{LateralPath: []string{"host-02"}}); got != IntentLateralMovement {
		t.Errorf("expected lateral_movement for lateral path, got %s", got)
	}
	if got := inferIntent(&kernel.AttackerLocation{}); got != IntentDiscovery {
		t.Errorf("expected discovery fallback, got %s", got)
	}
}
