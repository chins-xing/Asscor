package mitreengage

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// honeytokenHit records access to a decoy file/credential.
type honeytokenHit struct {
	Path      string
	Kind      string // "file" | "credential"
	Timestamp time.Time
}

// honeytokenDeployer places decoy files (MITRE Engage "Elicit" goal). An
// attacker who reads or uses a decoy reveals their presence. Uses only the
// standard library: files are placed under a configurable decoy root.
type honeytokenDeployer struct {
	mu    sync.Mutex
	root  string
	tokens map[string]honeytokenHit
	onHit func(honeytokenHit)
}

// NewHoneytokenDeployer creates a decoy deployer rooted at root.
func NewHoneytokenDeployer(root string, onHit func(honeytokenHit)) *honeytokenDeployer {
	return &honeytokenDeployer{
		root:  root,
		tokens: make(map[string]honeytokenHit),
		onHit: onHit,
	}
}

// DecoySpec describes a decoy file to deploy.
type DecoySpec struct {
	Path    string // relative path under root
	Content string // bait content (e.g. fake credentials)
	Kind    string // "file" | "credential"
}

// Deploy writes decoy files. Returns an error if any write fails.
func (d *honeytokenDeployer) Deploy(specs []DecoySpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range specs {
		full := filepath.Join(d.root, s.Path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(s.Content), 0600); err != nil {
			return err
		}
		d.tokens[full] = honeytokenHit{Path: full, Kind: s.Kind, Timestamp: time.Time{}}
	}
	return nil
}

// ReportAccess records that a decoy was touched (called by the file monitor).
func (d *honeytokenDeployer) ReportAccess(path string) {
	d.mu.Lock()
	hit := honeytokenHit{Path: path, Kind: "file", Timestamp: time.Now()}
	d.tokens[path] = hit
	d.mu.Unlock()
	if d.onHit != nil {
		d.onHit(hit)
	}
}

// Decoys lists all deployed decoy paths (copy).
func (d *honeytokenDeployer) Decoys() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.tokens))
	for p := range d.tokens {
		out = append(out, p)
	}
	return out
}

// Remove cleans up all deployed decoys.
func (d *honeytokenDeployer) Remove() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for p := range d.tokens {
		os.Remove(p)
	}
	d.tokens = make(map[string]honeytokenHit)
}
