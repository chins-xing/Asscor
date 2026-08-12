// Package mitreengage provides a lightweight MITRE Engage active-defense
// extension for ASSCOR: honeypots, honeytokens, and honey credentials.
// Zero external dependencies — pure Go standard library.
package mitreengage

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// honeypotHit records a connection to a decoy port — evidence of an attacker
// probing the network (MITRE Engage "Expose" goal).
type honeypotHit struct {
	RemoteIP   string
	RemotePort string
	LocalPort  int
	Timestamp  time.Time
}

// honeypot is a lightweight TCP decoy listener. It listens on common attack
// ports and records any connection source without responding — contrast with
// heavyweight honeypot clusters (T-Pot) that simulate full services.
type honeypot struct {
	mu      sync.Mutex
	ports   map[int]net.Listener
	hits    []honeypotHit
	onHit   func(honeypotHit)
	started bool
}

// NewHoneypot creates an empty honeypot controller.
func NewHoneypot(onHit func(honeypotHit)) *honeypot {
	return &honeypot{
		ports: make(map[int]net.Listener),
		onHit: onHit,
	}
}

// CommonAttackPorts lists ports frequently probed by attackers.
var CommonAttackPorts = []int{21, 22, 23, 25, 445, 3389, 8080, 9200, 6379}

// Start begins listening on the given ports. Any connection is recorded and
// immediately closed (no protocol response — pure "Expose" not "Simulate").
// Per the "good enough" principle, a single port that fails to bind (already
// in use) is skipped rather than failing the whole deployment.
func (h *honeypot) Start(ports []int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var lastErr error
	for _, port := range ports {
		if _, exists := h.ports[port]; exists {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			lastErr = err
			continue // skip unavailable port — good enough
		}
		h.ports[port] = ln
		go h.serve(port, ln)
	}
	if len(h.ports) > 0 {
		h.started = true
	}
	return lastErr
}

func (h *honeypot) serve(port int, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		hit := honeypotHit{
			RemoteIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
			RemotePort: fmt.Sprintf("%d", conn.RemoteAddr().(*net.TCPAddr).Port),
			LocalPort:  port,
			Timestamp:  time.Now(),
		}
		conn.Close() // no response — record only

		h.mu.Lock()
		h.hits = append(h.hits, hit)
		h.mu.Unlock()

		if h.onHit != nil {
			h.onHit(hit)
		}
	}
}

// Stop closes all decoy listeners.
func (h *honeypot) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for port, ln := range h.ports {
		ln.Close()
		delete(h.ports, port)
	}
	h.started = false
}

// Hits returns all recorded connections (copy).
func (h *honeypot) Hits() []honeypotHit {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]honeypotHit, len(h.hits))
	copy(out, h.hits)
	return out
}
