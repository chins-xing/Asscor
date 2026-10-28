package federation

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// maxReportBody caps the POST body (aggregate summary only — a few KiB is
// already generous; the cap keeps a rogue node from streaming the master
// out of memory).
const maxReportBody = 1 << 20 // 1 MiB

// MasterServer is the master kernel's HTTP collection endpoint:
//
//	POST /federation/report  — accept one NodeReport (JSON body)
//	GET  /federation/nodes   — return all collected reports
//
// Both endpoints require the [federation] token header when a token is
// configured. The listener is opened synchronously in Start (so a busy port is
// reported immediately) but the serve loop runs in the background — Start
// never blocks kernel bootstrap.
type MasterServer struct {
	collector  *Collector
	listenAddr string
	token      string

	mu  sync.Mutex
	ln  net.Listener
	srv *http.Server
}

// NewMasterServer builds the master collection endpoint. token may be empty
// (demo without a shared secret).
func NewMasterServer(collector *Collector, listenAddr, token string) *MasterServer {
	if collector == nil {
		collector = NewCollector()
	}
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}
	return &MasterServer{collector: collector, listenAddr: listenAddr, token: token}
}

// Collector exposes the collector (the kernel plugin hands it to the CLI).
func (m *MasterServer) Collector() *Collector { return m.collector }

// Start binds the listener and launches the HTTP server in the background. It
// returns once the listener is bound; it does not wait for the kernel.
func (m *MasterServer) Start() error {
	ln, err := net.Listen("tcp", m.listenAddr)
	if err != nil {
		return fmt.Errorf("federation: listen %s: %w", m.listenAddr, err)
	}
	srv := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	m.mu.Lock()
	m.ln = ln
	m.srv = srv
	m.mu.Unlock()

	go func() {
		// Serve only fails when the listener dies (or on Shutdown, which is
		// the expected path); the plugin health check surfaces a dead server.
		_ = srv.Serve(ln)
	}()
	return nil
}

// Addr returns the bound address (useful with listen_addr=:0 in tests).
func (m *MasterServer) Addr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln == nil {
		return m.listenAddr
	}
	return m.ln.Addr().String()
}

// Stop gracefully shuts the server down, bounded by ctx.
func (m *MasterServer) Stop(ctx context.Context) error {
	m.mu.Lock()
	srv := m.srv
	m.srv = nil
	m.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler returns the HTTP handler (exported for httptest in unit tests).
func (m *MasterServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(ReportPath, m.handleReport)
	mux.HandleFunc(NodesPath, m.handleNodes)
	mux.HandleFunc("/federation/check", m.handleCheck)
	return mux
}

func (m *MasterServer) authorized(r *http.Request) bool {
	if m.token == "" {
		return true
	}
	got := r.Header.Get(TokenHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(m.token)) == 1
}

func (m *MasterServer) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed: use POST")
		return
	}
	if !m.authorized(r) {
		writeJSONError(w, http.StatusUnauthorized, "invalid federation token")
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxReportBody)
	defer body.Close()

	var report NodeReport
	dec := json.NewDecoder(body)
	if err := dec.Decode(&report); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid report JSON: "+err.Error())
		return
	}
	if err := m.collector.Apply(report); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"node_id": report.NodeID,
		"nodes":   m.collector.Count(),
	})
}

func (m *MasterServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed: use GET")
		return
	}
	if !m.authorized(r) {
		writeJSONError(w, http.StatusUnauthorized, "invalid federation token")
		return
	}

	nodes := m.collector.Nodes()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":      len(nodes),
		"updated_at": m.collector.LastUpdated(),
		"nodes":      nodes,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}


// handleCheck 在合并图上回答跨节点可达性：GET /federation/check?src=&dst=。
func (m *MasterServer) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	src := r.URL.Query().Get("src")
	dst := r.URL.Query().Get("dst")
	if src == "" || dst == "" {
		http.Error(w, "missing src/dst", http.StatusBadRequest)
		return
	}
	var reports []NodeReport
	if m.collector != nil {
		reports = m.collector.Nodes()
	}
	res := CheckMerged(BuildMergedGraph(reports), src, dst, 5)
	res.Nodes = len(reports)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
