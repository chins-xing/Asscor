package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func postReport(t *testing.T, url, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestMasterEndpointsCollectWithToken(t *testing.T) {
	collector := NewCollector()
	master := NewMasterServer(collector, ":0", "demo-token")
	srv := httptest.NewServer(master.Handler())
	defer srv.Close()

	payload, _ := json.Marshal(NodeReport{NodeID: "nk1", Hosts: 10, ConfigHash: "abc", AvgSSAM: 88})

	// Missing token → 401, nothing collected.
	resp := postReport(t, srv.URL+ReportPath, "", payload)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST without token = %d, want 401", resp.StatusCode)
	}
	if collector.Count() != 0 {
		t.Fatalf("collector accepted an unauthenticated report")
	}

	// Wrong token → 401.
	resp = postReport(t, srv.URL+ReportPath, "wrong", payload)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST with wrong token = %d, want 401", resp.StatusCode)
	}

	// Correct token → 200 and the node is stored.
	resp = postReport(t, srv.URL+ReportPath, "demo-token", payload)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST with token = %d (%s), want 200", resp.StatusCode, body)
	}
	if collector.Count() != 1 {
		t.Fatalf("collector.Count = %d, want 1", collector.Count())
	}

	// GET /federation/nodes returns the collected report.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+NodesPath, nil)
	req.Header.Set(TokenHeader, "demo-token")
	nresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET nodes: %v", err)
	}
	defer nresp.Body.Close()
	if nresp.StatusCode != http.StatusOK {
		t.Fatalf("GET nodes = %d, want 200", nresp.StatusCode)
	}
	var out struct {
		Count int          `json:"count"`
		Nodes []NodeReport `json:"nodes"`
	}
	if err := json.NewDecoder(nresp.Body).Decode(&out); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if out.Count != 1 || len(out.Nodes) != 1 || out.Nodes[0].NodeID != "nk1" {
		t.Fatalf("nodes response = %+v", out)
	}
}

func TestMasterEndpointMethodAndBodyErrors(t *testing.T) {
	collector := NewCollector()
	master := NewMasterServer(collector, ":0", "")
	srv := httptest.NewServer(master.Handler())
	defer srv.Close()

	// GET on the report endpoint → 405.
	resp, err := http.Get(srv.URL + ReportPath)
	if err != nil {
		t.Fatalf("GET report path: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET report = %d, want 405", resp.StatusCode)
	}

	// POST on the nodes endpoint → 405.
	resp = postReport(t, srv.URL+NodesPath, "", []byte(`{}`))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST nodes = %d, want 405", resp.StatusCode)
	}

	// Malformed JSON → 400.
	resp = postReport(t, srv.URL+ReportPath, "", []byte(`{not json`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid JSON = %d, want 400", resp.StatusCode)
	}

	// Missing node_id → 400 (ErrMissingNodeID surfaced).
	resp = postReport(t, srv.URL+ReportPath, "", []byte(`{"hosts":1}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing node_id = %d, want 400", resp.StatusCode)
	}
}

func TestMasterStartBindsWithoutBlockingAndStopsGracefully(t *testing.T) {
	collector := NewCollector()
	master := NewMasterServer(collector, "127.0.0.1:0", "tok")
	if err := master.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := master.Addr()
	if addr == "" || strings.HasSuffix(addr, ":0") {
		t.Fatalf("Addr = %q, want a concrete bound address", addr)
	}

	payload, _ := json.Marshal(NodeReport{NodeID: "nk1", Hosts: 1})
	resp := postReport(t, "http://"+addr+ReportPath, "tok", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to started master = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := master.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stopping twice is a harmless no-op.
	if err := master.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
