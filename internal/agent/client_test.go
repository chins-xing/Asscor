package agent

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// ---------------------------------------------------------------------------
// Test helpers — an in-process JSON-over-TCP "kernel" endpoint
// ---------------------------------------------------------------------------

// testKernel is a minimal in-process server that speaks the same
// newline-delimited JSON envelope protocol as the real kernel RPC endpoint
// (see Client.call). Each accepted connection is served by a handler that
// receives the decoded envelope and returns the response envelope to write.
type testKernel struct {
	ln      net.Listener
	handler func(env map[string]interface{}) map[string]interface{}
	wg      sync.WaitGroup
}

// newTestKernel starts a listener on 127.0.0.1:0. The handler receives the
// decoded request envelope ({service, method, payload}) and must return a
// response envelope with "status" (and optionally "payload"/"error").
func newTestKernel(t *testing.T, handler func(env map[string]interface{}) map[string]interface{}) *testKernel {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	k := &testKernel{ln: ln, handler: handler}
	k.wg.Add(1)
	go k.serve()
	t.Cleanup(func() { k.ln.Close(); k.wg.Wait() })
	return k
}

func (k *testKernel) addr() string { return k.ln.Addr().String() }

func (k *testKernel) serve() {
	defer k.wg.Done()
	for {
		conn, err := k.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go k.handleConn(conn)
	}
}

func (k *testKernel) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var env map[string]interface{}
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		resp := k.handler(env)
		data, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		conn.Write(append(data, '\n'))
	}
}

func okEnv(payload interface{}) map[string]interface{} {
	return map[string]interface{}{"status": "ok", "payload": payload}
}

func errEnv(msg string) map[string]interface{} {
	return map[string]interface{}{"status": "error", "error": msg}
}

// ---------------------------------------------------------------------------
// Connect / Close / Connected
// ---------------------------------------------------------------------------

func TestClientConnectAndConnected(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{})
	})

	c := NewClient(k.addr(), nil)
	defer c.Close()

	if c.Connected() {
		t.Fatal("Connected() should be false before Connect")
	}
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !c.Connected() {
		t.Error("Connected() should be true after Connect")
	}

	// Re-connecting closes the old connection and dials again.
	if err := c.Connect(); err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if !c.Connected() {
		t.Error("Connected() should be true after re-Connect")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c.Connected() {
		t.Error("Connected() should be false after Close")
	}
}

func TestClientConnectRefused(t *testing.T) {
	// Reserve a port, then close the listener so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := NewClient(addr, nil)
	defer c.Close()

	err = c.Connect()
	if err == nil {
		t.Fatal("Connect to a refused port should fail")
	}
	if !strings.Contains(err.Error(), "connect to "+addr) {
		t.Errorf("error should mention the address, got: %v", err)
	}
}

func TestClientCloseIdempotent(t *testing.T) {
	c := NewClient("127.0.0.1:1", nil)
	if err := c.Close(); err != nil {
		t.Errorf("Close on a never-connected client should be nil, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close should be nil, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Call — request/response round trip over the wire
// ---------------------------------------------------------------------------

func TestClientCallRoundTrip(t *testing.T) {
	var gotMethod, gotService string
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		gotService, _ = env["service"].(string)
		gotMethod, _ = env["method"].(string)
		return okEnv(map[string]interface{}{
			"accepted":   true,
			"session_id": "sess-123",
		})
	})

	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	err := c.Call("ASSCOR.v1.KernelService", "Register",
		&apiv1.RegisterRequest{HostId: "host-1"}, &resp)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotService != "ASSCOR.v1.KernelService" || gotMethod != "Register" {
		t.Errorf("kernel saw service=%q method=%q", gotService, gotMethod)
	}
	if !resp.Accepted || resp.SessionId != "sess-123" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestClientCallNotConnected(t *testing.T) {
	c := NewClient("127.0.0.1:1", nil)
	defer c.Close()

	var resp apiv1.RegisterResponse
	err := c.Call("S", "M", &apiv1.RegisterRequest{}, &resp)
	if err == nil {
		t.Fatal("Call on a disconnected client should fail")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error = %v, want 'not connected'", err)
	}
}

func TestClientCallRPCError(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return errEnv("kernel rejected")
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	err := c.Call("S", "M", &apiv1.RegisterRequest{}, &resp)
	if err == nil {
		t.Fatal("kernel error should surface")
	}
	if !strings.Contains(err.Error(), "rpc error: kernel rejected") {
		t.Errorf("error = %v, want rpc error text", err)
	}
}

func TestClientCallMalformedResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		br.ReadBytes('\n') // consume request
		conn.Write([]byte("this is not json\n"))
	}()

	c := NewClient(ln.Addr().String(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	err = c.Call("S", "M", &apiv1.RegisterRequest{}, &resp)
	if err == nil {
		t.Fatal("malformed response should fail")
	}
	if !strings.Contains(err.Error(), "unmarshal response") {
		t.Errorf("error = %v, want unmarshal response", err)
	}
}

func TestClientCallPayloadMismatch(t *testing.T) {
	// Kernel returns a payload whose shape does not match the caller's
	// expected response type (e.g. RegisterResponse vs a string).
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv("not-an-object")
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	err := c.Call("S", "M", &apiv1.RegisterRequest{}, &resp)
	if err == nil {
		t.Fatal("type-mismatched payload should fail to unmarshal")
	}
	if !strings.Contains(err.Error(), "unmarshal response") {
		t.Errorf("error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Register / Heartbeat high-level wrappers
// ---------------------------------------------------------------------------

func TestClientRegister(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{
			"accepted":   true,
			"session_id": "sess-abc",
		})
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	resp, err := c.Register(&apiv1.RegisterRequest{HostId: "h1", Version: "v0.2.3"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp == nil || !resp.Accepted || resp.SessionId != "sess-abc" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestClientRegisterRejected(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return errEnv("host already registered")
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	resp, err := c.Register(&apiv1.RegisterRequest{HostId: "h1"})
	if err == nil {
		t.Fatal("rejected register should fail")
	}
	if resp != nil {
		t.Errorf("resp should be nil on error, got %+v", resp)
	}
}

func TestClientHeartbeat(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{
			"ok":                 true,
			"threat_coefficient": 0.42,
		})
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	resp, err := c.Heartbeat(&apiv1.HeartbeatRequest{HostId: "h1", SessionId: "s1"})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if resp == nil || !resp.Ok || resp.ThreatCoefficient != 0.42 {
		t.Errorf("resp = %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// TLS client construction (config only, no wire traffic)
// ---------------------------------------------------------------------------

func TestClientTLSConfigNoPanic(t *testing.T) {
	// Constructing a client with a TLS config must be safe even before any
	// connection attempt (a failed dial should report a TLS-flavored error).
	c := NewClient("127.0.0.1:1", &tls.Config{InsecureSkipVerify: true})
	defer c.Close()
	if c.addr != "127.0.0.1:1" {
		t.Errorf("addr = %q", c.addr)
	}
	err := c.Connect()
	if err == nil {
		t.Fatal("connect to closed port must fail")
	}
}

// ---------------------------------------------------------------------------
// Wire-format details
// ---------------------------------------------------------------------------

func TestClientEnvelopeShape(t *testing.T) {
	var gotEnv map[string]interface{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		gotEnv = env
		return okEnv(map[string]interface{}{})
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	if err := c.Call("svc", "mth", &apiv1.RegisterRequest{HostId: "h1"}, &resp); err != nil {
		t.Fatalf("Call: %v", err)
	}

	if gotEnv["service"] != "svc" || gotEnv["method"] != "mth" {
		t.Errorf("envelope service/method wrong: %v", gotEnv)
	}
	payload, ok := gotEnv["payload"].(map[string]interface{})
	if !ok {
		t.Fatalf("payload not an object: %T", gotEnv["payload"])
	}
	if payload["host_id"] != "h1" {
		t.Errorf("payload = %v, want host_id=h1", payload)
	}
}

// TestClientSequenceNumber verifies each call increments the internal sequence
// counter (observable indirectly through repeated successful calls).
func TestClientSequenceNumber(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{})
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	for i := 0; i < 3; i++ {
		var resp apiv1.RegisterResponse
		if err := c.Call("svc", "m", &apiv1.RegisterRequest{}, &resp); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if c.seq != 3 {
		t.Errorf("seq = %d, want 3", c.seq)
	}
}

// TestClientDeadlineConfig verifies the default deadline is applied.
func TestClientDeadlineConfig(t *testing.T) {
	c := NewClient("127.0.0.1:1", nil)
	if c.deadline != 30*time.Second {
		t.Errorf("deadline = %v, want 30s", c.deadline)
	}
}

// TestClientConcurrentCalls verifies the mutex serializes concurrent calls.
func TestClientConcurrentCalls(t *testing.T) {
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		return okEnv(map[string]interface{}{})
	})
	c := NewClient(k.addr(), nil)
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var resp apiv1.RegisterResponse
			if err := c.Call("svc", "m", &apiv1.RegisterRequest{}, &resp); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read deadline behavior: kernel that never answers
// ---------------------------------------------------------------------------

func TestClientCallTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn) // read forever, never reply
	}()

	c := NewClient(ln.Addr().String(), nil)
	defer c.Close()
	c.deadline = 200 * time.Millisecond
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var resp apiv1.RegisterResponse
	start := time.Now()
	err = c.Call("svc", "m", &apiv1.RegisterRequest{}, &resp)
	if err == nil {
		t.Fatal("unanswered call should time out")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("call took %v, deadline not honored", elapsed)
	}
	// Reset deadline for the Close() at defer.
	c.deadline = 30 * time.Second
}

// ensure fmt import is used when the file evolves (helper printing).
var _ = fmt.Sprintf
