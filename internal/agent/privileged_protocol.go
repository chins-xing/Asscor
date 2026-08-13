package agent

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/asscor/asscor/internal/model"
)

// Privileged request types. The main (non-root) agent sends one of these to
// the privileged agent process over a Unix domain socket.
const (
	privReqRunChecks  = "run_checks"
	privReqRunCommand = "run_command"
	privReqPing       = "ping"
)

// PrivilegedRequest is the JSON envelope sent from the main agent to the
// privileged agent process.
type PrivilegedRequest struct {
	Type    string            `json:"type"`
	Command string            `json:"command,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
}

// PrivilegedResponse is the JSON envelope returned by the privileged agent
// process.
type PrivilegedResponse struct {
	OK      bool                  `json:"ok"`
	Error   string                `json:"error,omitempty"`
	Checks  []model.CheckResult   `json:"checks,omitempty"`
	Output  string                `json:"output,omitempty"`
}

// readPrivilegedRequest decodes one newline-delimited JSON request.
func readPrivilegedRequest(r io.Reader) (*PrivilegedRequest, error) {
	dec := json.NewDecoder(r)
	var req PrivilegedRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode privileged request: %w", err)
	}
	return &req, nil
}

// writePrivilegedRequest encodes one newline-delimited JSON request.
func writePrivilegedRequest(w io.Writer, req *PrivilegedRequest) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("encode privileged request: %w", err)
	}
	return nil
}

// readPrivilegedResponse decodes one newline-delimited JSON response.
func readPrivilegedResponse(r io.Reader) (*PrivilegedResponse, error) {
	dec := json.NewDecoder(r)
	var resp PrivilegedResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode privileged response: %w", err)
	}
	return &resp, nil
}

// writePrivilegedResponse encodes one newline-delimited JSON response.
func writePrivilegedResponse(w io.Writer, resp *PrivilegedResponse) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		return fmt.Errorf("encode privileged response: %w", err)
	}
	return nil
}
