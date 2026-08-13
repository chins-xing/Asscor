package agent

import (
	"bytes"
	"testing"

	"github.com/asscor/asscor/internal/model"
)

func TestPrivilegedProtocolRoundTrip(t *testing.T) {
	tests := []PrivilegedRequest{
		{Type: privReqPing},
		{Type: privReqRunChecks},
		{Type: privReqRunCommand, Command: "isolate_host", Params: map[string]string{"host_id": "web-01"}},
	}

	for _, req := range tests {
		var buf bytes.Buffer
		if err := writePrivilegedRequest(&buf, &req); err != nil {
			t.Fatalf("write request: %v", err)
		}
		got, err := readPrivilegedRequest(&buf)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		if got.Type != req.Type {
			t.Errorf("type = %q, want %q", got.Type, req.Type)
		}
		if got.Command != req.Command {
			t.Errorf("command = %q, want %q", got.Command, req.Command)
		}
		if len(got.Params) != len(req.Params) {
			t.Errorf("params len = %d, want %d", len(got.Params), len(req.Params))
		}
	}
}

func TestPrivilegedResponseRoundTrip(t *testing.T) {
	resp := &PrivilegedResponse{
		OK:     true,
		Output: "host isolated",
		Checks: []model.CheckResult{
			{CheckID: "AS-012", Domain: model.DomainAttackSurface, Name: "幽灵账户检测", Passed: true, Delta: 0},
		},
	}

	var buf bytes.Buffer
	if err := writePrivilegedResponse(&buf, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	got, err := readPrivilegedResponse(&buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !got.OK {
		t.Error("expected OK=true")
	}
	if got.Output != "host isolated" {
		t.Errorf("output = %q", got.Output)
	}
	if len(got.Checks) != 1 || got.Checks[0].CheckID != "AS-012" {
		t.Errorf("checks = %+v", got.Checks)
	}
}
