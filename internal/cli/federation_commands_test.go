package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/federation"
)

type fakeFederationProvider struct {
	status federation.Status
}

func (f *fakeFederationProvider) FederationStatus() federation.Status { return f.status }

func withFederationProvider(t *testing.T, p FederationProvider) {
	t.Helper()
	SetFederationProvider(p)
	t.Cleanup(func() { SetFederationProvider(nil) })
}

func TestFederationCommandWithoutPluginReportsVisibleError(t *testing.T) {
	withFederationProvider(t, nil)

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode == ExitOK {
		t.Fatalf("exit code = 0, want a failure when the plugin is not loaded")
	}
	// Socket sessions render Output only — the error must be visible there
	// (not just in Result.Err).
	if !strings.Contains(res.Output, "federation 插件未加载") {
		t.Errorf("Output = %q, want the visible not-loaded error", res.Output)
	}
	if res.Err == nil {
		t.Errorf("Err = nil, want the error as well")
	}
}

func TestFederationCommandRequiresStatusAction(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{Role: federation.RoleOff}})

	res := federationCmdHandler(&CommandContext{Args: []string{"bogus"}})
	if res.ExitCode != ExitUsage {
		t.Errorf("exit code = %v, want ExitUsage", res.ExitCode)
	}
	if !strings.Contains(res.Output, "unsupported action") {
		t.Errorf("Output = %q, want an unsupported-action error", res.Output)
	}
}

func TestFederationCommandMasterText(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:       federation.RoleMaster,
		ListenAddr: ":5099",
		Running:    true,
		Nodes: []federation.NodeReport{
			{
				NodeID:     "nk1",
				ConfigHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Hosts:      10,
				Zones: map[string]federation.ZoneSummary{
					"dma": {Hosts: 4, Scored: 4, AvgSSAM: 90},
					"web": {Hosts: 6, Scored: 6, AvgSSAM: 80},
				},
				AvgSSAM:    84,
				ReceivedAt: now,
			},
			{
				NodeID:     "nk2",
				ConfigHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Hosts:      12,
				AvgSSAM:    75.5,
				ReceivedAt: now.Add(-time.Minute),
			},
		},
	}})

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK (output: %s)", res.ExitCode, res.Output)
	}
	for _, want := range []string{"Federation (master)", ":5099", "nk1", "nk2", "84.0", "75.5", "10", "12", "CONFIG_HASH", "dma"} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("Output missing %q:\n%s", want, res.Output)
		}
	}
	// The table truncates hashes to keep columns aligned.
	if !strings.Contains(res.Output, "aaaaaaaaaaaaaaaa") {
		t.Errorf("Output should include the short config hash:\n%s", res.Output)
	}
	if strings.Contains(res.Output, strings.Repeat("a", 64)) {
		t.Errorf("text view should not print the full 64-char hash:\n%s", res.Output)
	}
}

func TestFederationCommandNodeText(t *testing.T) {
	last := time.Date(2026, 10, 28, 12, 30, 0, 0, time.UTC)
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:               federation.RoleNode,
		NodeID:             "nk1",
		MasterURL:          "http://192.168.30.50:5099",
		ReportIntervalSec:  30,
		ConfigHash:         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Params:             map[string]string{"prism.debt_alpha": "1.2", "srd.aggregation": "rss"},
		Hosts:              10,
		AvgSSAM:            84.5,
		Zones:              map[string]federation.ZoneSummary{"dma": {Hosts: 10, Scored: 10, AvgSSAM: 84.5}},
		LastReportAt:       &last,
		LastReportAttempts: 1,
		Running:            true,
	}})

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK (output: %s)", res.ExitCode, res.Output)
	}
	for _, want := range []string{
		"Federation (node)", "nk1", "http://192.168.30.50:5099", "30s",
		"prism.debt_alpha=1.2", "84.5", "dma: 10 hosts/10 scored", "attempts: 1",
	} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("Output missing %q:\n%s", want, res.Output)
		}
	}
}

func TestFederationCommandOffAndConfigError(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:        federation.RoleOff,
		ConfigError: `invalid [federation] role "chief": must be master|node|off`,
	}})

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK", res.ExitCode)
	}
	if !strings.Contains(res.Output, "Config error") || !strings.Contains(res.Output, "chief") {
		t.Errorf("Output should surface the config error:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "未启用") {
		t.Errorf("Output should say federation is not enabled:\n%s", res.Output)
	}
}

// TestFederationCommandOffIsNotAnError pins the plain role=off UX: `federation
// status` is a successful informational view, not an error (socket sessions
// would render "error: ..." if the handler treated off as a failure).
func TestFederationCommandOffIsNotAnError(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:    federation.RoleOff,
		Running: true,
		NodeID:  "",
		Hosts:   0,
		AvgSSAM: 0,
	}})

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK for role=off (output: %s)", res.ExitCode, res.Output)
	}
	if res.Err != nil {
		t.Errorf("Err = %v, want nil for role=off", res.Err)
	}
	if strings.Contains(res.Output, "error:") {
		t.Errorf("role=off must not render an error:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "未启用") {
		t.Errorf("Output should say federation 未启用:\n%s", res.Output)
	}
}

// TestFederationCommandMasterListenError pins the degraded-master view: a
// listen failure must be visible in Output (socket sessions only render
// Output) while the command still succeeds.
func TestFederationCommandMasterListenError(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:        federation.RoleMaster,
		ListenAddr:  "127.0.0.1:5099",
		ListenError: "federation: listen 127.0.0.1:5099: bind: address already in use",
		Running:     true,
	}})

	res := federationCmdHandler(&CommandContext{})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK (degraded is not a command failure)", res.ExitCode)
	}
	if !strings.Contains(res.Output, "Listen error") || !strings.Contains(res.Output, "address already in use") {
		t.Errorf("Output should surface the listen failure:\n%s", res.Output)
	}
}

func TestFederationCommandJSON(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:    federation.RoleMaster,
		Nodes:   []federation.NodeReport{{NodeID: "nk1", Hosts: 10, AvgSSAM: 84.5, ConfigHash: "abc"}},
		Running: true,
	}})

	res := federationCmdHandler(&CommandContext{JSON: true})
	if res.ExitCode != ExitOK {
		t.Fatalf("exit code = %v, want OK (output: %s)", res.ExitCode, res.Output)
	}
	var decoded struct {
		Role  string `json:"role"`
		Nodes []struct {
			NodeID  string  `json:"node_id"`
			Hosts   int     `json:"hosts"`
			AvgSSAM float64 `json:"avg_ssam"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(res.Output), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, res.Output)
	}
	if decoded.Role != "master" || len(decoded.Nodes) != 1 || decoded.Nodes[0].NodeID != "nk1" {
		t.Errorf("decoded = %+v", decoded)
	}
	if decoded.Nodes[0].Hosts != 10 || decoded.Nodes[0].AvgSSAM != 84.5 {
		t.Errorf("decoded node = %+v", decoded.Nodes[0])
	}
}

func TestFederationCommandRegisteredInEngine(t *testing.T) {
	withFederationProvider(t, &fakeFederationProvider{status: federation.Status{
		Role:      federation.RoleNode,
		NodeID:    "nk1",
		MasterURL: "http://m:5099",
		Hosts:     1,
	}})

	engine := newTestEngine(newMockKernel())
	res := engine.Execute("federation status")
	if res.ExitCode != ExitOK {
		t.Fatalf("engine Execute exit = %v, output = %s", res.ExitCode, res.Output)
	}
	if !strings.Contains(res.Output, "Federation (node)") {
		t.Errorf("engine output = %s, want the federation status view", res.Output)
	}

	jsonRes := engine.Execute("federation status --json")
	if jsonRes.ExitCode != ExitOK {
		t.Fatalf("JSON exit = %v", jsonRes.ExitCode)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonRes.Output), &decoded); err != nil {
		t.Fatalf("engine JSON output invalid: %v\n%s", err, jsonRes.Output)
	}
	if decoded["role"] != "node" {
		t.Errorf("role = %v, want node", decoded["role"])
	}
}
