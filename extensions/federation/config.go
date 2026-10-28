// Package federation implements the T4 "one network, many configuration
// profiles" demo: a master kernel collects aggregate SRD/Prism summaries from
// N node kernels, each of which owns an independent configuration, model
// parameters and CA.
//
// The package is deliberately dependency-light (stdlib + kernel/topology) so
// that it builds with and without the `federation` build tag; the kernel
// wiring (cmd/kernel/federation_on.go) is the only tag-gated piece.
package federation

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Role is the [federation] role of this kernel.
//
//	off    — federation disabled (default; zero value of the config section)
//	master — collect reports from node kernels and serve /federation/nodes
//	node   — periodically POST this kernel's aggregate summary to master_url
type Role string

const (
	RoleOff    Role = "off"
	RoleMaster Role = "master"
	RoleNode   Role = "node"
)

const (
	// DefaultListenAddr is the master collection endpoint default ([federation]
	// listen_addr). The demo master kernel binds :5099 on its management net.
	DefaultListenAddr = ":5099"

	// DefaultReportIntervalSec is the node→master report cadence.
	DefaultReportIntervalSec = 30

	// DefaultRequestTimeout bounds one HTTP report attempt.
	DefaultRequestTimeout = 5 * time.Second

	// DefaultMaxAttempts is the per-cycle retry budget (first try + retries).
	DefaultMaxAttempts = 3

	// DefaultRetryBackoff is the base delay between retry attempts; each
	// further retry doubles it (capped at maxRetryBackoff).
	DefaultRetryBackoff = 500 * time.Millisecond

	maxRetryBackoff = 5 * time.Second

	// TokenHeader carries the optional demo-level shared secret
	// ([federation] token). It is intentionally a plain shared header — the
	// demo security boundary is documented as "token + optional mTLS"; it is
	// NOT a replacement for the kernel mTLS control plane.
	TokenHeader = "X-Federation-Token"

	// PluginVersion is the kernel plugin version advertised via Info().
	PluginVersion = "0.3.0"

	// ReportPath is the master POST collection endpoint.
	ReportPath = "/federation/report"

	// NodesPath is the master GET inspection endpoint.
	NodesPath = "/federation/nodes"
)

// Config is the parsed [federation] section.
type Config struct {
	Role           Role
	NodeID         string
	MasterURL      string
	ListenAddr     string
	ReportInterval time.Duration
	RequestTimeout time.Duration
	Token          string
}

// Defaults returns the effective defaults used when the section is absent or
// a key is omitted.
func Defaults() Config {
	return Config{
		Role:           RoleOff,
		ListenAddr:     DefaultListenAddr,
		ReportInterval: time.Duration(DefaultReportIntervalSec) * time.Second,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// ParseRole maps the raw [federation] role value to a Role.
//
// Accepted values (case-insensitive, surrounding blanks ignored):
//
//	"" / off / none / disabled → RoleOff
//	master                     → RoleMaster
//	node                       → RoleNode
//
// Anything else is an error — callers decide whether to fail fast or ignore
// the section (the kernel plugin logs the error and stays off so that a typo
// can never block bootstrap).
func ParseRole(raw string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off", "none", "disabled":
		return RoleOff, nil
	case "master":
		return RoleMaster, nil
	case "node":
		return RoleNode, nil
	default:
		return RoleOff, fmt.Errorf("invalid [federation] role %q: must be master|node|off", raw)
	}
}

// ParseConfig reads the [federation] section through a key getter shaped like
// the kernel config adapter (`cfg.Get("federation.role")`). A nil getter
// yields the defaults (role=off).
//
// Validation (all returned as errors, never panics):
//   - unknown role;
//   - non-positive/non-numeric report_interval_sec;
//   - role=node without master_url.
//
// An empty node_id for role=node falls back to the hostname so a node kernel
// is always identifiable on the master.
func ParseConfig(get func(string) string) (Config, error) {
	cfg := Defaults()
	if get == nil {
		return cfg, nil
	}

	role, err := ParseRole(get("federation.role"))
	if err != nil {
		return cfg, err
	}
	cfg.Role = role

	cfg.NodeID = strings.TrimSpace(get("federation.node_id"))
	cfg.MasterURL = strings.TrimSpace(get("federation.master_url"))
	if v := strings.TrimSpace(get("federation.listen_addr")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(get("federation.report_interval_sec")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("invalid [federation] report_interval_sec %q: must be a positive integer", v)
		}
		cfg.ReportInterval = time.Duration(n) * time.Second
	}
	cfg.Token = get("federation.token")

	if cfg.Role == RoleNode {
		if cfg.MasterURL == "" {
			return cfg, fmt.Errorf("[federation] role=node requires master_url")
		}
		if cfg.NodeID == "" {
			if h, herr := os.Hostname(); herr == nil {
				cfg.NodeID = h
			} else {
				cfg.NodeID = "unknown-node"
			}
		}
	}
	if cfg.Role == RoleMaster && cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	return cfg, nil
}

// ReportIntervalSec returns the interval in whole seconds (CLI/JSON display).
func (c Config) ReportIntervalSec() int {
	return int(c.ReportInterval / time.Second)
}
