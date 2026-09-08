//go:build linux

package agent

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/common"
	"github.com/chins-xing/asscor/internal/logger"
	"github.com/chins-xing/asscor/internal/model"
	"golang.org/x/sys/unix"
)

// PrivilegedConfig configures the privileged agent process. It runs under a
// dedicated privileged account and handles ONLY root-required business
// (root checks + root commands) on behalf of the non-root main agent.
type PrivilegedConfig struct {
	// AllowedPeerUID is the UID of the main agent account. The privileged
	// process refuses connections from any other UID (peer credential check).
	AllowedPeerUID int
	// SocketPath is the Unix socket path (informational; the actual listener
	// fd comes from systemd socket activation).
	SocketPath string
	// IsolationKeepPorts lists TCP ports that stay reachable while a host is
	// isolated (audit H-5). Isolating INPUT by default DROP would otherwise
	// cut the operator's own management/SSH channel along with the attacker;
	// these ports receive an explicit ACCEPT rule before the DROP policy is
	// installed. Empty means no extra ports are kept (only already-established
	// connections survive).
	IsolationKeepPorts []int
}

// PrivilegedAgent is the root-privileged worker process. It is started
// exclusively by the kernel side via systemd socket activation and never
// self-starts nor is started by the main agent or another privileged process.
type PrivilegedAgent struct {
	cfg PrivilegedConfig
	ln  net.Listener
	log *slog.Logger

	// isoMu serializes isolation state transitions (concurrent connections
	// may dispatch isolate/deisolate at once) and guards lastIsolation.
	isoMu         sync.Mutex
	lastIsolation time.Time
}

// NewPrivilegedAgent creates a privileged agent bound to the systemd-activated
// listening socket. It returns an error if no activated socket is present,
// which enforces "cannot self-start".
func NewPrivilegedAgent(cfg PrivilegedConfig) (*PrivilegedAgent, error) {
	ln, err := systemdActivatedListener()
	if err != nil {
		return nil, err
	}
	return &PrivilegedAgent{
		cfg: cfg,
		ln:  ln,
		log: logger.WithComponent("agent-priv"),
	}, nil
}

// Run accepts and serves privileged requests until the listener is closed.
func (p *PrivilegedAgent) Run() error {
	if p.ln == nil {
		return fmt.Errorf("privileged agent: no activated listener (must be started by systemd socket activation)")
	}
	p.log.Info("privileged agent started via socket activation", "addr", p.ln.Addr().String())

	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return fmt.Errorf("privileged agent accept: %w", err)
		}
		go p.serveConn(conn)
	}
}

func (p *PrivilegedAgent) serveConn(conn net.Conn) {
	defer conn.Close()

	if err := p.verifyPeer(conn); err != nil {
		p.log.Warn("privileged agent: rejected peer", "error", err.Error(), "remote", conn.RemoteAddr().String())
		writePrivilegedResponse(conn, &PrivilegedResponse{OK: false, Error: "unauthorized peer"})
		return
	}

	req, err := readPrivilegedRequest(conn)
	if err != nil {
		p.log.Warn("privileged agent: bad request", "error", err.Error())
		writePrivilegedResponse(conn, &PrivilegedResponse{OK: false, Error: "bad request"})
		return
	}

	resp := p.dispatch(req)
	if err := writePrivilegedResponse(conn, resp); err != nil {
		p.log.Warn("privileged agent: write response", "error", err.Error())
	}
}

// verifyPeer enforces the peer credential check: only the configured main
// agent UID may connect. A missing or unset AllowedPeerUID (<= 0) is refused
// — fail-closed: a peer check that cannot name its expected UID must not
// silently admit everyone (audit C-2).
func (p *PrivilegedAgent) verifyPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix socket connection")
	}
	if p.cfg.AllowedPeerUID <= 0 {
		return fmt.Errorf("peer check disabled (AllowedPeerUID=%d) — refusing connection", p.cfg.AllowedPeerUID)
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		return fmt.Errorf("peer credential unavailable: %w", err)
	}
	if uid != p.cfg.AllowedPeerUID {
		return fmt.Errorf("peer uid %d not allowed (want %d)", uid, p.cfg.AllowedPeerUID)
	}
	return nil
}

func (p *PrivilegedAgent) dispatch(req *PrivilegedRequest) *PrivilegedResponse {
	switch req.Type {
	case privReqPing:
		return &PrivilegedResponse{OK: true}
	case privReqRunChecks:
		return p.runRootChecks()
	case privReqRunCommand:
		return p.runRootCommand(req)
	default:
		return &PrivilegedResponse{OK: false, Error: "unknown request type: " + req.Type}
	}
}

// runRootChecks executes all root-privilege checks and returns their results.
func (p *PrivilegedAgent) runRootChecks() *PrivilegedResponse {
	items := checks.GetRoot()
	results := make([]model.CheckResult, 0, len(items))
	for _, item := range items {
		results = append(results, item.Run())
	}
	p.log.Info("privileged agent: ran root checks", "count", len(results))
	return &PrivilegedResponse{OK: true, Checks: results}
}

// runRootCommand executes a root command. It enforces a strict whitelist of
// logical actions (isolate_host/deisolate_host) that map to real iptables
// rules; no arbitrary shell command is accepted.
func (p *PrivilegedAgent) runRootCommand(req *PrivilegedRequest) *PrivilegedResponse {
	switch req.Command {
	case "isolate_host":
		return p.executeIsolation()
	case "deisolate_host":
		return p.executeDeisolation()
	default:
		return &PrivilegedResponse{OK: false, Error: "command not in privileged whitelist: " + req.Command}
	}
}

// isolationCooldown bounds how often isolate_host may be applied to the same
// host. After a successful isolation the privileged agent ignores further
// isolate requests inside the window, so a repeated or looped trigger cannot
// churn the firewall rules (audit H-5). De-isolation is never rate-limited.
const isolationCooldown = 30 * time.Second

// isolationOnCooldown reports whether a new isolate request must be refused
// because one was applied recently (audit H-5 anti-churn guard).
func (p *PrivilegedAgent) isolationOnCooldown() bool {
	return !p.lastIsolation.IsZero() && time.Since(p.lastIsolation) < isolationCooldown
}

func (p *PrivilegedAgent) executeIsolation() *PrivilegedResponse {
	p.isoMu.Lock()
	defer p.isoMu.Unlock()

	if p.isolationOnCooldown() {
		remain := isolationCooldown - time.Since(p.lastIsolation)
		p.log.Warn("privileged agent: isolate_host in cooldown, ignoring", "retry_in", remain.String())
		return &PrivilegedResponse{OK: false, Error: "isolate_host in cooldown, try again later"}
	}

	// Keep the management channel reachable BEFORE dropping INPUT: without
	// an explicit exception the operator's own SSH/management session would
	// be severed together with the attacker's (audit H-5). Build the check
	// (-C) list from the same single source isolationExceptionRules() so the
	// installed rules and the later de-isolation removal can never drift.
	cmds := [][]string{}
	for _, rule := range p.isolationExceptionRules() {
		check := append([]string{"-C"}, rule...)
		cmds = append(cmds, check)
	}

	// Install only missing rules (idempotent): iptables -C fails when the rule
	// is absent, then -A adds it. Re-isolation after a de-isolation therefore
	// never duplicates rules.
	for _, c := range cmds {
		exists, _ := iptablesRuleExists(c)
		if !exists {
			args := append([]string{"-A"}, c[1:]...)
			if _, err := common.RunCmdTimeout(30*time.Second, "iptables", args...); err != nil {
				p.log.Error("privileged agent: isolate_host add rule failed", "rule", c, "error", err)
				return &PrivilegedResponse{OK: false, Error: "isolate_host firewall rule failed"}
			}
		}
	}

	if _, err := common.RunCmdTimeout(30*time.Second, "iptables", "-P", "INPUT", "DROP"); err != nil {
		p.log.Error("privileged agent: isolate_host set policy failed", "error", err)
		return &PrivilegedResponse{OK: false, Error: "isolate_host firewall policy failed"}
	}

	p.lastIsolation = time.Now()
	p.log.Warn("privileged agent: host isolated (INPUT DROP, management ports kept)")
	return &PrivilegedResponse{OK: true, Output: "host isolated"}
}

func (p *PrivilegedAgent) executeDeisolation() *PrivilegedResponse {
	p.isoMu.Lock()
	defer p.isoMu.Unlock()

	// Remove the exception rules first (ignore "no such rule" — the host may
	// have been de-isolated already), then restore the ACCEPT policy.
	for _, rule := range p.isolationExceptionRules() {
		args := append([]string{"-D"}, rule...)
		common.RunCmdTimeout(30*time.Second, "iptables", args...)
	}
	common.RunCmdTimeout(30*time.Second, "iptables", "-P", "INPUT", "ACCEPT")

	p.lastIsolation = time.Time{}
	p.log.Info("privileged agent: host de-isolated (INPUT ACCEPT)")
	return &PrivilegedResponse{OK: true, Output: "host de-isolated"}
}

// isolationExceptionRules returns the full INPUT rules (without -A/-C/-D) that
// isolation installs and de-isolation removes.
func (p *PrivilegedAgent) isolationExceptionRules() [][]string {
	rules := [][]string{
		{"INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"},
	}
	for _, port := range p.cfg.IsolationKeepPorts {
		if port > 0 && port != 22 {
			rules = append(rules, []string{"INPUT", "-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
		}
	}
	return rules
}

// iptablesRuleExists reports whether the rule (checkArgs already prefixed
// with -C) is present. err == nil means present; any error (iptables exits 1
// for a missing rule, which common.RunCmdTimeout surfaces as a CommandError)
// means "not present". Isolation treats a missing rule as "needs adding" and
// de-isolation treats it as "already gone", so both directions are idempotent.
func iptablesRuleExists(checkArgs []string) (bool, error) {
	_, err := common.RunCmdTimeout(30*time.Second, "iptables", checkArgs...)
	if err == nil {
		return true, nil
	}
	return false, nil
}

// systemdActivatedListener returns the listening socket passed by systemd
// socket activation (LISTEN_FDS). If no socket is activated, it returns an
// error — the privileged process must never self-start.
func systemdActivatedListener() (net.Listener, error) {
	pidStr := os.Getenv("LISTEN_PID")
	fdsStr := os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, fmt.Errorf("not started by systemd socket activation (LISTEN_PID/LISTEN_FDS unset)")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid LISTEN_PID: %w", err)
	}
	if pid != os.Getpid() {
		return nil, fmt.Errorf("LISTEN_PID %d does not match process pid %d", pid, os.Getpid())
	}

	nfd, err := strconv.Atoi(fdsStr)
	if err != nil || nfd < 1 {
		return nil, fmt.Errorf("invalid LISTEN_FDS: %q", fdsStr)
	}

	// The first socket activation fd is always 3 (0=stdin, 1=stdout, 2=stderr).
	f := os.NewFile(3, "systemd-listener")
	if f == nil {
		return nil, fmt.Errorf("failed to wrap systemd listener fd 3")
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("systemd listener: %w", err)
	}
	return ln, nil
}

// peerUID returns the UID of the process on the other end of a Unix socket
// connection via SO_PEERCRED.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			sockErr = e
			return
		}
		uid = int(cred.Uid)
	})
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return uid, nil
}

// LookupUID resolves a unix account name to its numeric UID. It returns an
// error when the account cannot be resolved — the caller must then refuse to
// start rather than fall back to UID 0 (root), which would silently disable
// the peer credential check (audit C-2).
func LookupUID(name string) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("empty user name")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("lookup user %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("parse uid of %q: %w", name, err)
	}
	return uid, nil
}
