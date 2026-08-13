//go:build linux

package agent

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
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
}

// PrivilegedAgent is the root-privileged worker process. It is started
// exclusively by the kernel side via systemd socket activation and never
// self-starts nor is started by the main agent or another privileged process.
type PrivilegedAgent struct {
	cfg PrivilegedConfig
	ln  net.Listener
	log *slog.Logger
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
// agent UID may connect.
func (p *PrivilegedAgent) verifyPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix socket connection")
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		return fmt.Errorf("peer credential unavailable: %w", err)
	}
	if p.cfg.AllowedPeerUID > 0 && uid != p.cfg.AllowedPeerUID {
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

func (p *PrivilegedAgent) executeIsolation() *PrivilegedResponse {
	out1, err1 := common.RunCmdTimeout(30*time.Second, "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	out2, err2 := common.RunCmdTimeout(30*time.Second, "iptables", "-P", "INPUT", "DROP")
	if err1 != nil || err2 != nil {
		p.log.Error("privileged agent: isolate_host failed", "out1", out1, "err1", err1, "out2", out2, "err2", err2)
		return &PrivilegedResponse{OK: false, Error: "isolate_host firewall rule failed"}
	}
	p.log.Warn("privileged agent: host isolated (INPUT DROP)")
	return &PrivilegedResponse{OK: true, Output: "host isolated"}
}

func (p *PrivilegedAgent) executeDeisolation() *PrivilegedResponse {
	common.RunCmdTimeout(30*time.Second, "iptables", "-P", "INPUT", "ACCEPT")
	common.RunCmdTimeout(30*time.Second, "iptables", "-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	p.log.Info("privileged agent: host de-isolated (INPUT ACCEPT)")
	return &PrivilegedResponse{OK: true, Output: "host de-isolated"}
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

// LookupUID resolves a unix account name to its numeric UID. It returns 0
// (root) when the lookup fails so the caller can decide how to handle it.
func LookupUID(name string) int {
	if name == "" {
		return 0
	}
	u, err := user.Lookup(name)
	if err != nil {
		logger.WithComponent("agent-priv").Warn("peer user lookup failed", "user", name, "error", err.Error())
		return 0
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0
	}
	return uid
}
