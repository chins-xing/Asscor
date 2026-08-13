//go:build linux

package agent

import (
	"fmt"
	"net"
	"time"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

// PrivilegedClient is the main agent's client for the privileged agent
// process. It communicates over a Unix domain socket. Connecting to the
// socket triggers systemd socket activation, which starts the privileged
// process — the main agent itself never spawns it.
type PrivilegedClient struct {
	socketPath string
	timeout    time.Duration
}

// NewPrivilegedClient creates a client for the privileged agent socket.
func NewPrivilegedClient(socketPath string) *PrivilegedClient {
	return &PrivilegedClient{
		socketPath: socketPath,
		timeout:    60 * time.Second,
	}
}

// RunRootChecks requests the privileged process to execute all root checks.
// On failure (privileged process unavailable), it returns nil so the caller
// can fall back to reporting root checks as "skipped".
func (c *PrivilegedClient) RunRootChecks() []model.CheckResult {
	req := &PrivilegedRequest{Type: privReqRunChecks}
	resp, err := c.call(req)
	if err != nil {
		logger.WithComponent("agent").Warn("privileged agent unavailable, root checks skipped", "error", err.Error())
		return nil
	}
	if !resp.OK {
		logger.WithComponent("agent").Warn("privileged agent rejected root checks", "error", resp.Error)
		return nil
	}
	return resp.Checks
}

// RunRootCommand forwards a root command (isolate_host/deisolate_host) to the
// privileged process and returns its output.
func (c *PrivilegedClient) RunRootCommand(command string, params map[string]string) (string, error) {
	req := &PrivilegedRequest{Type: privReqRunCommand, Command: command, Params: params}
	resp, err := c.call(req)
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("privileged agent: %s", resp.Error)
	}
	return resp.Output, nil
}

func (c *PrivilegedClient) call(req *PrivilegedRequest) (*PrivilegedResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to privileged socket %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(c.timeout))
	if err := writePrivilegedRequest(conn, req); err != nil {
		return nil, err
	}
	return readPrivilegedResponse(conn)
}
