package cli

import (
	"context"
	"encoding/gob"
	"io"
	"net"
	"os"

	"github.com/asscor/asscor/internal/logger"
)

const defaultSocketPath = "/opt/asscor/asscor-cli.sock"

func socketPath() string {
	if p := os.Getenv("ASSCOR_CLI_SOCKET"); p != "" {
		return p
	}
	return defaultSocketPath
}

// cliPeerAllowed reports whether a connecting peer UID may use the CLI socket.
// Only root (management/install operations) and the kernel's own account (the
// asscor user the kernel runs as) are allowed; any other local user is
// rejected. This mirrors the privileged-agent peer check (SO_PEERCRED).
func cliPeerAllowed(peerUID, kernelEUID uint32) bool {
	return peerUID == 0 || peerUID == kernelEUID
}

type cliSession struct {
	conn   net.Conn
	engine *Engine
	done   chan struct{}
}

func (m *CLIModule) serveCLI(ctx context.Context) {
	sockPath := socketPath()
	if m.socketPath != "" {
		sockPath = m.socketPath
	}

	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		logger.WithComponent("cli").Error("cannot listen on unix socket", "path", sockPath, "error", err)
		return
	}
	defer ln.Close()
	defer os.Remove(sockPath)

	// Restrict the CLI socket to its owner (the kernel's account): 0600 blocks
	// other local users from reaching the management commands. On Linux the
	// per-connection SO_PEERCRED check additionally allows root.
	if err := os.Chmod(sockPath, 0600); err != nil {
		logger.WithComponent("cli").Warn("cannot chmod socket", "error", err)
	}

	logger.WithComponent("cli").Info("CLI unix socket listening",
		"path", sockPath, "connect", "ASSCOR-kernel --cli "+sockPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-m.done:
				return
			default:
				logger.WithComponent("cli").Warn("accept error", "error", err)
				continue
			}
		}

		// Reject connections from users other than root or the kernel's own
		// account before any command is processed.
		if err := verifyPeerCLI(conn); err != nil {
			logger.WithComponent("cli").Warn("cli connection rejected", "error", err)
			conn.Close()
			continue
		}

		session := &cliSession{
			conn:   conn,
			engine: m.engine,
			done:   make(chan struct{}),
		}
		go session.handle()
	}
}

func (s *cliSession) handle() {
	defer s.conn.Close()
	defer close(s.done)

	writeString(s.conn, "ASSCOR CLI — type 'help' for commands, 'exit' to disconnect\r\n")

	dec := gob.NewDecoder(s.conn)

	for {
		var line string
		if err := dec.Decode(&line); err != nil {
			if err == io.EOF {
				writeString(s.conn, "\r\ndisconnected.\r\n")
				return
			}
			return
		}

		if line == "exit" || line == "quit" {
			writeString(s.conn, "\r\nGoodbye. Kernel continues running.\r\n")
			return
		}

		if line == "" {
			continue
		}

		result := s.engine.Execute(line)
		writeString(s.conn, result.Output)
	}
}

func writeString(w io.Writer, s string) {
	w.Write([]byte(s))
}
