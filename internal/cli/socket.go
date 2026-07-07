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

	if err := os.Chmod(sockPath, 0660); err != nil {
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

	for {
		writeString(s.conn, "\r\nasscor> ")

		var line string
		dec := gob.NewDecoder(s.conn)
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
		if result.Data != nil {
			enc := gob.NewEncoder(s.conn)
			enc.Encode(result.Data)
		}
	}
}

func writeString(w io.Writer, s string) {
	w.Write([]byte(s))
}
