//go:build linux

package cli

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// verifyPeerCLI enforces the CLI socket peer credential check on Linux: the
// connecting process must be root or the kernel's own account (see
// cliPeerAllowed in socket.go). Connections from other users are closed.
func verifyPeerCLI(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("cli socket connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("cli socket syscall conn: %w", err)
	}

	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("cli socket control: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("cli socket peer cred: %w", serr)
	}

	euid := uint32(os.Geteuid())
	if !cliPeerAllowed(cred.Uid, euid) {
		return fmt.Errorf("cli socket peer uid %d not allowed (want root or %d)", cred.Uid, euid)
	}
	return nil
}
