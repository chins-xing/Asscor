//go:build !linux

package cli

import "net"

// verifyPeerCLI is a no-op on non-Linux platforms where SO_PEERCRED is
// unavailable; the socket file permission (0600) still restricts access.
func verifyPeerCLI(conn net.Conn) error {
	return nil
}
