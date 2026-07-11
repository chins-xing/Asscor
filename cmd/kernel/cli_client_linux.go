//go:build linux

package main

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tcgets = 0x5401
	tcsets = 0x5402
	icanon = 0x00000002
	echo   = 0x00000008
)

type termios struct {
	Iflag, Oflag, Cflag, Lflag uint32
	Line                        uint8
	Cc                          [32]uint8
	_                           [3]byte
}

func makeRaw(fd uintptr) (*termios, error) {
	var oldState, newState termios
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, tcgets, uintptr(unsafe.Pointer(&oldState))); err != 0 {
		return nil, err
	}
	newState = oldState
	newState.Lflag &^= icanon | echo
	newState.Cc[6] = 1
	newState.Cc[5] = 0
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, tcsets, uintptr(unsafe.Pointer(&newState))); err != 0 {
		return nil, err
	}
	return &oldState, nil
}

func restoreTerm(fd uintptr, state *termios) {
	syscall.Syscall(syscall.SYS_IOCTL, fd, tcsets, uintptr(unsafe.Pointer(state)))
}

func runCLIClient(sockPath string) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect to CLI socket %s: %v\n", sockPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		conn.Close()
		os.Exit(0)
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			os.Stdout.Write(buf[:n])
		}
	}()

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = os.Stdin
	}
	if tty != os.Stdin {
		defer tty.Close()
	}

	oldState, err := makeRaw(tty.Fd())
	if err == nil {
		defer restoreTerm(tty.Fd(), oldState)
	}

	encoder := gob.NewEncoder(conn)
	var line []byte
	buf := make([]byte, 1)

	for {
		os.Stdout.WriteString("\r\nasscor> " + string(line))
		n, err := tty.Read(buf)
		if err != nil || n == 0 {
			return
		}
		ch := buf[0]

		switch {
		case ch == 0x0d || ch == 0x0a:
			os.Stdout.WriteString("\r\n")
			cmd := strings.TrimSpace(string(line))
			line = line[:0]
			if cmd == "exit" || cmd == "quit" {
				encoder.Encode("exit")
				fmt.Fprintln(os.Stderr, "disconnected. Kernel continues running.")
				return
			}
			if cmd == "" {
				continue
			}
			if err := encoder.Encode(cmd); err != nil {
				fmt.Fprintf(os.Stderr, "connection lost: %v\n", err)
				return
			}
		case ch == 0x7f || ch == 0x08:
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case ch == 0x09:
			_ = ch // tab — beep
		case ch >= 0x20 && ch < 0x7f:
			line = append(line, ch)
		}
	}
}
