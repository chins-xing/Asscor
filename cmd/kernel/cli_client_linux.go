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
	"time"
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
	Line                       uint8
	Cc                         [32]uint8
	_                          [3]byte
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

// readSecretLine reads a line from a raw-mode TTY without echoing it back
// (deferred minor #9). makeRaw already cleared the terminal's ECHO bit, so
// nothing is echoed automatically; this function additionally never writes
// the typed characters to stdout (unlike the main prompt loop, which echoes
// printable input). Backspace is honored for typing corrections.
func readSecretLine(tty *os.File) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := tty.Read(buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		switch buf[0] {
		case 0x0d, 0x0a:
			return strings.TrimSpace(string(line)), nil
		case 0x7f, 0x08:
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		default:
			line = append(line, buf[0])
		}
	}
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

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
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
	// Echo input only when running on a real terminal in raw mode (which no
	// longer echoes by itself). When stdin is a pipe (scripted usage), echoing
	// would pollute the captured output.
	echoInput := tty != os.Stdin

	encoder := gob.NewEncoder(conn)
	var line []byte
	buf := make([]byte, 1)
	showPrompt := true

	for {
		if showPrompt {
			if echoInput {
				os.Stdout.WriteString("\r\nasscor> ")
			}
			showPrompt = false
		}

		n, err := tty.Read(buf)
		if err != nil || n == 0 {
			return
		}
		ch := buf[0]

		switch {
		case ch == 0x0d || ch == 0x0a:
			cmd := strings.TrimSpace(string(line))
			if echoInput {
				os.Stdout.WriteString("\r\n")
			}
			line = line[:0]
			showPrompt = true

			if cmd == "exit" || cmd == "quit" {
				encoder.Encode("exit")
				// Wait for the server to close the connection (it flushes its
				// "Goodbye" response first). Scripted usage pipes commands in
				// and reads the output back; exiting immediately used to race
				// the reader goroutine and drop the last command's result.
				select {
				case <-readerDone:
				case <-time.After(2 * time.Second):
				}
				fmt.Fprintln(os.Stderr, "disconnected. Kernel continues running.")
				return
			}
			if cmd == "" {
				continue
			}
			// Deferred minor #9: the kernel side cannot prompt for a password
			// (its stdin is the daemon's and socket sessions execute inside
			// the kernel process), so the interactive no-echo prompt lives
			// HERE, where the operator's TTY is. Raw mode already suppresses
			// echo; readSecretLine simply never writes the typed characters
			// back. Scripted (non-TTY) sessions are untouched: echoInput is
			// false there, so the command is sent as typed and the kernel
			// reports the missing --password itself.
			if echoInput {
				for _, flag := range needsSecretPrompt(cmd) {
					fmt.Fprintf(os.Stdout, "\r\n%s: ", secretPromptLabel(flag))
					pw, err := readSecretLine(tty)
					if err != nil {
						fmt.Fprintf(os.Stderr, "\r\npassword prompt failed: %v\r\n", err)
						continue
					}
					cmd = spliceSecret(cmd, flag, pw)
				}
			}
			if err := encoder.Encode(cmd); err != nil {
				fmt.Fprintf(os.Stderr, "connection lost: %v\n", err)
				return
			}
		case ch == 0x7f || ch == 0x08:
			if len(line) > 0 {
				line = line[:len(line)-1]
				os.Stdout.WriteString("\b \b")
			}
		case ch == 0x09:
			_ = ch
		case ch >= 0x20 && ch < 0x7f:
			line = append(line, ch)
			if echoInput {
				os.Stdout.Write(buf)
			}
		}
	}
}
