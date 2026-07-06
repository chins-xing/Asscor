//go:build linux

package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

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
		fmt.Fprintln(os.Stderr, "\r\ndisconnecting...")
		conn.Close()
		os.Exit(0)
	}()

	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			os.Stdout.Write(buf[:n])
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	encoder := gob.NewEncoder(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if line == "exit" || line == "quit" {
			encoder.Encode("exit")
			fmt.Fprintln(os.Stderr, "disconnected. Kernel continues running.")
			return
		}

		if err := encoder.Encode(line); err != nil {
			fmt.Fprintf(os.Stderr, "connection lost: %v\n", err)
			return
		}
	}
}
