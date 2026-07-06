//go:build !linux

package main

import (
	"fmt"
	"os"
)

func runCLIClient(sockPath string) {
	fmt.Fprintf(os.Stderr, "--cli is only supported on Linux (uses Unix domain socket)\n")
	os.Exit(1)
}
