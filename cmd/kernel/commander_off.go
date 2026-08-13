//go:build !commander

package main

import "github.com/asscor/asscor/internal/kernel"

// newCommander returns nil when the commander module is not compiled in.
func newCommander() kernel.CommanderInterface {
	return nil
}
