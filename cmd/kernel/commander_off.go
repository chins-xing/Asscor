//go:build !commander

package main

import "github.com/chins-xing/asscor/internal/kernel"

// newCommander returns nil when the commander module is not compiled in.
func newCommander() kernel.CommanderInterface {
	return nil
}
