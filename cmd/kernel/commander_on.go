//go:build commander

package main

import (
	"github.com/chins-xing/asscor/internal/commander"
	"github.com/chins-xing/asscor/internal/kernel"
)

// newCommander returns the commander module, or nil when the commander build
// tag is disabled (kernel zero-bloat).
func newCommander() kernel.CommanderInterface {
	return commander.New()
}
