//go:build srdwrapper

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/srdwrapper"
)

// newSRDPlugin returns the SRD wrapper plugin, or nil when the srdwrapper build
// tag is disabled (kernel zero-bloat).
func newSRDPlugin() kernel.Plugin {
	return srdwrapper.New()
}
