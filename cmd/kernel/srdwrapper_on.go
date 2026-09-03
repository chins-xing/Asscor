//go:build srdwrapper && engine

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/srdwrapper"
)

// newSRDPlugin returns the SRD wrapper plugin. The srdwrapper implementation
// requires the engine build tag (it adapts internal/engine/srd), so this
// wiring only compiles when both tags are present (coupling audit 2026-09-03,
// finding F2 — single `-tags srdwrapper` is no longer a half-built kernel).
func newSRDPlugin() kernel.Plugin {
	return srdwrapper.New()
}
