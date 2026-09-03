//go:build !srdwrapper || !engine

package main

import "github.com/asscor/asscor/internal/kernel"

// newSRDPlugin returns nil when the srdwrapper module (which requires the
// engine tag) is not fully enabled.
func newSRDPlugin() kernel.Plugin { return nil }
