//go:build !federation

package main

import "github.com/chins-xing/asscor/internal/kernel"

// newFederationPlugin returns nil when the federation module is not compiled
// in (-tags federation). The CLI command then reports a visible error instead
// of panicking.
func newFederationPlugin() kernel.Plugin { return nil }
