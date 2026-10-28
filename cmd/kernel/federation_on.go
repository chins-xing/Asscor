//go:build federation

package main

import (
	"github.com/chins-xing/asscor/internal/federation"
	"github.com/chins-xing/asscor/internal/kernel"
)

// newFederationPlugin returns the T4 federation demo plugin (master or node
// per [federation] role). The plugin never blocks bootstrap: the master binds
// its listener synchronously but serves in the background, the node only
// starts a reporting goroutine.
func newFederationPlugin() kernel.Plugin {
	return federation.New()
}
