//go:build sourcemanager

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/sourcemanager"
)

// newSourceManager returns the source manager module, or nil when the
// sourcemanager build tag is disabled (kernel zero-bloat).
func newSourceManager() kernel.SourceManagerInterface {
	return sourcemanager.New()
}
