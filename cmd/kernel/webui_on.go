//go:build webui

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/webui"
)

// newWebUI returns the web dashboard module, or nil when the webui build tag
// is disabled (kernel zero-bloat).
func newWebUI(port int) kernel.Plugin {
	if port <= 0 {
		return nil
	}
	return webui.New(port)
}
