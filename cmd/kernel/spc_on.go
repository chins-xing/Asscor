//go:build spc

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/spc"
)

// newSPC returns the SPC module, or nil when the spc build tag is disabled
// (kernel zero-bloat).
func newSPC() kernel.SPCInterface {
	return spc.New()
}
