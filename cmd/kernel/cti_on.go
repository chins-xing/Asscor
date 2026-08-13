//go:build cti

package main

import (
	"github.com/asscor/asscor/internal/cti"
	"github.com/asscor/asscor/internal/kernel"
)

// newCTI returns the CTI module, or nil when the cti build tag is disabled
// (kernel zero-bloat).
func newCTI() kernel.CTIInterface {
	return cti.New()
}
