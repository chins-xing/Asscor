//go:build !cti

package main

import "github.com/chins-xing/asscor/internal/kernel"

// newCTI returns nil when the CTI module is not compiled in.
func newCTI() kernel.CTIInterface {
	return nil
}
