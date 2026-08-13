//go:build !policy

package main

import "github.com/asscor/asscor/internal/kernel"

// newPolicy returns nil when the policy module is not compiled in.
func newPolicy() kernel.PolicyInterface {
	return nil
}
