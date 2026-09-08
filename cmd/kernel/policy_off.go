//go:build !policy

package main

import "github.com/chins-xing/asscor/internal/kernel"

// newPolicy returns nil when the policy module is not compiled in.
func newPolicy() kernel.PolicyInterface {
	return nil
}
