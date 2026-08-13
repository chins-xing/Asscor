//go:build policy

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/policy"
)

// newPolicy returns the policy module, or nil when the policy build tag is
// disabled (kernel zero-bloat).
func newPolicy() kernel.PolicyInterface {
	return policy.New()
}
