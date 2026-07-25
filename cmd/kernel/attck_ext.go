//go:build attck_ext

package main

import "github.com/asscor/asscor/internal/kernel"

func registerATTACK(assessor *kernel.AssessorModule) {
	attck := kernel.NewATTACKModule()
	assessor.SetATTACKProvider(attck.AsEngineProvider())
}

func init() {
	registeredATTACKInit = registerATTACK
}
