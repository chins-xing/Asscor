//go:build attck_ext

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	attckext "github.com/asscor/asscor/optional/algorithms/packages/attck-ext-pack"
)

func initATTACK(target kernel.ATTACKInjectionTarget) {
	attckext.Register(target)
}
