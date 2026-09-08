//go:build attck_ext

package main

import (
	"github.com/chins-xing/asscor/internal/kernel"
	attckext "github.com/chins-xing/asscor/optional/algorithms/packages/attck-ext-pack"
)

func initATTACK(target kernel.ATTACKInjectionTarget) {
	attckext.Register(target)
}
