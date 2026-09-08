//go:build !spc

package main

import "github.com/chins-xing/asscor/internal/kernel"

func newSPC() kernel.SPCInterface { return nil }
