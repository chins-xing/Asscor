//go:build !spc

package main

import "github.com/asscor/asscor/internal/kernel"

func newSPC() kernel.SPCInterface { return nil }
