//go:build !srdwrapper

package main

import "github.com/chins-xing/asscor/internal/kernel"

func newSRDPlugin() kernel.Plugin { return nil }
