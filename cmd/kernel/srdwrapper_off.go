//go:build !srdwrapper

package main

import "github.com/asscor/asscor/internal/kernel"

func newSRDPlugin() kernel.Plugin { return nil }
