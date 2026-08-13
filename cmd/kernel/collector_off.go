//go:build !collector

package main

import "github.com/asscor/asscor/internal/kernel"

func newLogCollector() kernel.LogCollectorInterface { return nil }
