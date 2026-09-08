//go:build !collector

package main

import "github.com/chins-xing/asscor/internal/kernel"

func newLogCollector() kernel.LogCollectorInterface { return nil }
