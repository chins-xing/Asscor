//go:build collector

package main

import (
	"github.com/asscor/asscor/internal/collector"
	"github.com/asscor/asscor/internal/kernel"
)

// newLogCollector returns the log collector module, or nil when the collector
// build tag is disabled (kernel zero-bloat).
func newLogCollector() kernel.LogCollectorInterface {
	return collector.New()
}
