//go:build collector

package main

import (
	"github.com/chins-xing/asscor/internal/collector"
	"github.com/chins-xing/asscor/internal/kernel"
)

// newLogCollector returns the log collector module, or nil when the collector
// build tag is disabled (kernel zero-bloat).
func newLogCollector() kernel.LogCollectorInterface {
	return collector.New()
}
