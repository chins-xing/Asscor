//go:build collector && collector_proc

package main

import (
	"github.com/chins-xing/asscor/extensions/logcollector"
	"github.com/chins-xing/asscor/internal/kernel"
)

// newLogCollector returns the process-isolated collector proxy.
func newLogCollector() kernel.LogCollectorInterface {
	return logcollector.NewProxy()
}
