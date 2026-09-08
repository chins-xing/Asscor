//go:build persistence

package main

import (
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/persistence"
)

// newPersistence returns the persistence module, or nil when the persistence
// build tag is disabled (kernel zero-bloat).
func newPersistence(dataDir string) kernel.PersistenceInterface {
	return persistence.New(dataDir)
}
