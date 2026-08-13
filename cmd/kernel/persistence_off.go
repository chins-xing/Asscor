//go:build !persistence

package main

import "github.com/asscor/asscor/internal/kernel"

func newPersistence(dataDir string) kernel.PersistenceInterface { return nil }
