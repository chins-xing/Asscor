//go:build !persistence

package main

import "github.com/chins-xing/asscor/internal/kernel"

func newPersistence(dataDir string) kernel.PersistenceInterface { return nil }
