//go:build !sourcemanager

package main

import "github.com/asscor/asscor/internal/kernel"

func newSourceManager() kernel.SourceManagerInterface { return nil }
