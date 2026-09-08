//go:build !sourcemanager

package main

import "github.com/chins-xing/asscor/internal/kernel"

func newSourceManager() kernel.SourceManagerInterface { return nil }
