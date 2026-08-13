//go:build !webui

package main

import "github.com/asscor/asscor/internal/kernel"

func newWebUI(port int) kernel.Plugin { return nil }
