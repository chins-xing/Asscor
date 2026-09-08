//go:build adapter && engine

package main

import (
	_ "github.com/asscor/asscor/internal/adapter/management"
	_ "github.com/asscor/asscor/internal/adapter/scanner"
)
