//go:build !spc && engine

package main

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
)

func attachSPC(cfg *config.Config, assessor *engine.Assessor) {}
