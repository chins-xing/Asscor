//go:build !spc && engine

package main

import (
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
)

func attachSPC(cfg *config.Config, assessor *engine.Assessor) {}
