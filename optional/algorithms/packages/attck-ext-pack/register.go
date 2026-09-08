//go:build attck_ext

package attckext

import (
	"github.com/chins-xing/asscor/internal/attck"
	"github.com/chins-xing/asscor/internal/kernel"
)

// Register activates the ATT&CK V19 module and injects it into the assessor.
// Call this during kernel bootstrap (after assessor construction, before Bootstrap):
//
//	if cfg.ATTACK.Enabled {
//	    attckext.Register(assessor)
//	}
func Register(target kernel.ATTACKInjectionTarget) {
	attckMod := attck.New()
	target.SetATTACKProvider(attckMod.AsEngineProvider())
}
