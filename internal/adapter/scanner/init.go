package scanner

import "github.com/asscor/asscor/internal/adapter"

func init() {
	adapter.Register(NewTrivyAdapter())
	adapter.Register(NewNucleiAdapter())
	adapter.Register(NewLynisAdapter())

	adapter.Register(NewOpenSCAPAdapter())
	adapter.Register(NewWazuhAgentAdapter())
	adapter.Register(NewSuricataAdapter())
	adapter.Register(NewFalcoAdapter())
	adapter.Register(NewClamAVAdapter())

	adapter.Register(NewOSVScannerAdapter())
	adapter.Register(NewAIDEAdapter())
	adapter.Register(NewNiktoAdapter())
}
