package management

import "github.com/asscor/asscor/internal/adapter"

func init() {
	adapter.Register(NewAnsibleAdapter())
	adapter.Register(NewNetBoxAdapter())
	adapter.Register(NewSnipeITAdapter())

	adapter.Register(NewFreeIPAAdapter())
	adapter.Register(NewKeycloakAdapter())
	adapter.Register(NewWazuhSIEMAdapter())
	adapter.Register(NewRundeckAdapter())

	adapter.Register(NewJiraAdapter())
	adapter.Register(NewTerraformAdapter())
	adapter.Register(NewOpenTofuAdapter())
}
