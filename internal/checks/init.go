package checks

import (
	"github.com/argus-security/argus/internal/checks/linux"
)

func init() {
	Register(linux.All()...)
}
