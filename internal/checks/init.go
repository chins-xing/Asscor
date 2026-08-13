//go:build checks

package checks

import (
	"github.com/asscor/asscor/internal/checks/linux"
)

func init() {
	Register(linux.All()...)
}
