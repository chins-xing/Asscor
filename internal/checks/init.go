//go:build checks

package checks

import (
	"github.com/chins-xing/asscor/internal/checks/linux"
)

func init() {
	Register(linux.All()...)
}
