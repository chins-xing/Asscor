//go:build spc

package spc

import (
	"io"

	"github.com/chins-xing/asscor/internal/logger"
)

// readLimitedBody reads at most limit bytes and surfaces the error instead of
// silently treating a truncated/failed read as a valid response (audit D-10).
func readLimitedBody(r io.Reader, limit int64) []byte {
	body, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		logger.WithComponent("spc").Warn("failed to read response body", "limit", limit, "error", err)
	}
	return body
}
