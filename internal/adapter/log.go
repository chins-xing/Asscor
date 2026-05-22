package adapter

import (
	"log/slog"

	"github.com/argus-security/argus/internal/logger"
)

var debugEnabled = false

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func ResetDebugForTesting() {
	debugEnabled = false
}

func LogInfo(msg string, args ...interface{}) {
	logger.WithComponent("adapter").Info(msg, args...)
}

func LogWarn(msg string, args ...interface{}) {
	logger.WithComponent("adapter").Warn(msg, args...)
}

func LogDebug(msg string, args ...interface{}) {
	if debugEnabled {
		logger.WithComponent("adapter").Debug(msg, args...)
	}
}

func LogError(msg string, args ...interface{}) {
	logger.WithComponent("adapter").Error(msg, args...)
}

func AdapterLogger(name string) *slog.Logger {
	return logger.With("adapter", "adapter_name", name)
}
