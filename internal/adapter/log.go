package adapter

import (
	"log/slog"

	"github.com/argus-security/argus/internal/logger"
)

var debugEnabled = false

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func LogInfo(msg string, args ...interface{}) {
	logger.With("component", "adapter").Info(msg, args...)
}

func LogWarn(msg string, args ...interface{}) {
	logger.With("component", "adapter").Warn(msg, args...)
}

func LogDebug(msg string, args ...interface{}) {
	if debugEnabled {
		logger.With("component", "adapter").Debug(msg, args...)
	}
}

func LogError(msg string, args ...interface{}) {
	logger.With("component", "adapter").Error(msg, args...)
}

func AdapterLogger(name string) *slog.Logger {
	return logger.With("component", "adapter", "adapter_name", name)
}
