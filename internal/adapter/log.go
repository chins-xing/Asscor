package adapter

import (
	"log"
)

var debugEnabled = false

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func LogInfo(format string, args ...interface{}) {
	log.Printf("[adapter] "+format, args...)
}

func LogWarn(format string, args ...interface{}) {
	log.Printf("[adapter:WARN] "+format, args...)
}

func LogDebug(format string, args ...interface{}) {
	if debugEnabled {
		log.Printf("[adapter:DEBUG] "+format, args...)
	}
}
