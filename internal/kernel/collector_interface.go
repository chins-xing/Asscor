package kernel

import apiv1 "github.com/asscor/asscor/api/v1"

type LogCollectorInterface interface {
	Append(entry *apiv1.LogEntry) error
	AppendBatch(entries []*apiv1.LogEntry) error
	LogPath() string
}
