package kernel

import apiv1 "github.com/asscor/asscor/api/v1"

type CommanderInterface interface {
	EnqueueCommand(hostID string, action string, params map[string]string) string
	DequeueCommands(hostID string) []*apiv1.Command
	AckCommand(hostID string, cmdID string, success bool, output string)
}
