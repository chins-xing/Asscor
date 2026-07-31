package kernel

import "time"

type AgentRecord struct {
	HostID      string
	Hostname    string
	Version     string
	LastSeen    time.Time
	Registered  time.Time
	Connections int64
	Active      bool
}

type HeartbeatInterface interface {
	RecordHeartbeat(hostID string)
	RegisterAgent(hostID, hostname, version string)
	GetAgent(hostID string) *AgentRecord
	ListAgents() []*AgentRecord
	IsAlive(hostID string) bool
}
