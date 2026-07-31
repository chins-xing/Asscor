package kernel

type HostStatus int

const (
	HostOK HostStatus = iota
	HostWarning
	HostCritical
	HostIsolated
)

func (s HostStatus) String() string {
	switch s {
	case HostOK:
		return "OK"
	case HostWarning:
		return "Warning"
	case HostCritical:
		return "Critical"
	case HostIsolated:
		return "Isolated"
	default:
		return "Unknown"
	}
}

type PolicyAction struct {
	Action  string
	Params  map[string]string
	Message string
}

type PolicyInterface interface {
	EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction)
	GetHostStatus(hostID string) HostStatus
}
