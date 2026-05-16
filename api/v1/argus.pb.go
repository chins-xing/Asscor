package apiv1

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type RegisterRequest struct {
	HostId   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

type RegisterResponse struct {
	Accepted   bool   `json:"accepted"`
	SessionId  string `json:"session_id"`
	CACertPEM  []byte `json:"ca_cert_pem,omitempty"`
}

type HeartbeatRequest struct {
	HostId    string            `json:"host_id"`
	SessionId string            `json:"session_id"`
	Result    *AssessmentResult `json:"result,omitempty"`
}

type HeartbeatResponse struct {
	Ok                bool              `json:"ok"`
	ThreatCoefficient float64           `json:"threat_coefficient"`
	PendingCommands   []*Command        `json:"pending_commands"`
	AssessmentResult  *AssessmentResult `json:"assessment_result,omitempty"`
}

type AssessmentResult struct {
	FinalScore   float64            `json:"final_score"`
	Acceptable   bool               `json:"acceptable"`
	DomainScores map[string]float64 `json:"domain_scores"`
	EdgeFactors  map[string]float64 `json:"edge_factors,omitempty"`
	ThreatCoeff  float64            `json:"threat_coefficient,omitempty"`
	SpcScore     float64            `json:"spc_score,omitempty"`
	Checks       []*CheckResult     `json:"checks"`
}

type CheckResult struct {
	CheckId       string  `json:"check_id"`
	Domain        string  `json:"domain"`
	Name          string  `json:"name"`
	Passed        bool    `json:"passed"`
	Delta         float64 `json:"delta"`
	Detail        string  `json:"detail"`
	ComplianceRef string  `json:"compliance_ref,omitempty"`
}

type Command struct {
	CommandId string            `json:"command_id"`
	Command   string            `json:"command"`
	Params    map[string]string `json:"params"`
	Signature []byte            `json:"signature"`
}

type CommandRequest struct {
	HostId    string `json:"host_id"`
	CommandId string `json:"command_id"`
}

type CommandResponse struct {
	CommandId string `json:"command_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
}

type SnapshotRequest struct {
	HostId string `json:"host_id"`
}

type SnapshotResponse struct {
	HostId string            `json:"host_id"`
	Result *AssessmentResult `json:"result"`
}

type LogEntry struct {
	HostId    string `json:"host_id"`
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type Ack struct {
	Ok bool `json:"ok"`
}

type MethodHandler func(ctx context.Context, payload []byte) ([]byte, error)

type ServiceDesc struct {
	ServiceName string
	Methods     map[string]MethodHandler
}

type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]*ServiceDesc
}

func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string]*ServiceDesc),
	}
}

func (r *ServiceRegistry) Register(desc *ServiceDesc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[desc.ServiceName] = desc
}

func (r *ServiceRegistry) Dispatch(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
	r.mu.RLock()
	desc, ok := r.services[service]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("service %s not found", service)
	}

	handler, ok := desc.Methods[method]
	if !ok {
		return nil, fmt.Errorf("method %s/%s not found", service, method)
	}

	return handler(ctx, payload)
}

type ServerCodec interface {
	ReadRequest(r io.Reader) (service, method string, payload []byte, err error)
	WriteResponse(conn net.Conn, payload []byte) error
	WriteError(conn net.Conn, err error) error
}

type JSONCodec struct{}

func (c *JSONCodec) ReadRequest(r io.Reader) (service, method string, payload []byte, err error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 256*1024)
	}

	line, err := br.ReadBytes('\n')
	if err != nil {
		return "", "", nil, err
	}

	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	var req struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return "", "", nil, fmt.Errorf("decode request: %w", err)
	}

	service = req.Service
	method = req.Method
	payload = req.Payload
	return
}

func (c *JSONCodec) WriteResponse(conn net.Conn, payload []byte) error {
	resp := map[string]interface{}{
		"status":  "ok",
		"payload": json.RawMessage(payload),
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, err := conn.Write(data)
	return err
}

func (c *JSONCodec) WriteError(conn net.Conn, err error) error {
	resp := map[string]string{
		"status": "error",
		"error":  err.Error(),
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, errWrite := conn.Write(data)
	return errWrite
}