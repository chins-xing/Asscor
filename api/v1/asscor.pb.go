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
	HostId        string            `json:"host_id"`
	SessionId     string            `json:"session_id"`
	Result        *AssessmentResult `json:"result,omitempty"`
	Packages      []string          `json:"packages,omitempty"`
	InstalledCPEs []string          `json:"installed_cpes,omitempty"`
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
	SpcCVEs      []SPCCVEInfo       `json:"spc_cves,omitempty"`
	Checks       []*CheckResult     `json:"checks"`

	ATTACKCoverage      []ATTACKCoverageInfo    `json:"attck_coverage,omitempty"`
	ATTACKKillChain     *ATTACKKillChainInfo    `json:"attck_kill_chain,omitempty"`
	ATTACKAPTMatches    []ATTACKAPTMatchInfo    `json:"attck_apt_matches,omitempty"`
	ATTACKPredictedRisk *ATTACKPredictedRiskInfo `json:"attck_predicted_risk,omitempty"`
	ATTACKFailedTechs   []string                `json:"attck_failed_techniques,omitempty"`
}

type ATTACKCoverageInfo struct {
	TacticID        string  `json:"tactic_id"`
	TacticName      string  `json:"tactic_name"`
	TotalTechniques int     `json:"total_techniques"`
	CoveredDet      int     `json:"covered_detection"`
	CoverageDet     float64 `json:"coverage_detection"`
	CoveragePrev    float64 `json:"coverage_prevention"`
	CoverageComp    float64 `json:"coverage_composite"`
	RiskLevel       string  `json:"risk_level"`
}

type ATTACKKillChainInfo struct {
	Stages       []ATTACKKillChainStage `json:"stages"`
	OverallScore float64                `json:"overall_score"`
	WeakestStage string                 `json:"weakest_stage"`
}

type ATTACKKillChainStage struct {
	Name         string `json:"name"`
	Score        float64 `json:"score"`
	Status       string `json:"status"`
	ChecksPassed int    `json:"checks_passed"`
	ChecksTotal  int    `json:"checks_total"`
}

type ATTACKAPTMatchInfo struct {
	GroupID     string   `json:"group_id"`
	GroupName   string   `json:"group_name"`
	Similarity  float64  `json:"similarity"`
	Confidence  string   `json:"confidence"`
	OverlapTech []string `json:"overlap_techniques"`
}

type ATTACKPredictedRiskInfo struct {
	MaxRiskScore    float64  `json:"max_risk_score"`
	EnhancedThreat  float64  `json:"enhanced_threat_coeff"`
	PredictedPaths  int      `json:"predicted_paths"`
	Recommendations []string `json:"recommendations,omitempty"`
}

type SPCCVEInfo struct {
	CVEID      string  `json:"cve_id"`
	CVSS       float64 `json:"cvss"`
	EPSS       float64 `json:"epss"`
	InKEV      bool    `json:"in_kev"`
	HasPoC     bool    `json:"has_poc"`
	Penalty    float64 `json:"penalty"`
	Product    string  `json:"product,omitempty"`
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

type StreamLogsRequest struct {
	Entries []*LogEntry `json:"entries"`
}

type Ack struct {
	Ok bool `json:"ok"`
}

type ListSourcesRequest struct {
	Category string `json:"category,omitempty"`
}

type ListSourcesResponse struct {
	Sources []*SourceStatus `json:"sources"`
}

type GetSourceRequest struct {
	Id string `json:"id"`
}

type GetSourceResponse struct {
	Status *SourceStatus `json:"status"`
	Spec   *SourceSpec   `json:"spec,omitempty"`
	Config *SourceConfig `json:"config,omitempty"`
}

type DeploySourceRequest struct {
	Spec   *SourceSpec   `json:"spec"`
	Config map[string]string `json:"config,omitempty"`
}

type DeploySourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type EnableSourceRequest struct {
	Id string `json:"id"`
}

type EnableSourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type DisableSourceRequest struct {
	Id string `json:"id"`
}

type DisableSourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type UninstallSourceRequest struct {
	Id    string `json:"id"`
	Force bool   `json:"force,omitempty"`
}

type UninstallSourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type UpdateSourceRequest struct {
	Id      string `json:"id"`
	Version string `json:"version"`
}

type UpdateSourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type ConfigureSourceRequest struct {
	Id       string            `json:"id"`
	Settings map[string]string `json:"settings"`
}

type ConfigureSourceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type RunSourceRequest struct {
	Id string `json:"id"`
}

type RunSourceResponse struct {
	Success      bool   `json:"success"`
	FindingsCount int32 `json:"findings_count"`
	Error        string `json:"error,omitempty"`
}

type SourceAuditLogRequest struct {
	SourceId string `json:"source_id,omitempty"`
	Limit    int32  `json:"limit,omitempty"`
}

type SourceAuditLogResponse struct {
	Entries []*AuditLogEntry `json:"entries"`
}

type SourceStatus struct {
	Id          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Category    string `json:"category,omitempty"`
	Priority    string `json:"priority,omitempty"`
	Description string `json:"description,omitempty"`
	State       string `json:"state"`
	Version     string `json:"version"`
	Enabled     bool   `json:"enabled"`
	LastSync    int64  `json:"last_sync"`
	LastError   string `json:"last_error,omitempty"`
	Findings    int32  `json:"findings_count"`
	SyncCount   int64  `json:"sync_count"`
	ErrorCount  int64  `json:"error_count"`
	InstalledAt int64  `json:"installed_at"`
}

type SourceSpec struct {
	Id              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Priority        string   `json:"priority"`
	Version         string   `json:"version"`
	Description     string   `json:"description,omitempty"`
	Interface       string   `json:"interface,omitempty"`
	AdapterId       string   `json:"adapter_id,omitempty"`
	OutputFormat    string   `json:"output_format,omitempty"`
	AdaptDifficulty string   `json:"adapt_difficulty,omitempty"`
	AccessValue     string   `json:"access_value,omitempty"`
	DependsOn       []string `json:"depends_on,omitempty"`
}

type SourceConfig struct {
	Id       string            `json:"id"`
	Settings map[string]string `json:"settings"`
}

type AuditLogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Action    string `json:"action"`
	SourceId  string `json:"source_id"`
	Operator  string `json:"operator"`
	Detail    string `json:"detail"`
	Success   bool   `json:"success"`
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
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	data = append(data, '\n')
	for written := 0; written < len(data); {
		n, err := conn.Write(data[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func (c *JSONCodec) WriteError(conn net.Conn, err error) error {
	resp := map[string]string{
		"status": "error",
		"error":  err.Error(),
	}
	data, merr := json.Marshal(resp)
	if merr != nil {
		return fmt.Errorf("marshal error response: %w", merr)
	}
	data = append(data, '\n')
	for written := 0; written < len(data); {
		n, werr := conn.Write(data[written:])
		if werr != nil {
			return werr
		}
		written += n
	}
	return nil
}