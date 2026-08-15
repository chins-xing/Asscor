package kernel

import (
	"context"
	"encoding/json"
	"fmt"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
)

type SourceManagerServiceImpl struct {
	sourceManager SourceManagerInterface
}

func NewSourceManagerServiceImpl(sm SourceManagerInterface) *SourceManagerServiceImpl {
	return &SourceManagerServiceImpl{sourceManager: sm}
}

func (s *SourceManagerServiceImpl) ListSources(ctx context.Context, req *apiv1.ListSourcesRequest) (*apiv1.ListSourcesResponse, error) {
	logger.WithComponent("source_manager").Debug("ListSources", "category", req.Category)

	var sources []SourceStatus
	if req.Category != "" {
		sources = s.sourceManager.ListSources(SourceCategory(req.Category))
	} else {
		sources = s.sourceManager.ListAllSources()
	}

	items := make([]*apiv1.SourceStatus, 0, len(sources))
	for _, src := range sources {
		spec, _ := s.sourceManager.GetSourceSpec(src.ID)
		items = append(items, ConvertSourceStatus(&src, spec))
	}

	return &apiv1.ListSourcesResponse{Sources: items}, nil
}

func (s *SourceManagerServiceImpl) GetSource(ctx context.Context, req *apiv1.GetSourceRequest) (*apiv1.GetSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	status, ok := s.sourceManager.GetSourceStatus(req.Id)
	if !ok {
		return nil, fmt.Errorf("source %s not found", req.Id)
	}

	spec, _ := s.sourceManager.GetSourceSpec(req.Id)
	cfg, _ := s.sourceManager.GetSourceConfig(req.Id)

	resp := &apiv1.GetSourceResponse{
		Status: ConvertSourceStatus(status, spec),
	}
	if spec != nil {
		resp.Spec = convertSourceSpec(spec)
	}
	if cfg != nil {
		resp.Config = &apiv1.SourceConfig{Id: cfg.ID, Settings: cfg.Settings}
	}

	return resp, nil
}

func (s *SourceManagerServiceImpl) DeploySource(ctx context.Context, req *apiv1.DeploySourceRequest) (*apiv1.DeploySourceResponse, error) {
	if req.Spec == nil {
		return nil, fmt.Errorf("spec is required")
	}

	spec := SourceSpec{
		ID:           req.Spec.Id,
		Name:         req.Spec.Name,
		Category:     SourceCategory(req.Spec.Category),
		Priority:     SourcePriority(req.Spec.Priority),
		Version:      req.Spec.Version,
		Description:  req.Spec.Description,
		Interface:    req.Spec.Interface,
		AdapterID:    req.Spec.AdapterId,
		OutputFormat: req.Spec.OutputFormat,
		AdaptDiff:    req.Spec.AdaptDifficulty,
		AccessValue:  req.Spec.AccessValue,
		DependsOn:    req.Spec.DependsOn,
	}

	cfg := SourceConfig{ID: spec.ID, Settings: req.Config}
	if cfg.Settings == nil {
		cfg.Settings = make(map[string]string)
	}

	if err := s.sourceManager.DeploySource(ctx, spec, cfg); err != nil {
		logger.WithComponent("source_manager").Error("deploy failed", "id", spec.ID, "error", err)
		return &apiv1.DeploySourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.DeploySourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) EnableSource(ctx context.Context, req *apiv1.EnableSourceRequest) (*apiv1.EnableSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	if err := s.sourceManager.EnableSource(ctx, req.Id); err != nil {
		return &apiv1.EnableSourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.EnableSourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) DisableSource(ctx context.Context, req *apiv1.DisableSourceRequest) (*apiv1.DisableSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	if err := s.sourceManager.DisableSource(ctx, req.Id); err != nil {
		return &apiv1.DisableSourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.DisableSourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) UninstallSource(ctx context.Context, req *apiv1.UninstallSourceRequest) (*apiv1.UninstallSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	if err := s.sourceManager.UninstallSource(ctx, req.Id, req.Force); err != nil {
		return &apiv1.UninstallSourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.UninstallSourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) UpdateSource(ctx context.Context, req *apiv1.UpdateSourceRequest) (*apiv1.UpdateSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}
	if req.Version == "" {
		return nil, fmt.Errorf("version is required")
	}

	if err := s.sourceManager.UpdateSource(ctx, req.Id, req.Version); err != nil {
		return &apiv1.UpdateSourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.UpdateSourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) ConfigureSource(ctx context.Context, req *apiv1.ConfigureSourceRequest) (*apiv1.ConfigureSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	cfg := SourceConfig{ID: req.Id, Settings: req.Settings}
	if cfg.Settings == nil {
		cfg.Settings = make(map[string]string)
	}

	if err := s.sourceManager.ConfigureSource(ctx, req.Id, cfg); err != nil {
		return &apiv1.ConfigureSourceResponse{Success: false, Error: err.Error()}, nil
	}

	return &apiv1.ConfigureSourceResponse{Success: true}, nil
}

func (s *SourceManagerServiceImpl) RunSource(ctx context.Context, req *apiv1.RunSourceRequest) (*apiv1.RunSourceResponse, error) {
	if req.Id == "" {
		return nil, fmt.Errorf("source id is required")
	}

	if err := s.sourceManager.RunSourceNow(ctx, req.Id); err != nil {
		return &apiv1.RunSourceResponse{Success: false, Error: err.Error()}, nil
	}

	status, _ := s.sourceManager.GetSourceStatus(req.Id)
	findings := 0
	if status != nil {
		findings = status.Findings
	}

	return &apiv1.RunSourceResponse{Success: true, FindingsCount: int32(findings)}, nil
}

func (s *SourceManagerServiceImpl) GetAuditLog(ctx context.Context, req *apiv1.SourceAuditLogRequest) (*apiv1.SourceAuditLogResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}

	entries := s.sourceManager.GetAuditLog(req.SourceId, limit)
	items := make([]*apiv1.AuditLogEntry, 0, len(entries))
	for _, e := range entries {
		items = append(items, &apiv1.AuditLogEntry{
			Timestamp: e.Timestamp.Unix(),
			Action:    e.Action,
			SourceId:  e.SourceID,
			Operator:  e.Operator,
			Detail:    e.Detail,
			Success:   e.Success,
		})
	}

	return &apiv1.SourceAuditLogResponse{Entries: items}, nil
}

func BuildSourceManagerServiceDesc(svc *SourceManagerServiceImpl) *apiv1.ServiceDesc {
	return &apiv1.ServiceDesc{
		ServiceName: "ASSCOR.v1.SourceManagerService",
		Methods: map[string]apiv1.MethodHandler{
			"ListSources": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.ListSourcesRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.ListSources(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"GetSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.GetSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.GetSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"DeploySource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.DeploySourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.DeploySource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"EnableSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.EnableSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.EnableSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"DisableSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.DisableSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.DisableSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"UninstallSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.UninstallSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.UninstallSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"UpdateSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.UpdateSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.UpdateSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"ConfigureSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.ConfigureSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.ConfigureSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"RunSource": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.RunSourceRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.RunSource(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
			"GetAuditLog": func(ctx context.Context, payload []byte) ([]byte, error) {
				var req apiv1.SourceAuditLogRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				resp, err := svc.GetAuditLog(ctx, &req)
				if err != nil {
					return nil, err
				}
				return json.Marshal(resp)
			},
		},
	}
}

func ConvertSourceStatus(s *SourceStatus, spec *SourceSpec) *apiv1.SourceStatus {
	status := &apiv1.SourceStatus{
		Id:          s.ID,
		State:       string(s.State),
		Version:     s.Version,
		Enabled:     s.Enabled,
		LastSync:    s.LastSync.Unix(),
		LastError:   s.LastError,
		Findings:    int32(s.Findings),
		SyncCount:   s.SyncCount,
		ErrorCount:  s.ErrorCount,
		InstalledAt: s.InstalledAt.Unix(),
	}
	if spec != nil {
		status.Name = spec.Name
		status.Category = string(spec.Category)
		status.Priority = string(spec.Priority)
		status.Description = spec.Description
	}
	return status
}

func convertSourceSpec(s *SourceSpec) *apiv1.SourceSpec {
	return &apiv1.SourceSpec{
		Id:              s.ID,
		Name:            s.Name,
		Category:        string(s.Category),
		Priority:        string(s.Priority),
		Version:         s.Version,
		Description:     s.Description,
		Interface:       s.Interface,
		AdapterId:       s.AdapterID,
		OutputFormat:    s.OutputFormat,
		AdaptDifficulty: s.AdaptDiff,
		AccessValue:     s.AccessValue,
		DependsOn:       s.DependsOn,
	}
}
