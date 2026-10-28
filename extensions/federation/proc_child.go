package federation

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ProcState 是联邦子进程的运行时状态（进程隔离模式）。
//
// 它只持有"纯逻辑"组件：Collector / MasterServer / Reporter 与最近一次由内核
// 推送的快照；不 import internal/kernel，也不访问主进程内存。
type ProcState struct {
	mu   sync.Mutex
	cfg  Config
	role Role

	collector *Collector
	server    *MasterServer
	reporter  *Reporter
	cancel    context.CancelFunc

	last        NodeReport
	localHosts  []HostFact
	localPolicy []PolicyFact
	localKnown  bool
	startedAt   time.Time
	listenErr   error

	shutdown chan struct{}
}

// NewProcState 构建子进程状态。
func NewProcState() *ProcState {
	return &ProcState{cfg: Defaults(), role: RoleOff, shutdown: make(chan struct{})}
}

// RunChild 是子进程入口：从 stdin 读 JSON 请求，向 stdout 写响应。
//
// 请求/响应是**行分隔 JSON**，与内核侧 Proxy 的 procClient 配对。
func RunChild() error {
	state := NewProcState()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(rpcResponse{ID: 0, Error: "parse: " + err.Error()})
			continue
		}
		result, err := state.handle(req.Method, req.Params)
		if err != nil {
			_ = enc.Encode(rpcResponse{ID: req.ID, Error: err.Error()})
			continue
		}
		raw, mErr := json.Marshal(result)
		if mErr != nil {
			_ = enc.Encode(rpcResponse{ID: req.ID, Error: "marshal: " + mErr.Error()})
			continue
		}
		_ = enc.Encode(rpcResponse{ID: req.ID, Result: raw})
		if req.Method == methodShutdown {
			return nil
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func (s *ProcState) handle(method string, params json.RawMessage) (any, error) {
	switch method {
	case methodPing:
		return map[string]any{"pong": true}, nil
	case methodConfigure:
		var p ConfigureParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return nil, s.configure(p)
	case methodSnapshot:
		var p SnapshotParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		s.applySnapshot(p)
		return map[string]any{"accepted": true}, nil
	case methodStatus:
		st := s.status()
		return st, nil
	case methodCheck:
		var p CheckParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return s.check(p), nil
	case methodExport:
		return s.export(), nil
	case methodReportNow:
		return nil, s.reportNow()
	case methodShutdown:
		s.stop()
		return map[string]any{"stopped": true}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func (s *ProcState) configure(p ConfigureParams) error {
	s.mu.Lock()
	if s.startedAt.IsZero() {
		s.startedAt = time.Now()
	}
	s.cfg = Config{
		Role:           Role(p.Role),
		NodeID:         p.NodeID,
		MasterURL:      p.MasterURL,
		ListenAddr:     p.ListenAddr,
		ReportInterval: time.Duration(p.ReportIntervalSec) * time.Second,
		RequestTimeout: DefaultRequestTimeout,
		Token:          p.Token,
	}
	if s.cfg.ListenAddr == "" {
		s.cfg.ListenAddr = DefaultListenAddr
	}
	if s.cfg.ReportInterval <= 0 {
		s.cfg.ReportInterval = time.Duration(DefaultReportIntervalSec) * time.Second
	}
	cfg := s.cfg
	s.role = cfg.Role
	started := s.startedAt
	s.mu.Unlock()

	if cfg.Role == RoleOff {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	switch cfg.Role {
	case RoleMaster:
		collector := NewCollector()
		server := NewMasterServer(collector, cfg.ListenAddr, cfg.Token)
		if err := server.Start(); err != nil {
			s.mu.Lock()
			s.collector = collector
			s.server = server
			s.listenErr = err
			s.mu.Unlock()
			return nil // 降级：子进程保持运行，状态里可见 ListenError
		}
		s.mu.Lock()
		s.collector = collector
		s.server = server
		s.mu.Unlock()
	case RoleNode:
		rep, err := NewReporter(ReporterConfig{
			MasterURL: cfg.MasterURL,
			NodeID:    cfg.NodeID,
			Token:     cfg.Token,
			Interval:  cfg.ReportInterval,
			Timeout:   cfg.RequestTimeout,
			OnReport: func(err error, attempts int) {
				_ = err
				_ = attempts
			},
		})
		if err != nil {
			cancel()
			return err
		}
		s.mu.Lock()
		s.reporter = rep
		s.mu.Unlock()
		go rep.Run(ctx, func() NodeReport {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.last
		})
	}
	_ = started
	return nil
}

func (s *ProcState) applySnapshot(p SnapshotParams) {
	s.mu.Lock()
	s.last = p.Report
	if p.Hosts != nil || p.Policies != nil {
		s.localHosts = p.Hosts
		s.localPolicy = p.Policies
		s.localKnown = p.PolicyKnown
	}
	s.mu.Unlock()
}

func (s *ProcState) status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Role:              s.role,
		NodeID:            s.cfg.NodeID,
		MasterURL:         s.cfg.MasterURL,
		ReportIntervalSec: int(s.cfg.ReportInterval / time.Second),
		Running:           true,
		ConfigHash:        s.last.ConfigHash,
		Params:            s.last.Params,
		Hosts:             s.last.Hosts,
		Zones:             s.last.Zones,
		AvgSSAM:           s.last.AvgSSAM,
	}
	if !s.startedAt.IsZero() {
		t := s.startedAt
		st.StartedAt = &t
	}
	if s.cfg.Role == RoleMaster {
		st.ListenAddr = s.cfg.ListenAddr
		if s.server != nil && s.server.Addr() != "" {
			st.ListenAddr = s.server.Addr()
		}
		if s.listenErr != nil {
			st.ListenError = s.listenErr.Error()
		}
		if s.collector != nil {
			st.Nodes = s.collector.Nodes()
		}
	}
	if s.reporter != nil {
		at, err, attempts := s.reporter.LastReport()
		if !at.IsZero() {
			t := at
			st.LastReportAt = &t
		}
		if err != nil {
			st.LastReportError = err.Error()
		}
		st.LastReportAttempts = attempts
	}
	return st
}

func (s *ProcState) mergedGraph() (g any) {
	s.mu.Lock()
	reports := s.collector.Nodes()
	hosts := append([]HostFact(nil), s.localHosts...)
	policies := append([]PolicyFact(nil), s.localPolicy...)
	known := s.localKnown
	s.mu.Unlock()
	return struct {
		Reports  []NodeReport
		Hosts    []HostFact
		Policies []PolicyFact
		Known    bool
	}{reports, hosts, policies, known}
}

func (s *ProcState) check(p CheckParams) any {
	parts := s.mergedGraph().(struct {
		Reports  []NodeReport
		Hosts    []HostFact
		Policies []PolicyFact
		Known    bool
	})
	lg := BuildMergedGraphWithLocal(parts.Reports, parts.Hosts, parts.Policies, parts.Known)
	res := CheckMerged(lg, p.Src, p.Dst, 5)
	res.Nodes = len(parts.Reports)
	return res
}

func (s *ProcState) export() any {
	parts := s.mergedGraph().(struct {
		Reports  []NodeReport
		Hosts    []HostFact
		Policies []PolicyFact
		Known    bool
	})
	return MergedTopologyWithLocal(parts.Reports, parts.Hosts, parts.Policies, parts.Known)
}

func (s *ProcState) reportNow() error {
	s.mu.Lock()
	rep := s.reporter
	report := s.last
	s.mu.Unlock()
	if rep == nil {
		return fmt.Errorf("report-now 只在 node 角色可用")
	}
	return rep.Report(context.Background(), report)
}

func (s *ProcState) stop() {
	s.mu.Lock()
	cancel := s.cancel
	rep := s.reporter
	server := s.server
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if rep != nil {
		rep.Stop()
	}
	if server != nil {
		_ = server.Stop(context.Background())
	}
	select {
	case <-s.shutdown:
	default:
		close(s.shutdown)
	}
}
