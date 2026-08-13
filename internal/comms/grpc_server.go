package comms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type GRPCServerConfig struct {
	Enabled      bool
	ListenAddr   string
	TLSEnabled   bool
	CertFile     string
	KeyFile      string
	CAFile       string
	MaxRecvSize  int
	KeepaliveMin time.Duration
}

func DefaultGRPCServerConfig() GRPCServerConfig {
	return GRPCServerConfig{
		Enabled:      false,
		ListenAddr:   ":50052",
		TLSEnabled:   false,
		CertFile:     "certs/server.crt",
		KeyFile:      "certs/server.key",
		CAFile:       "certs/ca.crt",
		MaxRecvSize:  4 * 1024 * 1024,
		KeepaliveMin: 30 * time.Second,
	}
}

type GRPCServer struct {
	cfg       GRPCServerConfig
	kernelSvc *KernelServiceImpl
	agentSvc  *AgentServiceImpl
	server    *grpc.Server
	mu        sync.RWMutex
	running   bool
}

func NewGRPCServer(cfg GRPCServerConfig, kernelSvc *KernelServiceImpl, agentSvc *AgentServiceImpl) *GRPCServer {
	return &GRPCServer{
		cfg:       cfg,
		kernelSvc: kernelSvc,
		agentSvc:  agentSvc,
	}
}

func (s *GRPCServer) Start() error {
	if !s.cfg.Enabled {
		logger.WithComponent("grpc_server").Info("gRPC server disabled")
		return nil
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.cfg.MaxRecvSize),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             s.cfg.KeepaliveMin,
			PermitWithoutStream: true,
		}),
	}

	if s.cfg.TLSEnabled {
		creds, err := s.loadTLSCredentials()
		if err != nil {
			return fmt.Errorf("load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		logger.WithComponent("grpc_server").Info("mTLS enabled")
	}

	s.server = grpc.NewServer(opts...)

	kernelHandler := &grpcKernelHandler{svc: s.kernelSvc}
	agentHandler := &grpcAgentHandler{svc: s.agentSvc}
	apiv1.RegisterKernelServiceServer(s.server, kernelHandler)
	apiv1.RegisterAgentServiceServer(s.server, agentHandler)

	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen on %s: %w", s.cfg.ListenAddr, err)
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	serveErr := make(chan error, 1)
	go func() {
		logger.WithComponent("grpc_server").Info("gRPC server starting", "addr", s.cfg.ListenAddr)
		if err := s.server.Serve(lis); err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			serveErr <- err
			logger.WithComponent("grpc_server").Error("gRPC server stopped", "error", err)
		}
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("gRPC server failed to start: %w", err)
	case <-time.After(5 * time.Second):
		logger.WithComponent("grpc_server").Info("gRPC server running", "addr", s.cfg.ListenAddr)
	}

	return nil
}

func (s *GRPCServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil && s.running {
		s.server.GracefulStop()
		s.running = false
		logger.WithComponent("grpc_server").Info("gRPC server stopped gracefully")
	}
}

func (s *GRPCServer) loadTLSCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(s.cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	return credentials.NewTLS(config), nil
}

type grpcKernelHandler struct {
	svc *KernelServiceImpl
}

func (h *grpcKernelHandler) Register(ctx context.Context, req *apiv1.PBRegisterRequest) (*apiv1.PBRegisterResponse, error) {
	jsonReq := &apiv1.RegisterRequest{
		HostId:   req.HostId,
		Hostname: req.Hostname,
		Version:  req.Version,
	}

	resp, err := h.svc.Register(ctx, jsonReq)
	if err != nil {
		return nil, err
	}

	return &apiv1.PBRegisterResponse{
		Accepted:      resp.Accepted,
		SessionId:     resp.SessionId,
		CaCertificate: resp.CACertPEM,
	}, nil
}

func (h *grpcKernelHandler) Heartbeat(ctx context.Context, req *apiv1.PBHeartbeatRequest) (*apiv1.PBHeartbeatResponse, error) {
	jsonReq := &apiv1.HeartbeatRequest{
		HostId:    req.HostId,
		SessionId: req.SessionId,
		Result:    apiv1.ConvertPBToAssessmentResult(req.Result),
		Packages:  req.Packages,
	}

	resp, err := h.svc.Heartbeat(ctx, jsonReq)
	if err != nil {
		return nil, err
	}

	pbResp := &apiv1.PBHeartbeatResponse{
		Ok:                resp.Ok,
		ThreatCoefficient: resp.ThreatCoefficient,
		AssessmentResult:  apiv1.ConvertAssessmentResultToPB(resp.AssessmentResult),
	}
	for _, cmd := range resp.PendingCommands {
		pbResp.PendingCommands = append(pbResp.PendingCommands, &apiv1.PBCommand{
			CommandId: cmd.CommandId,
			Command:   cmd.Command,
			Params:    cmd.Params,
			Signature: cmd.Signature,
		})
	}

	return pbResp, nil
}

type grpcAgentHandler struct {
	svc *AgentServiceImpl
}

func (h *grpcAgentHandler) GetSnapshot(ctx context.Context, req *apiv1.PBSnapshotRequest) (*apiv1.PBSnapshotResponse, error) {
	jsonReq := &apiv1.SnapshotRequest{HostId: req.HostId}

	resp, err := h.svc.GetSnapshot(ctx, jsonReq)
	if err != nil {
		return nil, err
	}

	return &apiv1.PBSnapshotResponse{
		HostId: resp.HostId,
		Result: apiv1.ConvertAssessmentResultToPB(resp.Result),
	}, nil
}

func (h *grpcAgentHandler) ExecuteCommand(ctx context.Context, req *apiv1.PBCommandRequest) (*apiv1.PBCommandResponse, error) {
	jsonReq := &apiv1.CommandRequest{
		HostId:    req.HostId,
		CommandId: req.CommandId,
	}

	resp, err := h.svc.ExecuteCommand(ctx, jsonReq)
	if err != nil {
		return nil, err
	}

	return &apiv1.PBCommandResponse{
		CommandId: resp.CommandId,
		Success:   resp.Success,
		Output:    resp.Output,
	}, nil
}

func (h *grpcAgentHandler) StreamLogs(stream apiv1.AgentService_StreamLogsServer) error {
	for {
		entry, err := stream.Recv()
		if err != nil {
			break
		}

		logger.WithComponent("grpc_stream_logs").Debug("received log entry",
			"host_id", entry.HostId, "level", entry.Level, "message", entry.Message)
	}

	return stream.SendAndClose(&apiv1.PBAck{Ok: true})
}

type GRPCClientConfig struct {
	ServerAddr string
	TLSEnabled bool
	CertFile   string
	KeyFile    string
	CAFile     string
	Timeout    time.Duration
}

func DefaultGRPCClientConfig() GRPCClientConfig {
	return GRPCClientConfig{
		ServerAddr: "127.0.0.1:50052",
		TLSEnabled: false,
		CertFile:   "certs/agent.crt",
		KeyFile:    "certs/agent.key",
		CAFile:     "certs/ca.crt",
		Timeout:    30 * time.Second,
	}
}

type GRPCClient struct {
	cfg    GRPCClientConfig
	conn   *grpc.ClientConn
	kc apiv1.KernelServiceClient
	mu     sync.RWMutex
}

func NewGRPCClient(cfg GRPCClientConfig) *GRPCClient {
	return &GRPCClient{cfg: cfg}
}

func (c *GRPCClient) Connect() error {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4 * 1024 * 1024)),
	}

	if c.cfg.TLSEnabled {
		creds, err := c.loadTLSCredentials()
		if err != nil {
			return fmt.Errorf("load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.cfg.ServerAddr, opts...)
	if err != nil {
		return fmt.Errorf("dial gRPC server: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.kc = apiv1.NewKernelServiceClient(conn)
	c.mu.Unlock()

	logger.WithComponent("grpc_client").Info("connected to gRPC server", "addr", c.cfg.ServerAddr)
	return nil
}

func (c *GRPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *GRPCClient) Register(ctx context.Context, hostId, hostname, version string) (*apiv1.PBRegisterResponse, error) {
	c.mu.RLock()
	kernel := c.kc
	c.mu.RUnlock()

	if kernel == nil {
		return nil, fmt.Errorf("not connected")
	}

	return kernel.Register(ctx, &apiv1.PBRegisterRequest{
		HostId:   hostId,
		Hostname: hostname,
		Version:  version,
	})
}

func (c *GRPCClient) Heartbeat(ctx context.Context, hostId, sessionId string, result *apiv1.AssessmentResult, packages []string) (*apiv1.PBHeartbeatResponse, error) {
	c.mu.RLock()
	kernel := c.kc
	c.mu.RUnlock()

	if kernel == nil {
		return nil, fmt.Errorf("not connected")
	}

	return kernel.Heartbeat(ctx, &apiv1.PBHeartbeatRequest{
		HostId:    hostId,
		SessionId: sessionId,
		Result:    apiv1.ConvertAssessmentResultToPB(result),
		Packages:  packages,
	})
}

func (c *GRPCClient) loadTLSCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(config), nil
}
