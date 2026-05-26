package kernel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/logger"
)

type ctxKey string

type ServerConfig struct {
	ListenAddr       string
	TLSConfig        *tls.Config
	MaxRecvMsgSize   int
	MaxSendMsgSize   int
	KeepaliveTime    time.Duration
	KeepaliveTimeout time.Duration
	MaxConns         int
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:       ":50051",
		MaxRecvMsgSize:   16 * 1024 * 1024,
		MaxSendMsgSize:   16 * 1024 * 1024,
		KeepaliveTime:    30 * time.Second,
		KeepaliveTimeout: 10 * time.Second,
		MaxConns:         100,
	}
}

type Server struct {
	cfg    ServerConfig
	kernel *Kernel

	registry *apiv1.ServiceRegistry
	codec    apiv1.ServerCodec

	interceptors *Interceptors

	mu       sync.Mutex
	listener net.Listener
	connSem  chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewServer(cfg ServerConfig, k *Kernel) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = 100
	}
	return &Server{
		cfg:      cfg,
		kernel:   k,
		registry: apiv1.NewServiceRegistry(),
		codec:    &apiv1.JSONCodec{},
		connSem:  make(chan struct{}, maxConns),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *Server) RegisterService(desc *apiv1.ServiceDesc) {
	s.registry.Register(desc)
}

func (s *Server) SetInterceptors(interceptors *Interceptors) {
	s.interceptors = interceptors
}

func (s *Server) Start() error {
	var lis net.Listener
	var err error

	if s.cfg.TLSConfig != nil {
		lis, err = tls.Listen("tcp", s.cfg.ListenAddr, s.cfg.TLSConfig)
	} else {
		lis, err = net.Listen("tcp", s.cfg.ListenAddr)
	}

	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddr, err)
	}

	s.listener = lis
	logger.WithComponent("grpc").Info("server listening", "addr", s.cfg.ListenAddr, "mtls", s.cfg.TLSConfig != nil)

	go s.acceptLoop()

	return nil
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				logger.WithComponent("grpc").Error("accept error", "error", err)
				continue
			}
		}

		select {
		case s.connSem <- struct{}{}:
		case <-s.ctx.Done():
			conn.Close()
			return
		}

		s.wg.Add(1)
		go func() {
			defer func() {
				<-s.connSem
				s.wg.Done()
			}()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		if r := recover(); r != nil {
			slog.Error("grpc: panic recovered", "remote", conn.RemoteAddr(), "panic", r, "stack", stackTrace(4096))
		}
	}()

	br := bufio.NewReaderSize(conn, 256*1024)

	clientAddr := conn.RemoteAddr().String()
	ctx := context.WithValue(s.ctx, ctxKey("client_addr"), clientAddr)

	var dispatch HandlerFunc
	if s.interceptors != nil && len(s.interceptors.Chain.Interceptors()) > 0 {
		dispatch = s.interceptors.Chain.Then(func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
			return s.registry.Dispatch(ctx, service, method, payload)
		})
	}

	maxPayload := int64(s.cfg.MaxRecvMsgSize)
	if maxPayload <= 0 {
		maxPayload = 16 * 1024 * 1024
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(s.cfg.KeepaliveTimeout))

		service, method, payload, err := s.codec.ReadRequest(io.LimitReader(br, maxPayload+1))
		if err != nil {
			if errors.Is(err, io.EOF) && len(payload) == 0 {
				return
			}
			if !errors.Is(err, io.EOF) {
				logger.WithComponent("grpc").Warn("read error", "error", err)
				return
			}
		}

		if int64(len(payload)) > maxPayload {
			logger.WithComponent("grpc").Warn("payload exceeds limit", "size", len(payload), "limit", maxPayload, "remote", clientAddr)
			if werr := s.codec.WriteError(conn, fmt.Errorf("payload too large: %d bytes (max %d)", len(payload), maxPayload)); werr != nil {
				logger.WithComponent("grpc").Error("write error response", "write_error", werr)
			}
			continue
		}

		var respPayload []byte
		if dispatch != nil {
			respPayload, err = dispatch(ctx, service, method, payload)
		} else {
			respPayload, err = s.registry.Dispatch(ctx, service, method, payload)
		}

		conn.SetWriteDeadline(time.Now().Add(s.cfg.KeepaliveTimeout))

		if err != nil {
			if werr := s.codec.WriteError(conn, err); werr != nil {
				logger.WithComponent("grpc").Error("write error response", "write_error", werr, "original_error", err)
			}
			continue
		}

		if err := s.codec.WriteResponse(conn, respPayload); err != nil {
			logger.WithComponent("grpc").Error("write error", "error", err)
			return
		}
	}
}

func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	if s.interceptors != nil {
		s.interceptors.Stop()
	}
	s.wg.Wait()
}

func BuildServiceDesc(kernelSvc *KernelServiceImpl, agentSvc *AgentServiceImpl) []*apiv1.ServiceDesc {
	return []*apiv1.ServiceDesc{
		{
			ServiceName: "ASSCOR.v1.KernelService",
			Methods: map[string]apiv1.MethodHandler{
				"Register": func(ctx context.Context, payload []byte) ([]byte, error) {
					var req apiv1.RegisterRequest
					if err := json.Unmarshal(payload, &req); err != nil {
						return nil, fmt.Errorf("decode: %w", err)
					}
					resp, err := kernelSvc.Register(ctx, &req)
					if err != nil {
						return nil, err
					}
					return json.Marshal(resp)
				},
				"Heartbeat": func(ctx context.Context, payload []byte) ([]byte, error) {
					var req apiv1.HeartbeatRequest
					if err := json.Unmarshal(payload, &req); err != nil {
						return nil, fmt.Errorf("decode: %w", err)
					}
					resp, err := kernelSvc.Heartbeat(ctx, &req)
					if err != nil {
						return nil, err
					}
					return json.Marshal(resp)
				},
			},
		},
		{
			ServiceName: "ASSCOR.v1.AgentService",
			Methods: map[string]apiv1.MethodHandler{
				"GetSnapshot": func(ctx context.Context, payload []byte) ([]byte, error) {
					var req apiv1.SnapshotRequest
					if err := json.Unmarshal(payload, &req); err != nil {
						return nil, fmt.Errorf("decode: %w", err)
					}
					resp, err := agentSvc.GetSnapshot(ctx, &req)
					if err != nil {
						return nil, err
					}
					return json.Marshal(resp)
				},
				"ExecuteCommand": func(ctx context.Context, payload []byte) ([]byte, error) {
					var req apiv1.CommandRequest
					if err := json.Unmarshal(payload, &req); err != nil {
						return nil, fmt.Errorf("decode: %w", err)
					}
					resp, err := agentSvc.ExecuteCommand(ctx, &req)
					if err != nil {
						return nil, err
					}
					return json.Marshal(resp)
				},
				"StreamLogs": func(ctx context.Context, payload []byte) ([]byte, error) {
					var req apiv1.StreamLogsRequest
					if err := json.Unmarshal(payload, &req); err != nil {
						return nil, fmt.Errorf("decode: %w", err)
					}
					resp, err := agentSvc.StreamLogs(ctx, &req)
					if err != nil {
						return nil, err
					}
					return json.Marshal(resp)
				},
			},
		},
	}
}

func stackTrace(n int) string {
	buf := make([]byte, n)
	m := runtime.Stack(buf, false)
	return string(buf[:m])
}