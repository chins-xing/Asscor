package kernel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	apiv1 "github.com/argus-security/argus/api/v1"
)

type ServerConfig struct {
	ListenAddr      string
	TLSConfig       *tls.Config
	MaxRecvMsgSize  int
	MaxSendMsgSize  int
	KeepaliveTime   time.Duration
	KeepaliveTimeout time.Duration
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:      "0.0.0.0:50051",
		MaxRecvMsgSize:  16 * 1024 * 1024,
		MaxSendMsgSize:  16 * 1024 * 1024,
		KeepaliveTime:   30 * time.Second,
		KeepaliveTimeout: 10 * time.Second,
	}
}

type Server struct {
	cfg    ServerConfig
	kernel *Kernel

	registry *apiv1.ServiceRegistry
	codec    apiv1.ServerCodec

	mu       sync.Mutex
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewServer(cfg ServerConfig, k *Kernel) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:      cfg,
		kernel:   k,
		registry: apiv1.NewServiceRegistry(),
		codec:    &apiv1.JSONCodec{},
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *Server) RegisterService(desc *apiv1.ServiceDesc) {
	s.registry.Register(desc)
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
	log.Printf("grpc: server listening on %s (mTLS: %v)", s.cfg.ListenAddr, s.cfg.TLSConfig != nil)

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
				log.Printf("grpc: accept error: %v", err)
				continue
			}
		}

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 256*1024)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		service, method, payload, err := s.codec.ReadRequest(br)
		if err != nil {
			if err.Error() != "EOF" {
				log.Printf("grpc: read error: %v", err)
			}
			return
		}

		respPayload, err := s.registry.Dispatch(s.ctx, service, method, payload)
		if err != nil {
			if werr := s.codec.WriteError(conn, err); werr != nil {
				log.Printf("grpc: write error response: %v (original: %v)", werr, err)
			}
			continue
		}

		if err := s.codec.WriteResponse(conn, respPayload); err != nil {
			log.Printf("grpc: write error: %v", err)
			return
		}
	}
}

func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
}

func BuildServiceDesc(kernelSvc *KernelServiceImpl, agentSvc *AgentServiceImpl) []*apiv1.ServiceDesc {
	return []*apiv1.ServiceDesc{
		{
			ServiceName: "argus.v1.KernelService",
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
			ServiceName: "argus.v1.AgentService",
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
			},
		},
	}
}