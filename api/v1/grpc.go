//go:build comms

package apiv1

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KernelServiceServer interface {
	Register(ctx context.Context, req *PBRegisterRequest) (*PBRegisterResponse, error)
	Heartbeat(ctx context.Context, req *PBHeartbeatRequest) (*PBHeartbeatResponse, error)
}

type AgentServiceServer interface {
	GetSnapshot(ctx context.Context, req *PBSnapshotRequest) (*PBSnapshotResponse, error)
	ExecuteCommand(ctx context.Context, req *PBCommandRequest) (*PBCommandResponse, error)
	StreamLogs(stream AgentService_StreamLogsServer) error
}

func RegisterKernelServiceServer(s grpc.ServiceRegistrar, srv KernelServiceServer) {
	desc := &grpc.ServiceDesc{
		ServiceName: "ASSCOR.v1.KernelService",
		HandlerType: (*KernelServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Register",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PBRegisterRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(KernelServiceServer).Register(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/ASSCOR.v1.KernelService/Register",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(KernelServiceServer).Register(ctx, req.(*PBRegisterRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
			{
				MethodName: "Heartbeat",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PBHeartbeatRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(KernelServiceServer).Heartbeat(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/ASSCOR.v1.KernelService/Heartbeat",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(KernelServiceServer).Heartbeat(ctx, req.(*PBHeartbeatRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "api/v1/ASSCOR.proto",
	}
	s.RegisterService(desc, srv)
}

func RegisterAgentServiceServer(s grpc.ServiceRegistrar, srv AgentServiceServer) {
	desc := &grpc.ServiceDesc{
		ServiceName: "ASSCOR.v1.AgentService",
		HandlerType: (*AgentServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetSnapshot",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PBSnapshotRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(AgentServiceServer).GetSnapshot(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/ASSCOR.v1.AgentService/GetSnapshot",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(AgentServiceServer).GetSnapshot(ctx, req.(*PBSnapshotRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
			{
				MethodName: "ExecuteCommand",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PBCommandRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(AgentServiceServer).ExecuteCommand(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/ASSCOR.v1.AgentService/ExecuteCommand",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(AgentServiceServer).ExecuteCommand(ctx, req.(*PBCommandRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "StreamLogs",
				ServerStreams: false,
				ClientStreams: true,
			},
		},
		Metadata: "api/v1/ASSCOR.proto",
	}
	s.RegisterService(desc, srv)
}

type KernelServiceClient interface {
	Register(ctx context.Context, req *PBRegisterRequest, opts ...grpc.CallOption) (*PBRegisterResponse, error)
	Heartbeat(ctx context.Context, req *PBHeartbeatRequest, opts ...grpc.CallOption) (*PBHeartbeatResponse, error)
}

type kernelServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKernelServiceClient(cc grpc.ClientConnInterface) KernelServiceClient {
	return &kernelServiceClient{cc: cc}
}

func (c *kernelServiceClient) Register(ctx context.Context, req *PBRegisterRequest, opts ...grpc.CallOption) (*PBRegisterResponse, error) {
	resp := new(PBRegisterResponse)
	err := c.cc.Invoke(ctx, "/ASSCOR.v1.KernelService/Register", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *kernelServiceClient) Heartbeat(ctx context.Context, req *PBHeartbeatRequest, opts ...grpc.CallOption) (*PBHeartbeatResponse, error) {
	resp := new(PBHeartbeatResponse)
	err := c.cc.Invoke(ctx, "/ASSCOR.v1.KernelService/Heartbeat", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

type AgentServiceClient interface {
	GetSnapshot(ctx context.Context, req *PBSnapshotRequest, opts ...grpc.CallOption) (*PBSnapshotResponse, error)
	ExecuteCommand(ctx context.Context, req *PBCommandRequest, opts ...grpc.CallOption) (*PBCommandResponse, error)
	StreamLogs(ctx context.Context, opts ...grpc.CallOption) (AgentService_StreamLogsClient, error)
}

type AgentService_StreamLogsClient interface {
	Send(*PBLogEntry) error
	CloseAndRecv() (*PBAck, error)
	grpc.ClientStream
}

type agentServiceStreamLogsClient struct {
	grpc.ClientStream
}

func (x *agentServiceStreamLogsClient) Send(m *PBLogEntry) error {
	return x.ClientStream.SendMsg(m)
}

func (x *agentServiceStreamLogsClient) CloseAndRecv() (*PBAck, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(PBAck)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type agentServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAgentServiceClient(cc grpc.ClientConnInterface) AgentServiceClient {
	return &agentServiceClient{cc: cc}
}

func (c *agentServiceClient) GetSnapshot(ctx context.Context, req *PBSnapshotRequest, opts ...grpc.CallOption) (*PBSnapshotResponse, error) {
	resp := new(PBSnapshotResponse)
	err := c.cc.Invoke(ctx, "/ASSCOR.v1.AgentService/GetSnapshot", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *agentServiceClient) ExecuteCommand(ctx context.Context, req *PBCommandRequest, opts ...grpc.CallOption) (*PBCommandResponse, error) {
	resp := new(PBCommandResponse)
	err := c.cc.Invoke(ctx, "/ASSCOR.v1.AgentService/ExecuteCommand", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *agentServiceClient) StreamLogs(ctx context.Context, opts ...grpc.CallOption) (AgentService_StreamLogsClient, error) {
	stream, err := c.cc.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "StreamLogs",
		ServerStreams: false,
		ClientStreams: true,
	}, "/ASSCOR.v1.AgentService/StreamLogs", opts...)
	if err != nil {
		return nil, err
	}
	return &agentServiceStreamLogsClient{ClientStream: stream}, nil
}

type AgentService_StreamLogsServer interface {
	SendAndClose(*PBAck) error
	Recv() (*PBLogEntry, error)
	grpc.ServerStream
}

type agentServiceStreamLogsServer struct {
	grpc.ServerStream
}

func (x *agentServiceStreamLogsServer) SendAndClose(m *PBAck) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceStreamLogsServer) Recv() (*PBLogEntry, error) {
	m := new(PBLogEntry)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func GRPCStatus(err error) *status.Status {
	return status.Convert(err)
}

func GRPCError(code codes.Code, msg string) error {
	return status.Error(code, msg)
}

func ConvertPBCommandsToJSON(pbCmds []*PBCommand) []*Command {
	cmds := make([]*Command, len(pbCmds))
	for i, c := range pbCmds {
		cmds[i] = &Command{
			CommandId: c.CommandId,
			Command:   c.Command,
			Params:    c.Params,
			Signature: c.Signature,
		}
	}
	return cmds
}

var _ = io.EOF
