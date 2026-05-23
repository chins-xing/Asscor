package apiv1

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PBRegisterRequest struct {
	HostId   string `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
	Hostname string `protobuf:"bytes,2,opt,name=hostname,proto3" json:"hostname,omitempty"`
	Version  string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
}

func (m *PBRegisterRequest) Reset()         { *m = PBRegisterRequest{} }
func (m *PBRegisterRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBRegisterRequest) ProtoMessage()  {}

type PBRegisterResponse struct {
	Accepted      bool   `protobuf:"varint,1,opt,name=accepted,proto3" json:"accepted,omitempty"`
	SessionId     string `protobuf:"bytes,2,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	CaCertificate []byte `protobuf:"bytes,3,opt,name=ca_certificate,json=caCertificate,proto3" json:"ca_certificate,omitempty"`
}

func (m *PBRegisterResponse) Reset()         { *m = PBRegisterResponse{} }
func (m *PBRegisterResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBRegisterResponse) ProtoMessage()  {}

type PBHeartbeatRequest struct {
	HostId    string              `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
	SessionId string              `protobuf:"bytes,2,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Result    *PBAssessmentResult `protobuf:"bytes,3,opt,name=result,proto3" json:"result,omitempty"`
	Packages  []string            `protobuf:"bytes,5,rep,name=packages,proto3" json:"packages,omitempty"`
}

func (m *PBHeartbeatRequest) Reset()         { *m = PBHeartbeatRequest{} }
func (m *PBHeartbeatRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBHeartbeatRequest) ProtoMessage()  {}

type PBHeartbeatResponse struct {
	Ok                bool                `protobuf:"varint,1,opt,name=ok,proto3" json:"ok,omitempty"`
	ThreatCoefficient float64             `protobuf:"fixed64,2,opt,name=threat_coefficient,json=threatCoefficient,proto3" json:"threat_coefficient,omitempty"`
	PendingCommands   []*PBCommand        `protobuf:"bytes,3,rep,name=pending_commands,json=pendingCommands,proto3" json:"pending_commands,omitempty"`
	AssessmentResult  *PBAssessmentResult `protobuf:"bytes,4,opt,name=assessment_result,json=assessmentResult,proto3" json:"assessment_result,omitempty"`
}

func (m *PBHeartbeatResponse) Reset()         { *m = PBHeartbeatResponse{} }
func (m *PBHeartbeatResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBHeartbeatResponse) ProtoMessage()  {}

type PBAssessmentResult struct {
	FinalScore   float64            `protobuf:"fixed64,1,opt,name=final_score,json=finalScore,proto3" json:"final_score,omitempty"`
	Acceptable   bool               `protobuf:"varint,2,opt,name=acceptable,proto3" json:"acceptable,omitempty"`
	DomainScores map[string]float64 `protobuf:"bytes,3,rep,name=domain_scores,json=domainScores,proto3" json:"domain_scores,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"fixed64,2,opt,name=value,proto3"`
	Checks       []*PBCheckResult   `protobuf:"bytes,4,rep,name=checks,proto3" json:"checks,omitempty"`
}

func (m *PBAssessmentResult) Reset()         { *m = PBAssessmentResult{} }
func (m *PBAssessmentResult) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBAssessmentResult) ProtoMessage()  {}

type PBCheckResult struct {
	CheckId string  `protobuf:"bytes,1,opt,name=check_id,json=checkId,proto3" json:"check_id,omitempty"`
	Domain  string  `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
	Passed  bool    `protobuf:"varint,3,opt,name=passed,proto3" json:"passed,omitempty"`
	Delta   float64 `protobuf:"fixed64,4,opt,name=delta,proto3" json:"delta,omitempty"`
	Detail  string  `protobuf:"bytes,5,opt,name=detail,proto3" json:"detail,omitempty"`
}

func (m *PBCheckResult) Reset()         { *m = PBCheckResult{} }
func (m *PBCheckResult) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBCheckResult) ProtoMessage()  {}

type PBCommand struct {
	CommandId string            `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	Command   string            `protobuf:"bytes,2,opt,name=command,proto3" json:"command,omitempty"`
	Params    map[string]string `protobuf:"bytes,3,rep,name=params,proto3" json:"params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Signature []byte            `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *PBCommand) Reset()         { *m = PBCommand{} }
func (m *PBCommand) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBCommand) ProtoMessage()  {}

type PBCommandRequest struct {
	HostId    string            `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
	CommandId string            `protobuf:"bytes,2,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	Command   string            `protobuf:"bytes,3,opt,name=command,proto3" json:"command,omitempty"`
	Params    map[string]string `protobuf:"bytes,4,rep,name=params,proto3" json:"params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Signature []byte            `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *PBCommandRequest) Reset()         { *m = PBCommandRequest{} }
func (m *PBCommandRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBCommandRequest) ProtoMessage()  {}

type PBCommandResponse struct {
	CommandId string `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	Success   bool   `protobuf:"varint,2,opt,name=success,proto3" json:"success,omitempty"`
	Output    string `protobuf:"bytes,3,opt,name=output,proto3" json:"output,omitempty"`
}

func (m *PBCommandResponse) Reset()         { *m = PBCommandResponse{} }
func (m *PBCommandResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBCommandResponse) ProtoMessage()  {}

type PBSnapshotRequest struct {
	HostId string `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
}

func (m *PBSnapshotRequest) Reset()         { *m = PBSnapshotRequest{} }
func (m *PBSnapshotRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBSnapshotRequest) ProtoMessage()  {}

type PBSnapshotResponse struct {
	HostId string             `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
	Result *PBAssessmentResult `protobuf:"bytes,2,opt,name=result,proto3" json:"result,omitempty"`
}

func (m *PBSnapshotResponse) Reset()         { *m = PBSnapshotResponse{} }
func (m *PBSnapshotResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBSnapshotResponse) ProtoMessage()  {}

type PBLogEntry struct {
	HostId    string `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty"`
	Timestamp int64  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Level     string `protobuf:"bytes,3,opt,name=level,proto3" json:"level,omitempty"`
	Message   string `protobuf:"bytes,4,opt,name=message,proto3" json:"message,omitempty"`
}

func (m *PBLogEntry) Reset()         { *m = PBLogEntry{} }
func (m *PBLogEntry) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBLogEntry) ProtoMessage()  {}

type PBAck struct {
	Ok bool `protobuf:"varint,1,opt,name=ok,proto3" json:"ok,omitempty"`
}

func (m *PBAck) Reset()         { *m = PBAck{} }
func (m *PBAck) String() string { return fmt.Sprintf("%+v", *m) }
func (m *PBAck) ProtoMessage()  {}

func ConvertAssessmentResultToPB(r *AssessmentResult) *PBAssessmentResult {
	if r == nil {
		return nil
	}
	pb := &PBAssessmentResult{
		FinalScore:   r.FinalScore,
		Acceptable:   r.Acceptable,
		DomainScores: r.DomainScores,
	}
	for _, c := range r.Checks {
		pb.Checks = append(pb.Checks, &PBCheckResult{
			CheckId: c.CheckId,
			Domain:  c.Domain,
			Passed:  c.Passed,
			Delta:   c.Delta,
			Detail:  c.Detail,
		})
	}
	return pb
}

func ConvertPBToAssessmentResult(pb *PBAssessmentResult) *AssessmentResult {
	if pb == nil {
		return nil
	}
	r := &AssessmentResult{
		FinalScore:   pb.FinalScore,
		Acceptable:   pb.Acceptable,
		DomainScores: pb.DomainScores,
	}
	for _, c := range pb.Checks {
		r.Checks = append(r.Checks, &CheckResult{
			CheckId: c.CheckId,
			Domain:  c.Domain,
			Passed:  c.Passed,
			Delta:   c.Delta,
			Detail:  c.Detail,
		})
	}
	return r
}

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
		ServiceName: "argus.v1.KernelService",
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
						FullMethod: "/argus.v1.KernelService/Register",
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
						FullMethod: "/argus.v1.KernelService/Heartbeat",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(KernelServiceServer).Heartbeat(ctx, req.(*PBHeartbeatRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "api/v1/argus.proto",
	}
	s.RegisterService(desc, srv)
}

func RegisterAgentServiceServer(s grpc.ServiceRegistrar, srv AgentServiceServer) {
	desc := &grpc.ServiceDesc{
		ServiceName: "argus.v1.AgentService",
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
						FullMethod: "/argus.v1.AgentService/GetSnapshot",
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
						FullMethod: "/argus.v1.AgentService/ExecuteCommand",
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
				ServerStreams:  false,
				ClientStreams:  true,
			},
		},
		Metadata: "api/v1/argus.proto",
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
	err := c.cc.Invoke(ctx, "/argus.v1.KernelService/Register", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *kernelServiceClient) Heartbeat(ctx context.Context, req *PBHeartbeatRequest, opts ...grpc.CallOption) (*PBHeartbeatResponse, error) {
	resp := new(PBHeartbeatResponse)
	err := c.cc.Invoke(ctx, "/argus.v1.KernelService/Heartbeat", req, resp, opts...)
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
	err := c.cc.Invoke(ctx, "/argus.v1.AgentService/GetSnapshot", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *agentServiceClient) ExecuteCommand(ctx context.Context, req *PBCommandRequest, opts ...grpc.CallOption) (*PBCommandResponse, error) {
	resp := new(PBCommandResponse)
	err := c.cc.Invoke(ctx, "/argus.v1.AgentService/ExecuteCommand", req, resp, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *agentServiceClient) StreamLogs(ctx context.Context, opts ...grpc.CallOption) (AgentService_StreamLogsClient, error) {
	stream, err := c.cc.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "StreamLogs",
		ServerStreams:  false,
		ClientStreams:  true,
	}, "/argus.v1.AgentService/StreamLogs", opts...)
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
