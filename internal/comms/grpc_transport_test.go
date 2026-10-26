//go:build comms

package comms

import (
	"encoding/json"
	"testing"

	apiv1 "github.com/chins-xing/asscor/api/v1"
)

// TestJSONCodecRoundTripsHeartbeat 钉住 gRPC 传输层能编解码 PBHeartbeatRequest。
//
// 之前默认 proto codec 编不了手写 PB 结构（没有 ProtoReflect），gRPC 通道实际不可用；
// 现在用 JSON codec，且心跳必须带上 NetworkInfo/InstalledCPEs/SecureMode。
func TestJSONCodecRoundTripsHeartbeat(t *testing.T) {
	in := &apiv1.PBHeartbeatRequest{
		HostId:        "domA-web",
		SessionId:     "sess-x",
		Packages:      []string{"openssh-server", "nftables"},
		InstalledCPEs: []string{"cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"},
		NetworkInfo: &apiv1.NetworkInfo{
			LocalIPs:    []string{"172.22.10.11"},
			Subnets:     []string{"172.22.10.0/24"},
			Gateways:    []string{"172.22.10.1"},
			NetworkZone: "internal",
		},
		SecureMode: &apiv1.SecureModeReport{Password: "ephemeral", Locked: false},
	}

	data, err := jsonCodec{}.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := &apiv1.PBHeartbeatRequest{}
	if err := (jsonCodec{}).Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.HostId != in.HostId || out.SessionId != in.SessionId {
		t.Fatalf("身份字段丢失: %+v", out)
	}
	if out.NetworkInfo == nil {
		t.Fatal("NetworkInfo 在 gRPC 编解码后丢失")
	}
	if len(out.NetworkInfo.Subnets) != 1 || out.NetworkInfo.Subnets[0] != "172.22.10.0/24" {
		t.Errorf("Subnets 丢失/变化: %+v", out.NetworkInfo.Subnets)
	}
	if len(out.InstalledCPEs) != 1 {
		t.Errorf("InstalledCPEs 丢失: %+v", out.InstalledCPEs)
	}
	if out.SecureMode == nil || out.SecureMode.Password != "ephemeral" {
		t.Errorf("SecureMode 丢失: %+v", out.SecureMode)
	}
}

// TestHeartbeatConversionPreservesFields 钉住"PB ↔ 内部请求"的逐字段搬运：
// 任何新增字段漏搬都会让 gRPC agent 静默丢数据（正是本次缺陷）。
func TestHeartbeatConversionPreservesFields(t *testing.T) {
	orig := &apiv1.HeartbeatRequest{
		HostId:        "domB-web",
		SessionId:     "sess-y",
		Packages:      []string{"nginx"},
		InstalledCPEs: []string{"cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"},
		NetworkInfo: &apiv1.NetworkInfo{
			LocalIPs:    []string{"172.23.10.11"},
			Subnets:     []string{"172.23.10.0/24"},
			NetworkZone: "internal",
		},
		SecureMode: &apiv1.SecureModeReport{Locked: true},
	}

	pb := heartbeatRequestToPB(orig)
	// PB 必须真的携带这些字段（结构体层面），否则序列化后就是空的。
	if pb.NetworkInfo == nil || len(pb.NetworkInfo.Subnets) != 1 {
		t.Fatalf("PB 请求未携带 NetworkInfo: %+v", pb.NetworkInfo)
	}
	if len(pb.InstalledCPEs) != 1 {
		t.Fatalf("PB 请求未携带 InstalledCPEs: %+v", pb.InstalledCPEs)
	}
	if pb.SecureMode == nil || !pb.SecureMode.Locked {
		t.Fatalf("PB 请求未携带 SecureMode: %+v", pb.SecureMode)
	}

	back := pbToHeartbeatRequest(pb)
	if back.HostId != orig.HostId || back.SessionId != orig.SessionId {
		t.Errorf("身份字段不一致: %+v", back)
	}
	if back.NetworkInfo == nil || back.NetworkInfo.Subnets[0] != "172.23.10.0/24" {
		t.Errorf("NetworkInfo 往返丢失: %+v", back.NetworkInfo)
	}
	if len(back.InstalledCPEs) != 1 || back.InstalledCPEs[0] != orig.InstalledCPEs[0] {
		t.Errorf("InstalledCPEs 往返丢失: %+v", back.InstalledCPEs)
	}
	if back.SecureMode == nil || !back.SecureMode.Locked {
		t.Errorf("SecureMode 往返丢失: %+v", back.SecureMode)
	}
	if len(back.Packages) != 1 || back.Packages[0] != "nginx" {
		t.Errorf("Packages 往返丢失: %+v", back.Packages)
	}
}

// 编码器必须能作为 gRPC encoding.Codec 使用（Name/Marshal/Unmarshal 三件套）。
func TestJSONCodecName(t *testing.T) {
	if got := (jsonCodec{}).Name(); got != "json" {
		t.Errorf("codec name = %q", got)
	}
	var _ interface {
		Marshal(interface{}) ([]byte, error)
		Unmarshal([]byte, interface{}) error
	} = jsonCodec{}
	if _, err := json.Marshal(json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
}
