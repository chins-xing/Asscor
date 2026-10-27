//go:build comms

package comms

import "testing"

// TestAddrConflicts 钉住 2026-10-27 的端口冲突故障：
// `[grpc] listen_addr` 与主 `--listen` 同端口时，gRPC 每次启动都 bind 失败、
// 只留一行 WARN 后静默 `grpc=false`。启动前必须能识别这种冲突。
func TestAddrConflicts(t *testing.T) {
	cases := []struct {
		name     string
		primary  string
		grpcAddr string
		want     bool
	}{
		{"完全相同", ":50051", ":50051", true},
		{"通配主机不同写法", "0.0.0.0:50051", ":50051", true},
		{"IPv6 通配", "[::]:50051", ":50051", true},
		{"默认不同端口", ":50051", ":50052", false},
		{"不同主机同端口", "127.0.0.1:50051", "192.168.30.50:50051", false},
		{"显式同主机同端口", "192.168.30.50:50051", "192.168.30.50:50051", true},
		{"空地址不判冲突", "", ":50051", false},
		{"纯端口写法", "50051", ":50051", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := AddrConflicts(c.primary, c.grpcAddr); got != c.want {
				t.Fatalf("AddrConflicts(%q, %q) = %v, want %v", c.primary, c.grpcAddr, got, c.want)
			}
		})
	}
}

// 默认配置必须与 JSONRPC 默认端口不同，否则开箱即冲突。
func TestDefaultGRPCListenAddrIsNotPrimary(t *testing.T) {
	cfg := DefaultGRPCServerConfig()
	if AddrConflicts(":50051", cfg.ListenAddr) {
		t.Fatalf("默认 gRPC 监听地址 %q 与 JSONRPC 默认 :50051 冲突", cfg.ListenAddr)
	}
}
