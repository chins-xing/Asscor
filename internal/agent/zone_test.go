package agent

import (
	"net"
	"testing"
)

// A-7：zone 推断必须把 IPv6 链路本地/ULA 当私网，否则纯私网主机会被误判为 dmz。
func TestIsPublicAddress(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":        false,
		"172.16.0.1":      false,
		"192.168.30.60":   false,
		"127.0.0.1":       false,
		"169.254.1.1":     false,
		"fe80::1":         false, // IPv6 链路本地（旧实现会误判为公网 → dmz）
		"fd00::1":         false, // ULA
		"::1":             false,
		"8.8.8.8":         true,
		"2606:4700::1111": true,
	}
	for s, want := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("解析失败: %s", s)
		}
		if got := isPublicAddress(ip); got != want {
			t.Errorf("isPublicAddress(%s)=%v want %v", s, got, want)
		}
	}
}

// 纯私网 + 链路本地 IPv6 ⇒ internal（不是 dmz）。
func TestInferZonePrivateWithLinkLocalIsInternal(t *testing.T) {
	a := &Agent{}
	if got := a.inferZone([]string{"172.22.10.1", "fe80::1"}); got != "internal" {
		t.Fatalf("纯私网 + 链路本地应判 internal，got %q", got)
	}
	if got := a.inferZone([]string{"172.22.10.1", "8.8.8.8"}); got != "dmz" {
		t.Fatalf("私网 + 公网应判 dmz，got %q", got)
	}
	if got := a.inferZone([]string{"8.8.8.8"}); got != "public" {
		t.Fatalf("纯公网应判 public，got %q", got)
	}
}
