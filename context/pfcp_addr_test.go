// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/smf/factory"
)

// TestResolvePfcpAddr covers the PFCP address forms the configuration accepts.
// The IPv6 cases used to fail with "too many colons in address", which made
// InitSmfContext return nil so the SMF did not start.
func TestResolvePfcpAddr(t *testing.T) {
	const podIPEnv = "POD_IP"
	tests := []struct {
		name     string
		addr     string
		port     uint16
		env      map[string]string
		wantIP   net.IP
		wantPort int
		wantAddr string
	}{
		{
			name:     "POD_IP is an IPv6 address (helm on an IPv6 cluster)",
			addr:     podIPEnv,
			env:      map[string]string{podIPEnv: "2001:db8::5"},
			wantIP:   net.ParseIP("2001:db8::5"),
			wantPort: int(DefaultPfcpPort),
			wantAddr: "2001:db8::5",
		},
		{
			name:     "POD_IP is an IPv4 address",
			addr:     podIPEnv,
			env:      map[string]string{podIPEnv: "10.42.0.17"},
			wantIP:   net.ParseIP("10.42.0.17"),
			wantPort: int(DefaultPfcpPort),
			wantAddr: "10.42.0.17",
		},
		{
			name:     "IPv4 literal with explicit port",
			addr:     "192.0.2.1",
			port:     8806,
			wantIP:   net.ParseIP("192.0.2.1"),
			wantPort: 8806,
			wantAddr: "192.0.2.1",
		},
		{
			name:     "IPv6 literal",
			addr:     "2001:db8::6",
			wantIP:   net.ParseIP("2001:db8::6"),
			wantPort: int(DefaultPfcpPort),
			wantAddr: "2001:db8::6",
		},
		{
			name:     "bracketed IPv6 literal",
			addr:     "[2001:db8::7]",
			wantIP:   net.ParseIP("2001:db8::7"),
			wantPort: int(DefaultPfcpPort),
			wantAddr: "[2001:db8::7]",
		},
		{
			name:     "empty address defaults to 0.0.0.0",
			addr:     "",
			wantIP:   net.IPv4zero,
			wantPort: int(DefaultPfcpPort),
			wantAddr: "0.0.0.0",
		},
		{
			name:     "hostname",
			addr:     "localhost",
			wantPort: int(DefaultPfcpPort),
			wantAddr: "localhost",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			pfcp := &factory.PFCP{Addr: tc.addr, Port: tc.port}

			got, err := resolvePfcpAddr(pfcp)
			if err != nil {
				t.Fatalf("resolvePfcpAddr(%+v) failed: %v", factory.PFCP{Addr: tc.addr, Port: tc.port}, err)
			}
			if tc.wantIP != nil && !got.IP.Equal(tc.wantIP) {
				t.Errorf("IP = %v, want %v", got.IP, tc.wantIP)
			}
			if tc.wantIP == nil && !got.IP.IsLoopback() {
				t.Errorf("IP = %v, want a loopback address", got.IP)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
			if pfcp.Addr != tc.wantAddr {
				t.Errorf("pfcp.Addr = %q, want %q", pfcp.Addr, tc.wantAddr)
			}
			if int(pfcp.Port) != tc.wantPort {
				t.Errorf("pfcp.Port = %d, want %d", pfcp.Port, tc.wantPort)
			}
		})
	}
}
