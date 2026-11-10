// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "IPv4 wildcard", host: "0.0.0.0", port: 29502, want: "0.0.0.0:29502"},
		{name: "IPv4 address", host: "192.0.2.10", port: 8805, want: "192.0.2.10:8805"},
		{name: "hostname", host: "smf.sdcore.svc.cluster.local", port: 29502, want: "smf.sdcore.svc.cluster.local:29502"},
		{name: "empty host", host: "", port: 29502, want: ":29502"},
		{name: "IPv6 wildcard", host: "::", port: 29502, want: "[::]:29502"},
		{name: "IPv6 address", host: "2001:db8::10", port: 8805, want: "[2001:db8::10]:8805"},
		{name: "IPv6 link-local with zone", host: "fe80::1%eth0", port: 8805, want: "[fe80::1%eth0]:8805"},
		{name: "already bracketed IPv6", host: "[2001:db8::11]", port: 9092, want: "[2001:db8::11]:9092"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HostPort(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("HostPort(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
			// The result must split back into the unbracketed host and the port.
			wantHost := strings.TrimSuffix(strings.TrimPrefix(tc.host, "["), "]")
			host, gotPort, err := net.SplitHostPort(got)
			if err != nil {
				t.Fatalf("net.SplitHostPort(%q) failed: %v", got, err)
			}
			if host != wantHost || gotPort != strconv.Itoa(tc.port) {
				t.Fatalf("net.SplitHostPort(%q) = (%q, %q), want (%q, %q)", got, host, gotPort, wantHost, strconv.Itoa(tc.port))
			}
		})
	}
}

// TestHostPortKeepsLegacyFormat checks that every non-IPv6 host gives exactly
// the string the previous fmt.Sprintf("%s:%d") produced.
func TestHostPortKeepsLegacyFormat(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "", "localhost", "upf"} {
		for _, port := range []int{29502, 8805, 9092, 0} {
			if got, legacy := HostPort(host, port), fmt.Sprintf("%s:%d", host, port); got != legacy {
				t.Errorf("HostPort(%q, %d) = %q, want legacy %q", host, port, got, legacy)
			}
		}
	}
}
