// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"net"
	"testing"
)

func TestKafkaBrokerAddr(t *testing.T) {
	const defaultBroker = "kafka:9092"
	tests := []struct {
		name string
		uri  string
		port int
		want string
	}{
		{name: "nothing configured", uri: "", port: 0, want: defaultBroker},
		{name: "only port configured", uri: "", port: 9093, want: defaultBroker},
		{name: "only host configured", uri: "broker.example", port: 0, want: defaultBroker},
		{name: "IPv4 address", uri: "192.0.2.20", port: 9092, want: "192.0.2.20:9092"},
		{name: "hostname", uri: "kafka-headless.aether.svc", port: 9094, want: "kafka-headless.aether.svc:9094"},
		{name: "IPv6 address", uri: "2001:db8::20", port: 9092, want: "[2001:db8::20]:9092"},
		{name: "already bracketed IPv6", uri: "[2001:db8::21]", port: 9092, want: "[2001:db8::21]:9092"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kafkaBrokerAddr(tc.uri, tc.port)
			if got != tc.want {
				t.Fatalf("kafkaBrokerAddr(%q, %d) = %q, want %q", tc.uri, tc.port, got, tc.want)
			}
			if _, _, err := net.SplitHostPort(got); err != nil {
				t.Fatalf("net.SplitHostPort(%q) failed: %v", got, err)
			}
		})
	}
}

// TestKafkaBrokerAddrKeepsLegacyFormat checks that a configured non-IPv6 broker
// gives exactly the string the previous fmt.Sprintf("%s:%d") produced.
func TestKafkaBrokerAddrKeepsLegacyFormat(t *testing.T) {
	for _, uri := range []string{"kafka", "10.0.0.5", "127.0.0.1", "broker.sdcore.svc.cluster.local"} {
		for _, port := range []int{9092, 29092} {
			if got, legacy := kafkaBrokerAddr(uri, port), fmt.Sprintf("%s:%d", uri, port); got != legacy {
				t.Errorf("kafkaBrokerAddr(%q, %d) = %q, want legacy %q", uri, port, got, legacy)
			}
		}
	}
}
