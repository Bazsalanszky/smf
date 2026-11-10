// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

func ipNet(s string) *net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

// The address the SMF gives the UPF adapter: IPv4 first, as before, and an IPv6 address on a
// host that has no IPv4 one, where it used to give none.
func TestFirstLocalIP(t *testing.T) {
	tests := []struct {
		name  string
		addrs []net.Addr
		want  string
	}{
		{"IPv4 host", []net.Addr{ipNet("127.0.0.1/8"), ipNet("10.42.0.17/24")}, "10.42.0.17"},
		{"dual-stack host keeps IPv4", []net.Addr{ipNet("::1/128"), ipNet("2001:db8:600::17/64"), ipNet("10.42.0.17/24")}, "10.42.0.17"},
		{"IPv6-only host", []net.Addr{ipNet("::1/128"), ipNet("fe80::1/64"), ipNet("2001:db8:600::17/64")}, "2001:db8:600::17"},
		{"loopback only", []net.Addr{ipNet("127.0.0.1/8"), ipNet("::1/128")}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstLocalIP(tc.addrs); got != tc.want {
				t.Errorf("firstLocalIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// With one N4 address, that address is what the adapter relays to: it is the one the PFCP socket
// is bound to.
func TestAdapterSmfIPIsTheN4Address(t *testing.T) {
	self := smf_context.SMF_Self()
	prev := self.N4Addrs
	t.Cleanup(func() { self.N4Addrs = prev })

	self.N4Addrs = smf_context.N4Addrs{IPv6: net.ParseIP("2001:db8:640::5")}
	if got := adapterSmfIP(); got != "2001:db8:640::5" {
		t.Errorf("adapterSmfIP = %q, want the N4 address 2001:db8:640::5", got)
	}
}
