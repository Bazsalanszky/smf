// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"errors"
	"net"
	"testing"
)

const (
	testV4 = "192.0.2.10"
	testV6 = "2001:db8::10"
)

// fakeDNS answers lookupIP from a table for the duration of a test. Names it does not know
// fail at once, so a test that ranges the UPF pool does not wait on the real resolver for
// names other tests registered.
func fakeDNS(t *testing.T, answers map[string][]string) {
	t.Helper()
	f := ipLookupFunc(func(_ context.Context, network, host string) ([]net.IP, error) {
		var ips []net.IP
		for _, s := range answers[host] {
			ip := net.ParseIP(s)
			switch {
			case network == "ip4" && ip.To4() == nil, network == "ip6" && ip.To4() != nil:
				continue
			}
			ips = append(ips, ip)
		}
		if len(ips) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return ips, nil
	})
	prev := ipLookupOverride.Swap(&f)
	t.Cleanup(func() { ipLookupOverride.Store(prev) })
}

// preferFamily sets N4PreferredFamily for the duration of a test.
func preferFamily(t *testing.T, f AddressFamily) {
	t.Helper()
	prev := AddressFamily(n4PreferredFamily.Load())
	SetN4PreferredFamily(f)
	t.Cleanup(func() { SetN4PreferredFamily(prev) })
}

// forgetHost drops a name from the SMF DNS cache when the test ends, so a later test (or a
// -count rerun) resolves it afresh.
func forgetHost(t *testing.T, hosts ...string) {
	t.Helper()
	t.Cleanup(func() {
		dnsHostIpCacheMu.Lock()
		defer dnsHostIpCacheMu.Unlock()
		for _, h := range hosts {
			delete(dnsHostIpCache, h)
			dnsHostIpGen[h]++
		}
	})
}

func TestParseAddressFamily(t *testing.T) {
	for in, want := range map[string]AddressFamily{
		"": AddressFamilyAuto, "auto": AddressFamilyAuto, "ipv4": AddressFamilyIPv4,
		"IPv4": AddressFamilyIPv4, "ipv6": AddressFamilyIPv6, " IPv6 ": AddressFamilyIPv6,
	} {
		got, err := ParseAddressFamily(in)
		if err != nil || got != want {
			t.Errorf("ParseAddressFamily(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"v6", "inet6", "dual"} {
		if _, err := ParseAddressFamily(in); err == nil {
			t.Errorf("ParseAddressFamily(%q) accepted an unknown family", in)
		}
	}
}

func TestSelectAddress(t *testing.T) {
	v4, v6, v6b := net.ParseIP(testV4), net.ParseIP(testV6), net.ParseIP("2001:db8::11")
	tests := []struct {
		name      string
		ips       []net.IP
		preferred AddressFamily
		want      net.IP
	}{
		{"auto prefers IPv4 even when the resolver put IPv6 first", []net.IP{v6, v4}, AddressFamilyAuto, v4},
		{"IPv4 preferred", []net.IP{v6, v4}, AddressFamilyIPv4, v4},
		{"IPv6 preferred", []net.IP{v4, v6}, AddressFamilyIPv6, v6},
		{"IPv4 preferred, only IPv6 available", []net.IP{v6}, AddressFamilyIPv4, v6},
		{"IPv6 preferred, only IPv4 available", []net.IP{v4.To4()}, AddressFamilyIPv6, v4},
		{"first of the family in resolver order", []net.IP{v4, v6b, v6}, AddressFamilyIPv6, v6b},
		{"empty answer", nil, AddressFamilyIPv4, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectAddress(tc.ips, tc.preferred)
			if !got.Equal(tc.want) {
				t.Fatalf("selectAddress = %v, want %v", got, tc.want)
			}
			if got != nil && len(got) != net.IPv6len {
				t.Errorf("selectAddress returned a %d-byte address; the DNS cache holds the 16-byte form", len(got))
			}
		})
	}
}

// An FQDN Node ID with both A and AAAA records resolves to the preferred family, whatever
// order the resolver answers in.
func TestResolveIPFollowsPreferredFamily(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"dual-a.upf.test": {testV6, testV4},
		"dual-b.upf.test": {testV6, testV4},
		"v6only.upf.test": {testV6},
	})
	forgetHost(t, "dual-a.upf.test", "dual-b.upf.test", "v6only.upf.test")

	preferFamily(t, AddressFamilyAuto)
	if ip, err := NewNodeID("dual-a.upf.test").ResolveIP(); err != nil || !ip.Equal(net.ParseIP(testV4)) {
		t.Errorf("default preference: ResolveIP = %v, %v; want %s", ip, err, testV4)
	}
	if ip, err := NewNodeID("v6only.upf.test").ResolveIP(); err != nil || !ip.Equal(net.ParseIP(testV6)) {
		t.Errorf("IPv6-only name: ResolveIP = %v, %v; want %s", ip, err, testV6)
	}

	SetN4PreferredFamily(AddressFamilyIPv6)
	if ip, err := NewNodeID("dual-b.upf.test").ResolveIP(); err != nil || !ip.Equal(net.ParseIP(testV6)) {
		t.Errorf("IPv6 preferred: ResolveIP = %v, %v; want %s", ip, err, testV6)
	}
	// The answer is cached: the cache is what every later resolution of the name reads.
	if ip, err := getDnsHostIp("dual-b.upf.test"); err != nil || !ip.Equal(net.ParseIP(testV6)) {
		t.Errorf("cached %v, %v; want %s", ip, err, testV6)
	}
}

// A name that does not resolve is an error, not 0.0.0.0. 0.0.0.0 looked like an address:
// two unresolvable UPFs compared equal, and the PFCP socket sent to it.
func TestResolveIPReportsFailureInsteadOfZeroAddress(t *testing.T) {
	fakeDNS(t, nil)
	forgetHost(t, "missing.upf.test")
	nodeID := NewNodeID("missing.upf.test")

	ip, err := nodeID.ResolveIP()
	var dnsErr *net.DNSError
	if err == nil || !errors.As(err, &dnsErr) {
		t.Fatalf("ResolveIP = %v, %v; want the resolver's error", ip, err)
	}
	if got := nodeID.ResolveNodeIdToIp(); got != nil {
		t.Errorf("ResolveNodeIdToIp = %v, want nil", got)
	}
	if _, err := (&NodeID{NodeIdType: 7}).ResolveIP(); err == nil {
		t.Error("ResolveIP accepted an unknown node id type")
	}
}

func TestNodeIDValueString(t *testing.T) {
	tests := []struct {
		nodeID NodeID
		want   string
	}{
		{*NewNodeID("10.0.0.1"), "10.0.0.1"},
		{NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP("10.0.0.1")}, "10.0.0.1"},
		{*NewNodeID("2001:db8::1"), "2001:db8::1"},
		{*NewNodeID("smf.example.org"), "smf.example.org"},
		{NodeID{}, "<nil>"},
	}
	for _, tc := range tests {
		if got := tc.nodeID.ValueString(); got != tc.want {
			t.Errorf("%+v.ValueString() = %q, want %q", tc.nodeID, got, tc.want)
		}
		if tc.nodeID.NodeIdValue == nil {
			continue
		}
		// Read back as the same Node ID, as the PFCP handlers read the IE with NewNodeID.
		if back := NewNodeID(tc.nodeID.ValueString()); !sameNode(*back, tc.nodeID) || back.NodeIdType != tc.nodeID.NodeIdType {
			t.Errorf("NewNodeID(%q) = %+v, not %+v", tc.nodeID.ValueString(), back, tc.nodeID)
		}
	}
}
