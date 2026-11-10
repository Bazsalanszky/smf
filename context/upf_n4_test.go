// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/openapi/v2/nfConfigApi"
)

// registerUPF puts a UPF in the pool for the duration of a test.
func registerUPF(t *testing.T, nodeID string) *UPF {
	t.Helper()
	upf := NewUPF(NewNodeID(nodeID), nil)
	t.Cleanup(func() { upfPool.Delete(upf.UUID()) })
	return upf
}

// Two IPv6 UPFs are two UPFs. Matching an FQDN against an IP Node ID compared the To4() of
// both addresses, which is nil for any IPv6 address, so every IPv6 UPF matched the first
// one the pool happened to range over.
func TestRetrieveUPFTellsIPv6UPFsApart(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"upf-a.v6.test": {"2001:db8:1::a"},
		"upf-b.v6.test": {"2001:db8:1::b"},
	})
	forgetHost(t, "upf-a.v6.test", "upf-b.v6.test")

	t.Run("FQDN UPFs, looked up by address", func(t *testing.T) {
		a := registerUPF(t, "upf-a.v6.test")
		b := registerUPF(t, "upf-b.v6.test")
		for want, by := range map[*UPF]string{a: "2001:db8:1::a", b: "2001:db8:1::b"} {
			if got := RetrieveUPFNodeByNodeID(*NewNodeID(by)); got != want {
				t.Errorf("RetrieveUPFNodeByNodeID(%s) = %v, want %s", by, describe(got), want.NodeID.ValueString())
			}
		}
		if got := RetrieveUPFNodeByNodeID(*NewNodeID("2001:db8:1::c")); got != nil {
			t.Errorf("an unknown IPv6 address matched %s", describe(got))
		}
	})

	t.Run("IP UPFs, looked up by name", func(t *testing.T) {
		a := registerUPF(t, "2001:db8:1::a")
		b := registerUPF(t, "2001:db8:1::b")
		for want, by := range map[*UPF]string{a: "upf-a.v6.test", b: "upf-b.v6.test"} {
			if got := RetrieveUPFNodeByNodeID(*NewNodeID(by)); got != want {
				t.Errorf("RetrieveUPFNodeByNodeID(%s) = %v, want %s", by, describe(got), want.NodeID.ValueString())
			}
		}
	})

	t.Run("IP UPFs, looked up by IP", func(t *testing.T) {
		a := registerUPF(t, "2001:db8:2::a")
		b := registerUPF(t, "2001:db8:2::b")
		if got := RetrieveUPFNodeByNodeID(*NewNodeID("2001:db8:2::b")); got != b {
			t.Errorf("got %v, want %s", describe(got), b.NodeID.ValueString())
		}
		if got := RetrieveUPFNodeByNodeID(*NewNodeID("2001:db8:2::a")); got != a {
			t.Errorf("got %v, want %s", describe(got), a.NodeID.ValueString())
		}
	})

	t.Run("remove takes out the matching one", func(t *testing.T) {
		a := registerUPF(t, "upf-a.v6.test")
		b := registerUPF(t, "upf-b.v6.test")
		if !RemoveUPFNodeByNodeID(*NewNodeID("2001:db8:1::b")) {
			t.Fatal("RemoveUPFNodeByNodeID found nothing")
		}
		if _, ok := upfPool.Load(b.UUID()); ok {
			t.Error("UPF B is still registered")
		}
		if _, ok := upfPool.Load(a.UUID()); !ok {
			t.Error("UPF A was removed instead of B")
		}
	})
}

func describe(upf *UPF) string {
	if upf == nil {
		return "nil"
	}
	return upf.NodeID.ValueString()
}

func TestSameNode(t *testing.T) {
	fakeDNS(t, map[string][]string{"upf.same.test": {"192.0.2.7"}})
	forgetHost(t, "upf.same.test", "gone.same.test")

	v4 := *NewNodeID("192.0.2.7")
	tests := []struct {
		name string
		a, b NodeID
		want bool
	}{
		{"IPv4, 4-byte and 16-byte forms", v4, NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP("192.0.2.7")}, true},
		{"different IPv4", v4, *NewNodeID("192.0.2.8"), false},
		{"different IPv6", *NewNodeID("2001:db8::1"), *NewNodeID("2001:db8::2"), false},
		{"same IPv6", *NewNodeID("2001:db8::1"), *NewNodeID("2001:db8:0::1"), true},
		{
			"an IPv4 and an IPv6 Node ID are different nodes", v4,
			NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: net.ParseIP("::ffff:192.0.2.7")},
			false,
		},
		{"FQDN and its address", *NewNodeID("upf.same.test"), v4, true},
		{"same FQDN", *NewNodeID("upf.same.test"), *NewNodeID("upf.same.test"), true},
		{"unresolvable FQDN and 0.0.0.0", *NewNodeID("gone.same.test"), *NewNodeID("0.0.0.0"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameNode(tc.a, tc.b); got != tc.want {
				t.Errorf("sameNode(%s, %s) = %t, want %t", tc.a.ValueString(), tc.b.ValueString(), got, tc.want)
			}
		})
	}
}

func TestTransportIP(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"n3-dual.test": {"2001:db8:630::3", "192.0.2.3"},
		"n3-v6.test":   {"2001:db8:630::4"},
	})
	const n3V4, n3V6 = "192.0.2.31", "2001:db8:630::1"
	v4, v6 := net.ParseIP(n3V4), net.ParseIP(n3V6)
	dual := UPFInterfaceInfo{IPv4EndPointAddresses: []net.IP{v4}, IPv6EndPointAddresses: []net.IP{v6}}
	v4only := UPFInterfaceInfo{IPv4EndPointAddresses: []net.IP{v4}}
	v6only := UPFInterfaceInfo{IPv6EndPointAddresses: []net.IP{v6}}
	fqdnDual := UPFInterfaceInfo{EndpointFQDN: "n3-dual.test"}
	fqdnV6 := UPFInterfaceInfo{EndpointFQDN: "n3-v6.test"}

	tests := []struct {
		name   string
		iface  UPFInterfaceInfo
		family AddressFamily
		want   string // "" = error
	}{
		{"dual, auto takes IPv4", dual, AddressFamilyAuto, n3V4},
		{"dual, IPv4", dual, AddressFamilyIPv4, n3V4},
		{"dual, IPv6 override", dual, AddressFamilyIPv6, n3V6},
		{"IPv4 only, auto", v4only, AddressFamilyAuto, n3V4},
		{"IPv4 only, IPv6 override", v4only, AddressFamilyIPv6, ""},
		{"IPv6 only, auto takes what there is", v6only, AddressFamilyAuto, n3V6},
		{"IPv6 only, IPv4 override", v6only, AddressFamilyIPv4, ""},
		{"FQDN with both, auto", fqdnDual, AddressFamilyAuto, "192.0.2.3"},
		{"FQDN with both, IPv6 override", fqdnDual, AddressFamilyIPv6, "2001:db8:630::3"},
		{"IPv6-only FQDN, auto", fqdnV6, AddressFamilyAuto, "2001:db8:630::4"},
		{"IPv6-only FQDN, IPv4 override", fqdnV6, AddressFamilyIPv4, ""},
		{"nothing configured", UPFInterfaceInfo{}, AddressFamilyAuto, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.iface.TransportIP(tc.family)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("TransportIP = %v, want an error", got)
				}
				return
			}
			if err != nil || !got.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("TransportIP = %v, %v; want %s", got, err, tc.want)
			}
			// The NGAP TransportLayerAddress is built from the length of this slice.
			wantLen := net.IPv6len
			if got.To4() != nil {
				wantLen = net.IPv4len
			}
			if len(got) != wantLen {
				t.Errorf("TransportIP returned %d bytes for %s, want %d", len(got), got, wantLen)
			}
		})
	}
}

// The per-UPF override reaches the UPF record, and an FQDN UPF's N3/N9 endpoint is resolved in
// the override family rather than the N4 one.
func TestUpfTransportFamilyOverride(t *testing.T) {
	fakeDNS(t, map[string][]string{"upf-ovr.test": {"192.0.2.44", "2001:db8:630::44"}})
	forgetHost(t, "upf-ovr.test")
	preferFamily(t, AddressFamilyAuto)

	prev := smfContext.UPFTransportFamily
	smfContext.UPFTransportFamily = map[string]AddressFamily{"upf-ovr.test": AddressFamilyIPv6}
	t.Cleanup(func() { smfContext.UPFTransportFamily = prev })

	upi := BuildUserPlaneInformationFromSessionManagement(nil, []nfConfigApi.SessionManagement{
		makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "upf-ovr.test", []string{"gnb-ovr"}),
		makeTestSessionConfig("slice2", "001", "01", "1", "010102", "internet", "10.0.1.0/24", "192.0.2.45", []string{"gnb-ovr"}),
	})
	overridden := upi.UPFs["upf-ovr.test"].UPF
	plain := upi.UPFs["192.0.2.45"].UPF
	t.Cleanup(func() {
		upfPool.Delete(overridden.UUID())
		upfPool.Delete(plain.UUID())
	})

	if got := overridden.GetTransportFamily(); got != AddressFamilyIPv6 {
		t.Errorf("overridden UPF transport family = %v, want ipv6", got)
	}
	if got := plain.GetTransportFamily(); got != AddressFamilyAuto {
		t.Errorf("UPF without an override has transport family %v, want auto", got)
	}
	// N4 resolves the name IPv4 first ...
	if ip := overridden.NodeID.ResolveNodeIdToIp(); !ip.Equal(net.ParseIP("192.0.2.44")) {
		t.Errorf("N4 address = %v, want 192.0.2.44", ip)
	}
	// ... and N3 uses the override.
	ip, err := overridden.N3Interfaces[0].TransportIP(overridden.GetTransportFamily())
	if err != nil || !ip.Equal(net.ParseIP("2001:db8:630::44")) {
		t.Errorf("N3 address = %v, %v; want 2001:db8:630::44", ip, err)
	}
	ip, err = plain.N3Interfaces[0].TransportIP(plain.GetTransportFamily())
	if err != nil || !ip.Equal(net.ParseIP("192.0.2.45")) {
		t.Errorf("N3 address of the UPF without an override = %v, %v; want 192.0.2.45", ip, err)
	}
}

// Until Phase 2, a GTP-U outer header is IPv4 only, so an IPv6 N9 peer is an error rather than
// an outer header naming 0.0.0.0.
func TestN9PeerIPv4RefusesIPv6(t *testing.T) {
	upf := &UPF{TransportFamily: AddressFamilyIPv6}
	iface := &UPFInterfaceInfo{
		IPv4EndPointAddresses: []net.IP{net.ParseIP("192.0.2.9")},
		IPv6EndPointAddresses: []net.IP{net.ParseIP("2001:db8::9")},
	}
	if ip, err := n9PeerIPv4(iface, upf); err == nil {
		t.Errorf("n9PeerIPv4 = %v, want an error for an IPv6 peer", ip)
	}
	upf.TransportFamily = AddressFamilyAuto
	if ip, err := n9PeerIPv4(iface, upf); err != nil || !ip.Equal(net.ParseIP("192.0.2.9")) {
		t.Errorf("n9PeerIPv4 = %v, %v; want 192.0.2.9", ip, err)
	}
	if _, err := n9PeerIPv4(nil, upf); err == nil {
		t.Error("n9PeerIPv4 accepted a missing interface")
	}
}
