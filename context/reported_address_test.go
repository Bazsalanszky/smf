// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"net/netip"
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

const (
	testReportedV6 = "2001:db8:500:0:123:4567:89ab:cdef"
	testReportedV4 = "10.60.0.8"
	nilAddress     = "<nil>"
)

func reportedAddressOf(v4 net.IP, v6 bool) *UeIpAddr {
	addr := &UeIpAddr{Ip: v4}
	if v6 {
		prefix := netip.MustParsePrefix(firstTestPrefix)
		iid := testIid
		addr.Ipv6Prefix, addr.Ipv6Iid = &prefix, &iid
	}
	return addr
}

// The session is reported by its IPv4 address as before whenever it has an Ip, by its IPv6
// address when it has only IPv6.
func TestReportedAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr *UeIpAddr
		want string
	}{
		{nameIPv4, reportedAddressOf(net.ParseIP(testReportedV4).To4(), false), testReportedV4},
		{"IPv4, 16-byte form", reportedAddressOf(net.ParseIP(testReportedV4), false), testReportedV4},
		{"IPv4 released", reportedAddressOf(net.IPv4zero, false), "0.0.0.0"},
		{nameIPv6, reportedAddressOf(nil, true), testReportedV6},
		{nameIPv4v6, reportedAddressOf(net.ParseIP(testReportedV4).To4(), true), testReportedV4},
		{"none", &UeIpAddr{}, nilAddress},
		{"no address at all", nil, nilAddress},
	} {
		if got := tc.addr.ReportedAddress(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// An IPv6 session's Kafka event and session profile series carry its IPv6 address, where they
// carried "" and "<nil>".
func TestAnIPv6SessionIsReportedByItsIPv6Address(t *testing.T) {
	events := capturePublishedEvents(t)

	smContext := NewSMContext("imsi-208930000099981", 5)
	t.Cleanup(func() { RemoveSMContext(smContext.Ref) })
	smContext.PDUAddress = reportedAddressOf(nil, true)
	smContext.Snssai = models.NewSnssai(1)
	smContext.Tunnel = &UPTunnel{DataPathPool: DataPathPool{
		1: &DataPath{IsDefaultPath: true, FirstDPNode: &DataPathNode{UPF: &UPF{NodeID: *NewNodeID("10.90.0.1")}}},
	}}
	smContext.ChangeState(SmStateActive)

	if len(*events) == 0 || (*events)[len(*events)-1].Subscriber.IPAddress != testReportedV6 {
		t.Errorf("Kafka events %+v, want the last to carry %s", *events, testReportedV6)
	}
	// The label the session profile series was published with, and is deleted with.
	if smContext.activeIP != testReportedV6 {
		t.Errorf("session profile series published with ip %q, want %s", smContext.activeIP, testReportedV6)
	}

	// A session with no address is still exported without one.
	bare := NewSMContext("imsi-208930000099982", 5)
	t.Cleanup(func() { RemoveSMContext(bare.Ref) })
	bare.Snssai = models.NewSnssai(1)
	bare.PDUAddress = &UeIpAddr{}
	bare.PublishSmCtxtInfo()
	if got := (*events)[len(*events)-1].Subscriber.IPAddress; got != "" {
		t.Errorf("a session without an address was exported with %q", got)
	}
}
