// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/smf/context"
)

const (
	pduIPv4   = nasMessage.PDUSessionTypeIPv4
	pduIPv6   = nasMessage.PDUSessionTypeIPv6
	pduIPv4v6 = nasMessage.PDUSessionTypeIPv4IPv6
	ueV4      = "172.250.0.9"
	ueV6Pfx   = "2001:db8:500:7::/64"
)

// activatedUEIPAddresses activates the default uplink and downlink PDR of a session on upf and
// returns the UE IP Address IE of each.
func activatedUEIPAddresses(t *testing.T, smContext *context.SMContext, upf *context.UPF) (ul, dl *context.UEIPAddress) {
	t.Helper()
	smContext.Dnn = testDnn
	smContext.Tunnel = &context.UPTunnel{ANInformation: struct {
		IPAddress net.IP
		TEID      uint32
	}{IPAddress: net.IP{10, 0, 0, 1}, TEID: 12345}}

	up := uplinkNode(upf)
	if err := up.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}
	down := downlinkNode(upf)
	if err := down.ActivateDlLinkPdr(smContext, &context.QER{}, 10, &context.DataPath{FirstDPNode: down}); err != nil {
		t.Fatalf("ActivateDlLinkPdr: %v", err)
	}
	return up.UpLinkTunnel.PDR[defaultPdr].PDI.UEIPAddress, down.DownLinkTunnel.PDR[defaultPdr].PDI.UEIPAddress
}

func ueAddressOf(typ uint8) *context.UeIpAddr {
	addr := &context.UeIpAddr{}
	if typ != pduIPv6 {
		addr.Ip = net.ParseIP(ueV4).To4()
	}
	if typ != pduIPv4 {
		prefix := netip.MustParsePrefix(ueV6Pfx)
		iid := context.InterfaceIdentifier{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
		addr.Ipv6Prefix, addr.Ipv6Iid = &prefix, &iid
	}
	return addr
}

// The UE IP Address IE of each PDR, by PDU session type and by whether the UPF allocates IPv4
// addresses: the IPv4 part as before, CHV4 or the address; the IPv6 part the SMF's /64 with
// IP6PL and the UE's identifier, never CHV6; S/D on the downlink PDR of a session with IPv6.
func TestUEIPAddressIEByPDUSessionType(t *testing.T) {
	v4 := net.ParseIP(ueV4).To4()
	v6 := net.ParseIP("2001:db8:500:7:123:4567:89ab:cdef") // the prefix with the session's identifier
	for _, tc := range []struct {
		name           string
		typ            uint8
		upfAllocates   bool
		wantUL, wantDL context.UEIPAddress
	}{
		{
			name:   "IPv4",
			typ:    pduIPv4,
			wantUL: context.UEIPAddress{V4: true, Ipv4Address: v4},
			wantDL: context.UEIPAddress{V4: true, Ipv4Address: v4},
		},
		{
			name: "IPv4, the UPF allocates", typ: pduIPv4, upfAllocates: true,
			wantUL: context.UEIPAddress{CHV4: true},
			wantDL: context.UEIPAddress{CHV4: true},
		},
		{
			name:   "IPv6",
			typ:    pduIPv6,
			wantUL: context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64},
			wantDL: context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true},
		},
		{
			// The SMF chose the prefix; an allocating UPF is not asked for an IPv4 address the
			// session does not have.
			name: "IPv6, the UPF allocates", typ: pduIPv6, upfAllocates: true,
			wantUL: context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64},
			wantDL: context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true},
		},
		{
			name: "IPv4v6",
			typ:  pduIPv4v6,
			wantUL: context.UEIPAddress{
				V4: true, Ipv4Address: v4, V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64,
			},
			wantDL: context.UEIPAddress{
				V4: true, Ipv4Address: v4, V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true,
			},
		},
		{
			name: "IPv4v6, the UPF allocates", typ: pduIPv4v6, upfAllocates: true,
			wantUL: context.UEIPAddress{CHV4: true, V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64},
			wantDL: context.UEIPAddress{CHV4: true, V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upf := &context.UPF{}
			if tc.upfAllocates {
				upf = ueipUpf()
			}
			smContext := &context.SMContext{SelectedPDUSessionType: tc.typ, PDUAddress: ueAddressOf(tc.typ)}
			ul, dl := activatedUEIPAddresses(t, smContext, upf)
			if ul == nil || !reflect.DeepEqual(*ul, tc.wantUL) {
				t.Errorf("uplink UE IP Address\n got %+v\nwant %+v", ul, tc.wantUL)
			}
			if dl == nil || !reflect.DeepEqual(*dl, tc.wantDL) {
				t.Errorf("downlink UE IP Address\n got %+v\nwant %+v", dl, tc.wantDL)
			}
		})
	}
}

// A session restored from a document written before the SMF selected types, or one with no type
// at all, is IPv4: its rules carry the IPv4 address as they did.
func TestUEIPAddressIEOfASessionWithNoType(t *testing.T) {
	smContext := &context.SMContext{PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)}}
	ul, dl := activatedUEIPAddresses(t, smContext, &context.UPF{})
	want := context.UEIPAddress{V4: true, Ipv4Address: net.IP{192, 168, 1, 1}}
	for _, got := range []*context.UEIPAddress{ul, dl} {
		if got == nil || !reflect.DeepEqual(*got, want) {
			t.Errorf("UE IP Address %+v, want %+v", got, want)
		}
	}
}

// Ipv6UEIPAddress names the prefix with its host bits clear, whatever the stored prefix holds,
// and the identifier in the lower 64 bits; a prefix without an identifier is sent as the prefix.
func TestIpv6UEIPAddressMasksThePrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:500:7:1:2:3:4/64")
	addr := &context.UeIpAddr{Ipv6Prefix: &prefix}
	var ueIP context.UEIPAddress
	addr.Ipv6UEIPAddress(&ueIP, false)
	if !ueIP.Ipv6Address.Equal(net.ParseIP("2001:db8:500:7::")) || ueIP.Ipv6PrefixLength != 64 || ueIP.Sd {
		t.Errorf("got %+v", ueIP)
	}
	iid := context.InterfaceIdentifier{0, 0, 0, 0, 0, 0, 0xab, 0xcd}
	addr.Ipv6Iid = &iid
	var withIid context.UEIPAddress
	addr.Ipv6UEIPAddress(&withIid, true)
	if !withIid.Ipv6Address.Equal(net.ParseIP("2001:db8:500:7::abcd")) || withIid.Ipv6PrefixLength != 64 || !withIid.Sd {
		t.Errorf("with an identifier: got %+v", withIid)
	}
	var none context.UEIPAddress
	(&context.UeIpAddr{Ip: net.IPv4(10, 0, 0, 1)}).Ipv6UEIPAddress(&none, true)
	if !reflect.DeepEqual(none, context.UEIPAddress{}) {
		t.Errorf("a session without a prefix added %+v", none)
	}
}
