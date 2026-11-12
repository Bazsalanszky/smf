// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/wmnsk/go-pfcp/ie"
)

var upfV4 = net.IP{10, 10, 3, 1}

func upIPRes(flags uint8, v4, v6, ni string, si uint8) []byte {
	return ie.NewUserPlaneIPResourceInformation(flags, 0, v4, v6, ni, si).Payload
}

func TestParseN3Advertisement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payloads [][]byte
		want     context.N3Advertisement
	}{
		{"none", nil, context.N3Advertisement{}},
		{
			"IPv4, access (omec UPF without a DNN: 0x41)",
			[][]byte{upIPRes(0x41, "10.10.3.1", "", "", ie.SrcInterfaceAccess)},
			context.N3Advertisement{Known: true, V4: true},
		},
		{
			"both, access, with a network instance (omec UPF with a DNN: 0x63)",
			[][]byte{upIPRes(0x63, "10.10.3.1", "2001:db8:630::1", "\x08internet", ie.SrcInterfaceAccess)},
			context.N3Advertisement{Known: true, V4: true, V6: true},
		},
		{
			"IPv6 only, no source interface",
			[][]byte{upIPRes(0x02, "", "2001:db8:630::1", "", 0)},
			context.N3Advertisement{Known: true, V6: true},
		},
		{
			"core side only: not N3",
			[][]byte{upIPRes(0x43, "10.10.6.1", "2001:db8:660::2", "", ie.SrcInterfaceCore)},
			context.N3Advertisement{},
		},
		{
			"one entry per family",
			[][]byte{
				upIPRes(0x41, "10.10.3.1", "", "", ie.SrcInterfaceAccess),
				upIPRes(0x42, "", "2001:db8:630::1", "", ie.SrcInterfaceAccess),
			},
			context.N3Advertisement{Known: true, V4: true, V6: true},
		},
		{"truncated", [][]byte{{0x03, 10, 10, 3, 1, 0x20}}, context.N3Advertisement{}},
		{"empty", [][]byte{{}}, context.N3Advertisement{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := context.ParseN3Advertisement(tc.payloads); got != tc.want {
				t.Errorf("ParseN3Advertisement = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestN3Transport(t *testing.T) {
	v4 := context.N3Advertisement{Known: true, V4: true}
	v6 := context.N3Advertisement{Known: true, V6: true}
	both := context.N3Advertisement{Known: true, V4: true, V6: true}
	for _, tc := range []struct {
		name   string
		family context.AddressFamily
		adv    context.N3Advertisement
		want   context.N3Transport
	}{
		{"auto, nothing advertised: as before", context.AddressFamilyAuto, context.N3Advertisement{}, context.N3Transport{}},
		{"auto, IPv4 advertised: as before", context.AddressFamilyAuto, v4, context.N3Transport{}},
		{"auto, IPv6 advertised", context.AddressFamilyAuto, v6, context.N3Transport{Family: context.AddressFamilyIPv6}},
		{"auto, both advertised: dual", context.AddressFamilyAuto, both, context.N3Transport{Dual: true}},
		{"ipv4 override, both advertised", context.AddressFamilyIPv4, both, context.N3Transport{Family: context.AddressFamilyIPv4}},
		{"ipv6 override, both advertised", context.AddressFamilyIPv6, both, context.N3Transport{Family: context.AddressFamilyIPv6}},
		{"ipv6 override, nothing advertised", context.AddressFamilyIPv6, context.N3Advertisement{}, context.N3Transport{Family: context.AddressFamilyIPv6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upf := &context.UPF{TransportFamily: tc.family, N3Advertised: tc.adv}
			if got := upf.GetN3Transport(); got != tc.want {
				t.Errorf("GetN3Transport = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestN3TransportLayerAddress(t *testing.T) {
	dual := append(append(net.IP{}, upfV4...), upfV6...)
	both := context.N3Advertisement{Known: true, V4: true, V6: true}
	for _, tc := range []struct {
		name   string
		family context.AddressFamily
		adv    context.N3Advertisement
		n3     context.UPFInterfaceInfo
		want   net.IP
	}{
		{
			"dual F-TEID: 160 bits, IPv4 first", context.AddressFamilyAuto, both,
			context.N3InterfaceFromFTEID(upfV4, upfV6), dual,
		},
		{
			"dual N3, the UPF gave IPv4 only: 32 bits", context.AddressFamilyAuto, both,
			context.N3InterfaceFromFTEID(upfV4, nil), upfV4,
		},
		{
			"dual N3, the UPF gave IPv6 only: 128 bits", context.AddressFamilyAuto, both,
			context.N3InterfaceFromFTEID(nil, upfV6), upfV6.To16(),
		},
		{
			"IPv4 UPF: 32 bits, as before", context.AddressFamilyAuto,
			context.N3Advertisement{Known: true, V4: true},
			context.N3InterfaceFromFTEID(upfV4, nil), upfV4,
		},
		{
			"no advertisement, both addresses: IPv4 as before", context.AddressFamilyAuto,
			context.N3Advertisement{},
			context.N3InterfaceFromFTEID(upfV4, upfV6), upfV4,
		},
		{
			"ipv4 override of a dual UPF", context.AddressFamilyIPv4, both,
			context.N3InterfaceFromFTEID(upfV4, upfV6), upfV4,
		},
		{
			"ipv6 override of a dual UPF", context.AddressFamilyIPv6, both,
			context.N3InterfaceFromFTEID(upfV4, upfV6), upfV6.To16(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upf := &context.UPF{
				TransportFamily: tc.family, N3Advertised: tc.adv,
				N3Interfaces: []context.UPFInterfaceInfo{tc.n3},
			}
			got, err := upf.N3TransportLayerAddress()
			// Compared byte for byte: the length is the TransportLayerAddress length (4, 16 or 20).
			if err != nil || string(got) != string(tc.want) {
				t.Errorf("N3TransportLayerAddress = %v (%d bytes), %v; want %v (%d bytes)", got, len(got), err, tc.want, len(tc.want))
			}
		})
	}
	if _, err := (&context.UPF{}).N3TransportLayerAddress(); err == nil {
		t.Error("no N3 interface: want an error")
	}
}

func TestAssignedFTEIDOfADualAddress(t *testing.T) {
	dual := append(append(net.IP{}, upfV4...), upfV6...)
	f := context.AssignedFTEID(7, dual)
	if f == nil || !f.V4 || !f.V6 || !f.Ipv4Address.Equal(upfV4) || !f.Ipv6Address.Equal(upfV6) || f.Teid != 7 || f.Ch {
		t.Fatalf("AssignedFTEID(160 bits) = %+v, want V4 %v and V6 %v, TEID 7", f, upfV4, upfV6)
	}
	// One family each, as before.
	if f := context.AssignedFTEID(7, upfV4); f == nil || !f.V4 || f.V6 || len(f.Ipv4Address) != net.IPv4len {
		t.Errorf("AssignedFTEID(IPv4) = %+v", f)
	}
	if f := context.AssignedFTEID(7, net.IPv4(10, 10, 3, 1)); f == nil || !f.V4 || f.V6 || len(f.Ipv4Address) != net.IPv4len {
		t.Errorf("AssignedFTEID(IPv4 in 16 bytes) = %+v", f)
	}
	if f := context.AssignedFTEID(7, upfV6); f == nil || f.V4 || !f.V6 {
		t.Errorf("AssignedFTEID(IPv6) = %+v", f)
	}
	if f := context.AssignedFTEID(7, nil); f != nil {
		t.Errorf("AssignedFTEID(nil) = %+v, want nil", f)
	}
}

func TestUplinkPdrOfADualN3UPF(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)},
		Dnn:        testDnn,
	}
	dpNode := &context.DataPathNode{
		UPF: &context.UPF{N3Advertised: context.N3Advertisement{Known: true, V4: true, V6: true}},
		UpLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{defaultPdr: {FAR: &context.FAR{}}},
		},
	}
	if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}
	pdr := dpNode.UpLinkTunnel.PDR[defaultPdr]
	if f := pdr.PDI.LocalFTeid; !f.V4 || !f.V6 || !f.Ch || !f.Chid {
		t.Errorf("F-TEID %+v: want CHOOSE V4 and V6 with a CHOOSE ID", *f)
	}
	if got := pdr.OuterHeaderRemoval.OuterHeaderRemovalDescription; got != context.OuterHeaderRemovalGtpUUdpIp {
		t.Errorf("outer header removal %d, want %d (GTP-U/UDP/IP)", got, context.OuterHeaderRemovalGtpUUdpIp)
	}
}

// With a dual F-TEID, the RAN picks a family, and its downlink address says which: the outer
// header creation follows it.
func TestDownlinkFarOfADualN3FollowsTheRAN(t *testing.T) {
	dualUPF := context.N3Transport{Dual: true}
	for _, tc := range []struct {
		name   string
		an     net.IP
		desc   uint16
		v4, v6 net.IP
	}{
		{"IPv4 gNB", gnbV4, context.OuterHeaderCreationGtpUUdpIpv4, gnbV4, nil},
		{"IPv6 gNB", gnbV6, context.OuterHeaderCreationGtpUUdpIpv6, nil, gnbV6},
		{
			"dual gNB: IPv4, as before", append(append(net.IP{}, gnbV4...), gnbV6...),
			context.OuterHeaderCreationGtpUUdpIpv4, gnbV4, nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ohc := context.AccessOuterHeaderCreation(tc.an, 0x99, dualUPF.Family)
			if ohc.OuterHeaderCreationDescription != tc.desc || !ohc.Ipv4Address.Equal(tc.v4) || !ohc.Ipv6Address.Equal(tc.v6) {
				t.Errorf("OHC %+v, want description %#x to %v/%v", *ohc, tc.desc, tc.v4, tc.v6)
			}
		})
	}
}
