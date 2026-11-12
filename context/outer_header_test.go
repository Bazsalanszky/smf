// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
)

var (
	gnbV4 = net.IP{10, 10, 3, 232}
	gnbV6 = net.ParseIP("2001:db8:630::232")
	upfV6 = net.ParseIP("2001:db8:630::1")
)

func TestSplitTransportLayerAddress(t *testing.T) {
	dual := append(append([]byte{}, gnbV4...), gnbV6...)
	for _, tc := range []struct {
		name   string
		in     []byte
		v4, v6 net.IP
	}{
		{"32 bits", gnbV4, gnbV4, nil},
		{"128 bits", gnbV6, nil, gnbV6},
		{"160 bits, IPv4 first", dual, gnbV4, gnbV6},
		{"IPv4 in 16 bytes, as a restored net.IP", net.IPv4(10, 10, 3, 232), gnbV4, nil},
		{"any other length", []byte{1, 2, 3}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := context.SplitTransportLayerAddress(tc.in)
			if !v4.Equal(tc.v4) || !v6.Equal(tc.v6) {
				t.Errorf("got %v %v, want %v %v", v4, v6, tc.v4, tc.v6)
			}
		})
	}
}

func TestAccessOuterHeaderCreation(t *testing.T) {
	dual := append(append([]byte{}, gnbV4...), gnbV6...)
	for _, tc := range []struct {
		name     string
		an       []byte
		family   context.AddressFamily
		wantDesc uint16
		wantIP   net.IP
	}{
		{"IPv4 RAN", gnbV4, context.AddressFamilyAuto, context.OuterHeaderCreationGtpUUdpIpv4, gnbV4},
		{"IPv4 RAN, IPv6 UPF", gnbV4, context.AddressFamilyIPv6, context.OuterHeaderCreationGtpUUdpIpv4, gnbV4},
		{"IPv6 RAN", gnbV6, context.AddressFamilyAuto, context.OuterHeaderCreationGtpUUdpIpv6, gnbV6},
		{"dual RAN, auto", dual, context.AddressFamilyAuto, context.OuterHeaderCreationGtpUUdpIpv4, gnbV4},
		{"dual RAN, IPv4 UPF", dual, context.AddressFamilyIPv4, context.OuterHeaderCreationGtpUUdpIpv4, gnbV4},
		{"dual RAN, IPv6 UPF", dual, context.AddressFamilyIPv6, context.OuterHeaderCreationGtpUUdpIpv6, gnbV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ohc := context.AccessOuterHeaderCreation(tc.an, 0x42, tc.family)
			if ohc.OuterHeaderCreationDescription != tc.wantDesc || ohc.Teid != 0x42 {
				t.Fatalf("description %#x TEID %#x, want %#x 0x42", ohc.OuterHeaderCreationDescription, ohc.Teid, tc.wantDesc)
			}
			got := ohc.Ipv4Address
			if tc.wantDesc == context.OuterHeaderCreationGtpUUdpIpv6 {
				got = ohc.Ipv6Address
				if ohc.Ipv4Address != nil {
					t.Errorf("IPv4 address %v beside the IPv6 description", ohc.Ipv4Address)
				}
			} else if ohc.Ipv6Address != nil {
				t.Errorf("IPv6 address %v beside the IPv4 description", ohc.Ipv6Address)
			}
			if !got.Equal(tc.wantIP) {
				t.Errorf("peer %v, want %v", got, tc.wantIP)
			}
		})
	}
}

// What the SMF sent an IPv4 RAN before it had IPv6 N3: the same 4 bytes, the same description.
func TestAccessOuterHeaderCreationToAnIPv4RANIsUnchanged(t *testing.T) {
	ohc := context.AccessOuterHeaderCreation(gnbV4, 7, context.AddressFamilyAuto)
	if !ohc.Ipv4Address.Equal(gnbV4) || len(ohc.Ipv4Address) != net.IPv4len {
		t.Errorf("IPv4 address %#v, want the 4 bytes %#v", ohc.Ipv4Address, gnbV4.To4())
	}
	if ohc.OuterHeaderCreationDescription != context.OuterHeaderCreationGtpUUdpIpv4 || ohc.Teid != 7 ||
		ohc.Ipv6Address != nil || ohc.PortNumber != 0 {
		t.Errorf("unexpected fields in %+v", *ohc)
	}
}

func TestAssignedFTEID(t *testing.T) {
	if f := context.AssignedFTEID(5, net.IPv4(10, 10, 3, 1)); f == nil || !f.V4 || f.V6 || len(f.Ipv4Address) != 4 {
		t.Errorf("IPv4 address: %+v", f)
	}
	if f := context.AssignedFTEID(5, upfV6); f == nil || f.V4 || !f.V6 || !f.Ipv6Address.Equal(upfV6) || f.Teid != 5 {
		t.Errorf("IPv6 address: %+v", f)
	}
	if f := context.AssignedFTEID(5, nil); f != nil {
		t.Errorf("no address: %+v, want nil", f)
	}
}

func TestN3InterfaceFromFTEID(t *testing.T) {
	upfV4 := net.IP{10, 10, 3, 1}
	for _, tc := range []struct {
		name   string
		v4, v6 net.IP
		family context.AddressFamily
		want   net.IP
	}{
		{"V4", upfV4, nil, context.AddressFamilyAuto, upfV4},
		{"V6", nil, upfV6, context.AddressFamilyAuto, upfV6},
		{"V6, IPv6 UPF", nil, upfV6, context.AddressFamilyIPv6, upfV6},
		{"dual, auto", upfV4, upfV6, context.AddressFamilyAuto, upfV4},
		{"dual, IPv6 UPF", upfV4, upfV6, context.AddressFamilyIPv6, upfV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n3 := context.N3InterfaceFromFTEID(tc.v4, tc.v6)
			got, err := n3.TransportIP(tc.family)
			if err != nil || !got.Equal(tc.want) {
				t.Errorf("TransportIP = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	// Neither: the old shape, a single nil IPv4 address.
	if n3 := context.N3InterfaceFromFTEID(nil, nil); len(n3.IPv4EndPointAddresses) != 1 || len(n3.IPv6EndPointAddresses) != 0 {
		t.Errorf("no address: %+v", n3)
	}
}

func TestUplinkPdrOfAnIPv6N3UPF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		family  context.AddressFamily
		v4, v6  bool
		wantOHR uint8
	}{
		{"auto", context.AddressFamilyAuto, true, false, context.OuterHeaderRemovalGtpUUdpIpv4},
		{"ipv4", context.AddressFamilyIPv4, true, false, context.OuterHeaderRemovalGtpUUdpIpv4},
		{"ipv6", context.AddressFamilyIPv6, false, true, context.OuterHeaderRemovalGtpUUdpIpv6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := &context.SMContext{
				PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)},
				Dnn:        testDnn,
			}
			dpNode := &context.DataPathNode{
				UPF: &context.UPF{TransportFamily: tc.family},
				UpLinkTunnel: &context.GTPTunnel{
					PDR: map[string]*context.PDR{defaultPdr: {FAR: &context.FAR{}}},
				},
			}
			if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
				t.Fatalf("ActivateUpLinkPdr: %v", err)
			}
			pdr := dpNode.UpLinkTunnel.PDR[defaultPdr]
			f := pdr.PDI.LocalFTeid
			if f.V4 != tc.v4 || f.V6 != tc.v6 || !f.Ch || !f.Chid {
				t.Errorf("F-TEID %+v: want V4=%v V6=%v with CH and CHID", *f, tc.v4, tc.v6)
			}
			if got := pdr.OuterHeaderRemoval.OuterHeaderRemovalDescription; got != tc.wantOHR {
				t.Errorf("outer header removal %d, want %d", got, tc.wantOHR)
			}
		})
	}
}

// The downlink FAR towards an IPv6 gNB is an IPv6 outer header creation.
func TestDownlinkFarToAnIPv6RAN(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)},
		Dnn:        testDnn,
		Tunnel:     &context.UPTunnel{},
	}
	smContext.Tunnel.ANInformation.IPAddress = gnbV6
	smContext.Tunnel.ANInformation.TEID = 0x99
	dpNode := &context.DataPathNode{
		UPF: &context.UPF{TransportFamily: context.AddressFamilyIPv6},
		DownLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{defaultPdr: {FAR: &context.FAR{}}},
		},
	}
	dataPath := &context.DataPath{FirstDPNode: dpNode}
	if err := dpNode.ActivateDlLinkPdr(smContext, &context.QER{}, 10, dataPath); err != nil {
		t.Fatalf("ActivateDlLinkPdr: %v", err)
	}
	ohc := dpNode.DownLinkTunnel.PDR[defaultPdr].FAR.ForwardingParameters.OuterHeaderCreation
	if ohc.OuterHeaderCreationDescription != context.OuterHeaderCreationGtpUUdpIpv6 ||
		!ohc.Ipv6Address.Equal(gnbV6) || ohc.Teid != 0x99 {
		t.Errorf("outer header creation %+v, want GTP-U/UDP/IPv6 to %v TEID 0x99", *ohc, gnbV6)
	}
}
