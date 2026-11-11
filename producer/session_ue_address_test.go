// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	smf_context "github.com/omec-project/smf/context"
	"go.uber.org/zap"
)

const testRuleUeIpv4 = "172.250.0.11"

func ueAddress(v4 bool, v6 bool) *smf_context.UeIpAddr {
	addr := &smf_context.UeIpAddr{}
	if v4 {
		addr.Ip = net.ParseIP(testRuleUeIpv4).To4()
	}
	if v6 {
		prefix := netip.MustParsePrefix("2001:db8:500:9::/64")
		iid := smf_context.InterfaceIdentifier{0, 0, 0, 0, 0, 0, 0, 1}
		addr.Ipv6Prefix, addr.Ipv6Iid = &prefix, &iid
	}
	return addr
}

// A rule added to an established session names the addresses the session holds, as the
// establishment does: the IPv4 address as before, the IPv6 address with its prefix length, and S/D on the
// downlink with an IPv6 part.
func TestSessionUEAddressByFamily(t *testing.T) {
	v4 := net.ParseIP(testRuleUeIpv4).To4()
	v6 := net.ParseIP("2001:db8:500:9::1")
	for _, tc := range []struct {
		name     string
		addr     *smf_context.UeIpAddr
		downlink bool
		want     *smf_context.UEIPAddress
	}{
		{name: "IPv4 uplink", addr: ueAddress(true, false), want: &smf_context.UEIPAddress{V4: true, Ipv4Address: v4}},
		{name: "IPv4 downlink", addr: ueAddress(true, false), downlink: true, want: &smf_context.UEIPAddress{V4: true, Ipv4Address: v4}},
		{
			name: "IPv6 downlink", addr: ueAddress(false, true), downlink: true,
			want: &smf_context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true},
		},
		{
			name: "IPv4v6 uplink", addr: ueAddress(true, true),
			want: &smf_context.UEIPAddress{V4: true, Ipv4Address: v4, V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64},
		},
		{
			// The IPv4 address the user plane supplied was released; the prefix is still held.
			name: "IPv4v6 with the IPv4 address released", addr: &smf_context.UeIpAddr{
				Ip: net.IPv4zero, Ipv6Prefix: ueAddress(false, true).Ipv6Prefix, Ipv6Iid: ueAddress(false, true).Ipv6Iid,
			},
			want: &smf_context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64},
		},
		{name: "none", addr: nil},
		{name: "released", addr: &smf_context.UeIpAddr{Ip: net.IPv4zero}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			param := &pfcpParam{}
			got := sessionUEAddress(&smf_context.SMContext{PDUAddress: tc.addr}, param, tc.downlink)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			if (len(param.unbuilt) != 0) != (tc.want == nil) {
				t.Errorf("unbuilt %v for a rule that names %+v", param.unbuilt, got)
			}
		})
	}
}

// A re-installed rule of an IPv4v6 session whose IPv4 address the user plane chose names that
// address instead of CHV4, and keeps its IPv6 part. One of an IPv6 session is left alone.
func TestPinUeAddressKeepsTheIPv6Part(t *testing.T) {
	v6 := net.ParseIP("2001:db8:500:9::")
	ipv6Part := smf_context.UEIPAddress{V6: true, Ipv6Address: v6, IP6PL: true, Ipv6PrefixLength: 64, Sd: true}

	dual := ipv6Part
	dual.CHV4 = true
	smContext := &smf_context.SMContext{
		SelectedPDUSessionType: nasMessage.PDUSessionTypeIPv4IPv6,
		PDUAddress:             ueAddress(true, true),
	}
	smContext.PDUAddress.UpfProvided = true
	smContext.SubPfcpLog = zap.NewNop().Sugar()
	pdr := &smf_context.PDR{PDI: smf_context.PDI{UEIPAddress: &dual}}
	pinUeAddress(smContext, pdr)
	want := ipv6Part
	want.V4, want.Ipv4Address = true, smContext.PDUAddress.Ip
	if !reflect.DeepEqual(*pdr.PDI.UEIPAddress, want) {
		t.Errorf("IPv4v6 rule\n got %+v\nwant %+v", *pdr.PDI.UEIPAddress, want)
	}

	v6Only := ipv6Part
	v6Session := &smf_context.SMContext{SelectedPDUSessionType: nasMessage.PDUSessionTypeIPv6, PDUAddress: ueAddress(false, true)}
	v6Pdr := &smf_context.PDR{PDI: smf_context.PDI{UEIPAddress: &v6Only}}
	pinUeAddress(v6Session, v6Pdr)
	if !reflect.DeepEqual(*v6Pdr.PDI.UEIPAddress, ipv6Part) {
		t.Errorf("IPv6 rule changed to %+v", *v6Pdr.PDI.UEIPAddress)
	}
}
