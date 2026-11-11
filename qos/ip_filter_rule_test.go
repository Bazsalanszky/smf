// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"net/netip"
	"testing"
)

// Addresses several cases share.
const (
	testV6Addr = "2001:db8::1"
	testV4Addr = "1.1.1.1"
)

// A flow description is split into its fields the same way whatever the family of its addresses:
// on white space, and an address from its length on the "/". The colons of an IPv6 literal stay in
// the address, and the ports stay tokens of their own.
func TestAFlowDescriptionIsSplitIntoItsFieldsForEitherFamily(t *testing.T) {
	tests := []struct {
		name     string
		flowDesc string
		want     IPFilterRule
	}{
		{
			name:     "IPv6 remote address, assigned local",
			flowDesc: "permit out ip from 2001:db8::1 to assigned",
			want: IPFilterRule{
				protoId: "ip",
				sAddr:   IPFilterRuleIpAddr{addr: testV6Addr},
				dAddr:   IPFilterRuleIpAddr{addr: ipFilterAddrAssigned},
			},
		},
		{
			name:     "IPv6 remote prefix with a port, local port range",
			flowDesc: "permit out 17 from 2001:db8::/32 53 to assigned 1000-2000",
			want: IPFilterRule{
				protoId:    "17",
				sPort:      "53",
				sAddr:      IPFilterRuleIpAddr{addr: "2001:db8::", mask: "32"},
				dAddr:      IPFilterRuleIpAddr{addr: ipFilterAddrAssigned},
				dPortRange: IPFilterRulePortRange{lowLimit: "1000", highLimit: "2000"},
			},
		},
		{
			name:     "IPv6 on both sides with prefixes and ports",
			flowDesc: "permit out 6 from 2001:db8:1::10/64 80-443 to 2001:db8:500::1/64 50000",
			want: IPFilterRule{
				protoId:    "6",
				sPortRange: IPFilterRulePortRange{lowLimit: "80", highLimit: "443"},
				dPort:      "50000",
				sAddr:      IPFilterRuleIpAddr{addr: "2001:db8:1::10", mask: "64"},
				dAddr:      IPFilterRuleIpAddr{addr: "2001:db8:500::1", mask: "64"},
			},
		},
		{
			name:     "any remote, IPv6 local",
			flowDesc: "permit out ip from any to 2001:db8::5",
			want: IPFilterRule{
				protoId: "ip",
				sAddr:   IPFilterRuleIpAddr{addr: ipFilterAddrAny},
				dAddr:   IPFilterRuleIpAddr{addr: "2001:db8::5"},
			},
		},
		{
			name:     "router solicitations to all-routers",
			flowDesc: "permit out 58 from ff02::2/128 to assigned",
			want: IPFilterRule{
				protoId: "58",
				sAddr:   IPFilterRuleIpAddr{addr: "ff02::2", mask: "128"},
				dAddr:   IPFilterRuleIpAddr{addr: ipFilterAddrAssigned},
			},
		},
		{
			name:     "shortest IPv6 forms",
			flowDesc: "permit out ip from ::1 to ::",
			want: IPFilterRule{
				protoId: "ip",
				sAddr:   IPFilterRuleIpAddr{addr: "::1"},
				dAddr:   IPFilterRuleIpAddr{addr: "::"},
			},
		},
		{
			name:     "IPv4 as before",
			flowDesc: "permit out 17 from 1.1.1.1/24 1000-1200 to 2.2.2.2/24 2000-2500",
			want: IPFilterRule{
				protoId:    "17",
				sPortRange: IPFilterRulePortRange{lowLimit: "1000", highLimit: "1200"},
				dPortRange: IPFilterRulePortRange{lowLimit: "2000", highLimit: "2500"},
				sAddr:      IPFilterRuleIpAddr{addr: testV4Addr, mask: "24"},
				dAddr:      IPFilterRuleIpAddr{addr: "2.2.2.2", mask: "24"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeFlowDescToIPFilters(tc.flowDesc)
			if *got != tc.want {
				t.Errorf("DecodeFlowDescToIPFilters(%q)\n got %+v\nwant %+v", tc.flowDesc, *got, tc.want)
			}
		})
	}
}

// Each side of a flow description reads as an address of either family with its prefix length,
// and what cannot be read so is refused rather than dropped.
func TestAnIPFilterAddressReadsAsAPrefixOfEitherFamily(t *testing.T) {
	tests := []struct {
		name    string
		side    IPFilterRuleIpAddr
		want    netip.Prefix
		wantErr bool
	}{
		{name: "IPv6 without a length is a /128", side: IPFilterRuleIpAddr{addr: testV6Addr}, want: netip.MustParsePrefix("2001:db8::1/128")},
		{name: "IPv6 with a length", side: IPFilterRuleIpAddr{addr: "2001:db8::", mask: "32"}, want: netip.MustParsePrefix("2001:db8::/32")},
		{name: "IPv6 host bits are kept", side: IPFilterRuleIpAddr{addr: "2001:db8::10", mask: "64"}, want: netip.PrefixFrom(netip.MustParseAddr("2001:db8::10"), 64)},
		{name: "IPv6 /0", side: IPFilterRuleIpAddr{addr: "::", mask: "0"}, want: netip.MustParsePrefix("::/0")},
		{name: "IPv6 /128", side: IPFilterRuleIpAddr{addr: "ff02::2", mask: "128"}, want: netip.MustParsePrefix("ff02::2/128")},
		{name: "IPv4 without a length is a /32", side: IPFilterRuleIpAddr{addr: testV4Addr}, want: netip.MustParsePrefix("1.1.1.1/32")},
		{name: "IPv4 with a length", side: IPFilterRuleIpAddr{addr: "10.0.0.0", mask: "8"}, want: netip.MustParsePrefix("10.0.0.0/8")},
		{name: "IPv4 length with a leading zero, as Atoi took it", side: IPFilterRuleIpAddr{addr: testV4Addr, mask: "024"}, want: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 24)},
		{name: "IPv4-mapped reads as IPv4", side: IPFilterRuleIpAddr{addr: "::ffff:10.1.2.3"}, want: netip.MustParsePrefix("10.1.2.3/32")},
		{name: "IPv4-mapped with an IPv4 length", side: IPFilterRuleIpAddr{addr: "::ffff:10.1.2.0", mask: "24"}, want: netip.MustParsePrefix("10.1.2.0/24")},

		{name: "IPv6 length beyond 128", side: IPFilterRuleIpAddr{addr: testV6Addr, mask: "129"}, wantErr: true},
		{name: "IPv6 negative length", side: IPFilterRuleIpAddr{addr: testV6Addr, mask: "-1"}, wantErr: true},
		{name: "IPv6 length not a number", side: IPFilterRuleIpAddr{addr: testV6Addr, mask: "ffff::"}, wantErr: true},
		{name: "IPv6 with a zone", side: IPFilterRuleIpAddr{addr: "fe80::1%eth0"}, wantErr: true},
		{name: "IPv6 in brackets", side: IPFilterRuleIpAddr{addr: "[2001:db8::1]"}, wantErr: true},
		{name: "IPv6 with a port glued on", side: IPFilterRuleIpAddr{addr: "2001:db8::1:80:90:1:2:3"}, wantErr: true},
		{name: "IPv6 negated", side: IPFilterRuleIpAddr{addr: "!2001:db8::1"}, wantErr: true},
		{name: "IPv4 length beyond 32", side: IPFilterRuleIpAddr{addr: testV4Addr, mask: "33"}, wantErr: true},
		{name: "IPv4 netmask instead of a length", side: IPFilterRuleIpAddr{addr: testV4Addr, mask: "255.255.255.0"}, wantErr: true},
		{name: "IPv4-mapped with an IPv6 length", side: IPFilterRuleIpAddr{addr: "::ffff:10.1.2.3", mask: "120"}, wantErr: true},
		{name: "IPv4 truncated", side: IPFilterRuleIpAddr{addr: "1.1.1"}, wantErr: true},
		{name: "keyword any", side: IPFilterRuleIpAddr{addr: ipFilterAddrAny}, wantErr: true},
		{name: "keyword assigned", side: IPFilterRuleIpAddr{addr: ipFilterAddrAssigned}, wantErr: true},
		{name: "empty", side: IPFilterRuleIpAddr{}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.side.prefix()
			if tc.wantErr {
				if err == nil {
					t.Errorf("%+v read as %v, want it refused", tc.side, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%+v refused: %v", tc.side, err)
			}
			if got != tc.want {
				t.Errorf("%+v read as %v, want %v", tc.side, got, tc.want)
			}
		})
	}
}

// "any" and "assigned" are keywords on either side, never addresses.
func TestTheAnyAndAssignedKeywordsAreNotAddresses(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: ipFilterAddrAny, want: true},
		{addr: ipFilterAddrAssigned, want: true},
		{addr: testV6Addr, want: false},
		{addr: testV4Addr, want: false},
		{addr: "ANY", want: false},
		{addr: "", want: false},
	}

	for _, tc := range tests {
		if got := (IPFilterRuleIpAddr{addr: tc.addr}).isKeyword(); got != tc.want {
			t.Errorf("isKeyword(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
