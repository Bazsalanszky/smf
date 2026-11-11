// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/openapi/v2/nfConfigApi"
)

const testUeV4Subnet = "172.250.0.0/16"

func dnnInfoOf(t *testing.T, domain nfConfigApi.IpDomain) *SnssaiSmfDnnInfo {
	t.Helper()
	sm := makeSessionConfig("slice1", "222", "02", "2", "1", "ims", "", "upf-1", 8805)
	sm.IpDomain = []nfConfigApi.IpDomain{domain}
	info := buildSnssaiSmfInfo(&sm, nil).DnnInfos[domain.DnnName]
	if info == nil {
		t.Fatalf("no DNN info for %s", domain.DnnName)
	}
	return info
}

// The IPv6 part of an IP domain: the pool with its prefix length, the IPv6 DNS server and the
// P-CSCF. ueSubnet and dnsIpv4 are empty strings for an IPv6-only DNN.
func TestIpDomainIPv6(t *testing.T) {
	str := func(s string) *string { return &s }
	length := func(l int32) *int32 { return &l }
	for _, tc := range []struct {
		name          string
		domain        nfConfigApi.IpDomain
		wantV4, want6 bool
		wantLen       int
		wantDNS       string
		wantPCSCF     string
	}{
		{
			name:   "IPv4 only, as before",
			domain: nfConfigApi.IpDomain{DnnName: "v4", UeSubnet: testUeV4Subnet, DnsIpv4: testDnsIpv4, Mtu: 1400},
			wantV4: true,
		},
		{
			name: "dual stack",
			domain: nfConfigApi.IpDomain{
				DnnName: "dual", UeSubnet: testUeV4Subnet, DnsIpv4: testDnsIpv4, Mtu: 1400,
				UeSubnetIpv6: str(testUeIpv6Pool), DnsIpv6: str(testDnsIpv6), PcscfIpv6: str(testPcscfIpv6),
			},
			wantV4: true, want6: true, wantLen: 64, wantDNS: testDnsIpv6, wantPCSCF: testPcscfIpv6,
		},
		{
			name: "IPv6 only, /60 prefixes",
			domain: nfConfigApi.IpDomain{
				DnnName: "v6", Mtu: 1400, UeSubnetIpv6: str("2001:db8:600::/48"), UeIpv6PrefixLength: length(60),
			},
			want6: true, wantLen: 60,
		},
		{
			name: "invalid IPv6 values are ignored",
			domain: nfConfigApi.IpDomain{
				DnnName: "bad", UeSubnet: testUeV4Subnet, Mtu: 1400,
				UeSubnetIpv6: str("10.0.0.0/8"), DnsIpv6: str("8.8.4.4"), PcscfIpv6: str("::ffff:10.0.0.1"),
			},
			wantV4: true,
		},
		{
			name: "a prefix length shorter than the pool",
			domain: nfConfigApi.IpDomain{
				DnnName: "short", Mtu: 1400, UeSubnetIpv6: str(testUeIpv6Pool), UeIpv6PrefixLength: length(48),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := dnnInfoOf(t, tc.domain)
			if info.HasIpv4Pool() != tc.wantV4 || info.HasIpv6Pool() != tc.want6 {
				t.Errorf("IPv4 pool %t, IPv6 pool %t; want %t, %t", info.HasIpv4Pool(), info.HasIpv6Pool(), tc.wantV4, tc.want6)
			}
			if tc.want6 && info.UeIpv6Allocator.PrefixLength() != tc.wantLen {
				t.Errorf("prefix length %d, want %d", info.UeIpv6Allocator.PrefixLength(), tc.wantLen)
			}
			if got := info.DNS.IPv6Addr; (got == nil) != (tc.wantDNS == "") || (got != nil && !got.Equal(net.ParseIP(tc.wantDNS))) {
				t.Errorf("IPv6 DNS %v, want %q", got, tc.wantDNS)
			}
			if got := info.PCSCFIPv6; (got == nil) != (tc.wantPCSCF == "") || (got != nil && !got.Equal(net.ParseIP(tc.wantPCSCF))) {
				t.Errorf("IPv6 P-CSCF %v, want %q", got, tc.wantPCSCF)
			}
		})
	}
}

// An IPv4-only IP domain builds the DNN info it built before: no IPv6 field is set.
func TestIpDomainIPv4BuildsNoIPv6(t *testing.T) {
	info := dnnInfoOf(t, nfConfigApi.IpDomain{DnnName: "v4", UeSubnet: testUeV4Subnet, DnsIpv4: testDnsIpv4, Mtu: 1400})
	if info.UeIpv6Allocator != nil || info.DNS.IPv6Addr != nil || info.PCSCFIPv6 != nil {
		t.Errorf("an IPv4 DNN has IPv6 configuration: %+v", info)
	}
	if !info.DNS.IPv4Addr.Equal(net.ParseIP(testDnsIpv4)) || info.MTU != 1400 || !info.HasIpv4Pool() {
		t.Errorf("IPv4 DNN info %+v", info)
	}
}
