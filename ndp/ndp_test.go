// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package ndp

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// The goldens below were computed with an independent implementation (Python struct packing and
// an RFC 1071 sum over the RFC 8200 pseudo-header), not with this package.
const (
	// fe80::1 -> ff02::1, cur hop limit 64, M=O=0, router lifetime 64800 s, reachable/retrans 0;
	// PIO 2001:db8:500:1::/64, L=0 A=1, infinite lifetimes; MTU 1400. Checksum 0xbe6e.
	goldenUnsolicitedRA = "6000000000383aff" +
		"fe800000000000000000000000000001" +
		"ff020000000000000000000000000001" +
		"8600be6e4000fd200000000000000000" +
		"03044040ffffffffffffffff00000000" +
		"20010db8050000010000000000000000" +
		"0501000000000578"
	// fe80::1 -> fe80::1234:5678:9abc:def0, the same without MTU option. Checksum 0xe718.
	goldenSolicitedRA = "6000000000303aff" +
		"fe800000000000000000000000000001" +
		"fe80000000000000123456789abcdef0" +
		"8600e7184000fd200000000000000000" +
		"03044040ffffffffffffffff00000000" +
		"20010db8050000010000000000000000"
	// fe80::1234:5678:9abc:def0 -> ff02::2, no option. Checksum 0x9add.
	goldenRS = "6000000000083aff" +
		"fe80000000000000123456789abcdef0" +
		"ff020000000000000000000000000002" +
		"85009add00000000"
	// :: -> ff02::2. Checksum 0x7bb8.
	goldenRSUnspecified = "6000000000083aff" +
		"00000000000000000000000000000000" +
		"ff020000000000000000000000000002" +
		"85007bb800000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sessionRA(mtu uint32) *RouterAdvertisement {
	return &RouterAdvertisement{
		Prefix:            netip.MustParsePrefix("2001:db8:500:1::/64"),
		CurHopLimit:       64,
		RouterLifetime:    64800,
		Autonomous:        true,
		ValidLifetime:     InfiniteLifetime,
		PreferredLifetime: InfiniteLifetime,
		MTU:               mtu,
	}
}

func TestRouterAdvertisementBytes(t *testing.T) {
	ue := netip.MustParseAddr("fe80::1234:5678:9abc:def0")
	for _, tc := range []struct {
		name   string
		ra     *RouterAdvertisement
		dst    netip.Addr
		golden string
	}{
		{"unsolicited with MTU", sessionRA(1400), AllNodes, goldenUnsolicitedRA},
		{"solicited without MTU", sessionRA(0), ue, goldenSolicitedRA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.ra.Marshal(netip.MustParseAddr("fe80::1"), tc.dst)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, tc.golden); !bytes.Equal(got, want) {
				t.Fatalf("RA\n got %x\nwant %x", got, want)
			}
			// The checksum verifies over the pseudo-header: summing the message with it gives 0.
			if sum := checksum(netip.MustParseAddr("fe80::1"), tc.dst, got[ipv6HeaderLen:]); sum != 0 {
				t.Fatalf("checksum residue %#x", sum)
			}
		})
	}
}

func TestRouterAdvertisementFlagsAndPrefix(t *testing.T) {
	ra := sessionRA(0)
	ra.Managed, ra.Other, ra.OnLink = true, true, true
	ra.Prefix = netip.MustParsePrefix("2001:db8:500:1:ffff::/56") // host bits are masked off
	got, err := ra.Marshal(netip.MustParseAddr("fe80::1"), AllNodes)
	if err != nil {
		t.Fatal(err)
	}
	icmp := got[ipv6HeaderLen:]
	if icmp[5] != 0xc0 {
		t.Errorf("M/O flags %#x, want 0xc0", icmp[5])
	}
	if icmp[16+2] != 56 || icmp[16+3] != 0xc0 {
		t.Errorf("PIO length/flags %d/%#x, want 56/0xc0", icmp[16+2], icmp[16+3])
	}
	if p := netip.AddrFrom16([16]byte(icmp[32:48])); p != netip.MustParseAddr("2001:db8:500::") {
		t.Errorf("PIO prefix %s", p)
	}
	if checksum(netip.MustParseAddr("fe80::1"), AllNodes, icmp) != 0 {
		t.Error("checksum does not verify")
	}
}

func TestRouterAdvertisementRefusesNonIPv6(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	ll := netip.MustParseAddr("fe80::1")
	for _, tc := range []struct {
		name     string
		src, dst netip.Addr
		prefix   netip.Prefix
	}{
		{"IPv4 source", v4, AllNodes, netip.MustParsePrefix("2001:db8::/64")},
		{"mapped destination", ll, mapped, netip.MustParsePrefix("2001:db8::/64")},
		{"IPv4 prefix", ll, AllNodes, netip.MustParsePrefix("10.0.0.0/8")},
		{"no prefix", ll, AllNodes, netip.Prefix{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ra := sessionRA(0)
			ra.Prefix = tc.prefix
			if _, err := ra.Marshal(tc.src, tc.dst); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

func TestParseRouterSolicitation(t *testing.T) {
	rs, err := ParseRouterSolicitation(mustHex(t, goldenRS))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Source != netip.MustParseAddr("fe80::1234:5678:9abc:def0") || rs.Destination != AllRouters {
		t.Fatalf("got %+v", rs)
	}
	rs, err = ParseRouterSolicitation(mustHex(t, goldenRSUnspecified))
	if err != nil {
		t.Fatal(err)
	}
	if !rs.Source.IsUnspecified() {
		t.Fatalf("source %s", rs.Source)
	}
}

// withHopByHop inserts an 8-octet hop-by-hop options header (PadN) before the ICMPv6 message, as an
// MLD-aware stack may, and fixes the lengths. The ICMPv6 checksum does not cover it.
func withHopByHop(pkt []byte) []byte {
	out := append([]byte{}, pkt[:ipv6HeaderLen]...)
	out[6] = nextHeaderHopByHop
	out[5] += 8
	out = append(out, nextHeaderICMPv6, 0, 1, 4, 0, 0, 0, 0)
	return append(out, pkt[ipv6HeaderLen:]...)
}

func TestParseRouterSolicitationWalksExtensionHeaders(t *testing.T) {
	rs, err := ParseRouterSolicitation(withHopByHop(mustHex(t, goldenRS)))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Destination != AllRouters {
		t.Fatalf("got %+v", rs)
	}
}

// fixChecksum recomputes the ICMPv6 checksum of an IPv6 packet without extension headers.
func fixChecksum(pkt []byte) []byte {
	icmp := pkt[ipv6HeaderLen:]
	icmp[2], icmp[3] = 0, 0
	sum := checksum(netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), icmp)
	icmp[2], icmp[3] = byte(sum>>8), byte(sum)
	return pkt
}

func TestParseRouterSolicitationRefuses(t *testing.T) {
	good := func() []byte { return mustHex(t, goldenRS) }
	slla := func() []byte {
		// :: with a Source Link-Layer Address option.
		pkt := mustHex(t, goldenRSUnspecified)
		pkt = append(pkt, optSourceLinkLayerAddress, 1, 2, 0, 0, 0, 0, 1)
		pkt[5] = 16
		return fixChecksum(pkt)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{"short", func(b []byte) []byte { return b[:20] }, "IPv6 header"},
		{"IPv4", func(b []byte) []byte { b[0] = 0x45; return b }, "version"},
		{"truncated payload", func(b []byte) []byte { return b[:len(b)-1] }, "payload length"},
		{"forwarded (hop limit 254)", func(b []byte) []byte { b[7] = 254; return b }, "hop limit"},
		{"UDP", func(b []byte) []byte { b[6] = 17; return b }, "not ICMPv6"},
		{"fragment", func(b []byte) []byte { b[6] = nextHeaderFragment; return b }, "fragmented"},
		{"echo request", func(b []byte) []byte { b[ipv6HeaderLen] = 128; return b }, "type 128"},
		{"code 1", func(b []byte) []byte { b[ipv6HeaderLen+1] = 1; return b }, "code 1"},
		{"bad checksum", func(b []byte) []byte { b[ipv6HeaderLen+3] ^= 1; return b }, "checksum"},
		{"zero-length option", func(b []byte) []byte {
			b = append(b, 1, 0, 0, 0, 0, 0, 0, 0)
			b[5] = 16
			return fixChecksum(b)
		}, "length 0"},
		{"SLLA from ::", func([]byte) []byte { return slla() }, "unspecified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRouterSolicitation(tc.mutate(good()))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestLinkLocal(t *testing.T) {
	if got := LinkLocal([8]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}); got != netip.MustParseAddr("fe80::1234:5678:9abc:def0") {
		t.Fatalf("got %s", got)
	}
}
