// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const (
	testUeIpv6Pool = "2001:db8:500::/56"
	// The first two /64 prefixes of 2001:db8:500::/56.
	firstTestPrefix  = "2001:db8:500::/64"
	secondTestPrefix = "2001:db8:500:1::/64"
)

// Subtest names for the three IP PDU session types.
const (
	nameIPv4   = "IPv4"
	nameIPv6   = "IPv6"
	nameIPv4v6 = "IPv4v6"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestNewIpv6PrefixAllocatorValidates(t *testing.T) {
	for _, tc := range []struct {
		pool      string
		prefixLen int
		wantErr   string // empty for success
		wantCount uint64
	}{
		{pool: testUeIpv6Pool, prefixLen: 64, wantCount: 256},
		{pool: firstTestPrefix, prefixLen: 64, wantCount: 1},
		{pool: "2001:db8::/48", prefixLen: 60, wantCount: 4096},
		{pool: "2001:db8:500:1::/56", prefixLen: 64, wantCount: 256}, // host bits are masked, as net.ParseCIDR does for IPv4
		{pool: " 2001:db8:500::/56 ", prefixLen: 64, wantCount: 256},
		{pool: "::/0", prefixLen: 64, wantErr: "more than 2^63"},
		{pool: "2001:db8:500::/56", prefixLen: 48, wantErr: "want between /56 and /64"},
		{pool: "2001:db8:500::/56", prefixLen: 80, wantErr: "want between /56 and /64"},
		{pool: "2001:db8:500::/96", prefixLen: 64, wantErr: "want between /96 and /64"},
		{pool: "10.0.0.0/8", prefixLen: 64, wantErr: "not an IPv6 prefix"},
		{pool: "::ffff:10.0.0.0/104", prefixLen: 104, wantErr: "not an IPv6 prefix"},
		{pool: "2001:db8::", prefixLen: 64, wantErr: "no '/'"},
		{pool: "", prefixLen: 64, wantErr: "UE IPv6 pool"},
	} {
		t.Run(fmt.Sprintf("%s_len%d", tc.pool, tc.prefixLen), func(t *testing.T) {
			a, err := NewIpv6PrefixAllocator(tc.pool, tc.prefixLen)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewIpv6PrefixAllocator(%q, %d) error = %v, want one containing %q",
						tc.pool, tc.prefixLen, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewIpv6PrefixAllocator(%q, %d): %v", tc.pool, tc.prefixLen, err)
			}
			if a.count != tc.wantCount {
				t.Errorf("pool holds %d prefixes, want %d", a.count, tc.wantCount)
			}
			if a.PrefixLength() != tc.prefixLen {
				t.Errorf("PrefixLength() = %d, want %d", a.PrefixLength(), tc.prefixLen)
			}
		})
	}
}

// Every prefix of a pool is handed out once, in order, and then the pool is exhausted; a released
// prefix is handed out again, after the ones not handed out yet.
func TestIpv6PrefixAllocatorExhaustionReleaseAndReuse(t *testing.T) {
	a, err := NewIpv6PrefixAllocator("2001:db8:500::/62", 64)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{firstTestPrefix, secondTestPrefix, "2001:db8:500:2::/64", "2001:db8:500:3::/64"}
	for _, w := range want {
		p, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		if p.String() != w {
			t.Errorf("Allocate() = %s, want %s", p, w)
		}
	}
	if p, err := a.Allocate(); err == nil {
		t.Fatalf("Allocate() on an exhausted pool = %s, want an error", p)
	}

	a.Release(mustPrefix(t, secondTestPrefix))
	a.Release(mustPrefix(t, "2001:db8:500:2::/64"))
	for _, w := range []string{secondTestPrefix, "2001:db8:500:2::/64"} {
		p, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate after release: %v", err)
		}
		if p.String() != w {
			t.Errorf("Allocate() after release = %s, want %s", p, w)
		}
	}

	// Releasing what the pool does not hold changes nothing.
	a.Release(mustPrefix(t, "2001:db8:600::/64"))
	a.Release(mustPrefix(t, "2001:db8:500::/63"))
	if _, err := a.Allocate(); err == nil {
		t.Errorf("a foreign release freed a prefix")
	}
}

func TestIpv6PrefixAllocatorDoesNotReuseAtOnce(t *testing.T) {
	a, err := NewIpv6PrefixAllocator(testUeIpv6Pool, 64)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	a.Release(first)
	second, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Errorf("a released prefix %s was handed out again at once", first)
	}
}

func TestIpv6PrefixAllocatorPrefixLengths(t *testing.T) {
	a, err := NewIpv6PrefixAllocator("2001:db8::/48", 60)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"2001:db8::/60", "2001:db8:0:10::/60", "2001:db8:0:20::/60"} {
		p, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if p.String() != w {
			t.Errorf("Allocate() = %s, want %s", p, w)
		}
	}
}

func TestIpv6PrefixAllocatorClaim(t *testing.T) {
	a, err := NewIpv6PrefixAllocator("2001:db8:500::/62", 64)
	if err != nil {
		t.Fatal(err)
	}
	static := mustPrefix(t, "2001:db8:500:2::/64")

	fromPool, err := a.Claim(static)
	if err != nil || !fromPool {
		t.Fatalf("Claim(%s) = %t, %v; want from the pool", static, fromPool, err)
	}
	if _, err := a.Claim(static); err == nil {
		t.Errorf("a second Claim(%s) succeeded", static)
	}
	// Dynamic allocation goes around the claimed prefix.
	for range 3 {
		p, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if p == static {
			t.Fatalf("Allocate() handed out the claimed %s", static)
		}
	}
	if _, err := a.Allocate(); err == nil {
		t.Errorf("the pool is not exhausted with its last prefix claimed")
	}
	a.Release(static)
	if p, err := a.Allocate(); err != nil || p != static {
		t.Errorf("Allocate() after the static prefix's release = %s, %v; want %s", p, err, static)
	}

	outside := mustPrefix(t, "2001:db8:900::/64")
	if fromPool, err := a.Claim(outside); err != nil || fromPool {
		t.Errorf("Claim(%s) = %t, %v; want a success outside the pool", outside, fromPool, err)
	}
	overlapping := mustPrefix(t, "2001:db8:500::/60")
	if _, err := a.Claim(overlapping); err == nil {
		t.Errorf("Claim(%s), which covers the pool, succeeded", overlapping)
	}
	wrongLength := mustPrefix(t, "2001:db8:500:1::/80")
	if _, err := a.Claim(wrongLength); err == nil {
		t.Errorf("Claim(%s), inside the pool at the wrong length, succeeded", wrongLength)
	}
}

// The two ways an allocator can come without a pool (see Ipv6PrefixAllocator) are answered, never
// dereferenced.
func TestIpv6PrefixAllocatorWithNoPool(t *testing.T) {
	for name, a := range map[string]*Ipv6PrefixAllocator{
		"nil allocator":      nil,
		"restored from JSON": {},
	} {
		t.Run(name, func(t *testing.T) {
			if p, err := a.Allocate(); err == nil {
				t.Errorf("Allocate() = %s, want an error", p)
			}
			if fromPool, err := a.Claim(mustPrefix(t, "2001:db8::/64")); err != nil || fromPool {
				t.Errorf("Claim = %t, %v; want false, nil", fromPool, err)
			}
			a.Release(mustPrefix(t, "2001:db8::/64"))
			if a.Pool().IsValid() || a.PrefixLength() != 0 {
				t.Errorf("Pool() = %s, PrefixLength() = %d; want neither", a.Pool(), a.PrefixLength())
			}
		})
	}
}

func TestNewInterfaceIdentifierIsRandomAndNotReserved(t *testing.T) {
	seen := map[InterfaceIdentifier]bool{}
	for range 1000 {
		iid, err := NewInterfaceIdentifier()
		if err != nil {
			t.Fatal(err)
		}
		if iid == (InterfaceIdentifier{}) || iid.IsReserved() {
			t.Fatalf("NewInterfaceIdentifier() = %s, a reserved identifier", iid)
		}
		if seen[iid] {
			t.Fatalf("NewInterfaceIdentifier() returned %s twice", iid)
		}
		seen[iid] = true
	}
}

func TestNewInterfaceIdentifierSkipsReservedDraws(t *testing.T) {
	draws := [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0x02, 0x00, 0x5e, 0xff, 0xfe, 0x00, 0x52, 0x13},
		{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
		{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
	}
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	randRead = func(b []byte) (int, error) {
		d := draws[0]
		draws = draws[1:]
		return copy(b, d), nil
	}
	iid, err := NewInterfaceIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	if iid.String() != "1234:5678:9abc:def0" {
		t.Errorf("NewInterfaceIdentifier() = %s, want the first unreserved draw", iid)
	}

	randRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := NewInterfaceIdentifier(); err == nil {
		t.Errorf("NewInterfaceIdentifier() with a failing source succeeded")
	}
	randRead = func(b []byte) (int, error) { clear(b); return len(b), nil }
	if _, err := NewInterfaceIdentifier(); err == nil {
		t.Errorf("NewInterfaceIdentifier() with a source of zeros succeeded")
	}
}

func TestInterfaceIdentifierIsReserved(t *testing.T) {
	for _, tc := range []struct {
		iid  string
		want bool
	}{
		{"0000:0000:0000:0000", true},
		{"0000:0000:0000:0001", false},
		{"0200:5eff:fdff:ffff", false},
		{"0200:5eff:fe00:0000", true},
		{"0200:5eff:fe00:5213", true},
		{"0200:5eff:feff:ffff", true},
		{"0200:5eff:ff00:0000", false},
		{"fdff:ffff:ffff:ff7f", false},
		{"fdff:ffff:ffff:ff80", true},
		{"fdff:ffff:ffff:ffff", true},
		{"fe00:0000:0000:0000", false},
		{"ffff:ffff:ffff:ffff", false},
	} {
		var iid InterfaceIdentifier
		if err := iid.UnmarshalText([]byte(tc.iid)); err != nil {
			t.Fatal(err)
		}
		if got := iid.IsReserved(); got != tc.want {
			t.Errorf("%s.IsReserved() = %t, want %t", tc.iid, got, tc.want)
		}
	}
}

func TestInterfaceIdentifierText(t *testing.T) {
	iid := InterfaceIdentifier{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	text, err := iid.MarshalText()
	if err != nil || string(text) != "0123:4567:89ab:cdef" {
		t.Fatalf("MarshalText() = %q, %v", text, err)
	}
	var back InterfaceIdentifier
	if err := back.UnmarshalText(text); err != nil || back != iid {
		t.Fatalf("UnmarshalText(%q) = %s, %v", text, back, err)
	}
	for _, bad := range []string{"", "0123:4567:89ab", "0123:4567:89ab:cdef:00", "0123:4567:89ab:cdeg"} {
		if err := back.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) succeeded", bad)
		}
	}
}

func TestIpv6Address(t *testing.T) {
	iid := InterfaceIdentifier{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	got := Ipv6Address(mustPrefix(t, "2001:db8:500:7::/64"), iid)
	if got.String() != "2001:db8:500:7:123:4567:89ab:cdef" {
		t.Errorf("Ipv6Address = %s", got)
	}
}
