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

func dualStackDnn(t *testing.T, v4Pool, v6Pool string) *SnssaiSmfDnnInfo {
	t.Helper()
	info := &SnssaiSmfDnnInfo{MTU: 1400}
	if v4Pool != "" {
		a, err := NewIPAllocator(v4Pool)
		if err != nil {
			t.Fatal(err)
		}
		info.UeIPAllocator = a
	}
	if v6Pool != "" {
		a, err := NewIpv6PrefixAllocator(v6Pool, DefaultUeIpv6PrefixLength)
		if err != nil {
			t.Fatal(err)
		}
		info.UeIpv6Allocator = a
	}
	return info
}

func sessionOfType(dnn *SnssaiSmfDnnInfo, pduSessionType uint8) *SMContext {
	smContext := &SMContext{Supi: testSupi, DNNInfo: dnn, SelectedPDUSessionType: pduSessionType}
	smContext.initLogTags()
	return smContext
}

func TestAllocateUeAddressesByType(t *testing.T) {
	for _, tc := range []struct {
		name       string
		typ        uint8
		want4      bool
		want6      bool
		wantPrefix string
	}{
		{name: nameIPv4, typ: tV4, want4: true},
		{name: nameIPv6, typ: tV6, want6: true, wantPrefix: firstTestPrefix},
		{name: nameIPv4v6, typ: tV4V6, want4: true, want6: true, wantPrefix: firstTestPrefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dnn := dualStackDnn(t, "172.250.0.0/30", "2001:db8:500::/63")
			smContext := sessionOfType(dnn, tc.typ)
			if err := smContext.AllocateUeAddresses(); err != nil {
				t.Fatalf("AllocateUeAddresses: %v", err)
			}
			addr := smContext.PDUAddress
			if addr.HasIpv4() != tc.want4 || addr.HasIpv6() != tc.want6 {
				t.Fatalf("allocated %+v, want IPv4 %t IPv6 %t", addr, tc.want4, tc.want6)
			}
			if tc.want4 && !addr.Ip.Equal(net.ParseIP("172.250.0.1")) {
				t.Errorf("IPv4 = %v, want the pool's first address", addr.Ip)
			}
			if !tc.want4 && addr.Ip != nil {
				t.Errorf("an IPv6 session holds IPv4 %v", addr.Ip)
			}
			if tc.want6 {
				if addr.Ipv6Prefix.String() != tc.wantPrefix {
					t.Errorf("prefix = %s, want %s", addr.Ipv6Prefix, tc.wantPrefix)
				}
				if addr.Ipv6Iid.IsReserved() {
					t.Errorf("interface identifier %s is reserved", addr.Ipv6Iid)
				}
			}
			// Only the families the session carries are taken from their pools.
			if got := AllocatorHolds(dnn.UeIPAllocator, net.ParseIP("172.250.0.1")); got != tc.want4 {
				t.Errorf("IPv4 pool holds the first address: %t, want %t", got, tc.want4)
			}
			if got := len(dnn.UeIpv6Allocator.used); got != map[bool]int{false: 0, true: 1}[tc.want6] {
				t.Errorf("IPv6 pool has %d prefixes in use", got)
			}

			// The release frees both, and a second release is a no-op.
			if err := smContext.ReleaseUeIpAddr(); err != nil {
				t.Fatalf("ReleaseUeIpAddr: %v", err)
			}
			if smContext.PDUAddress.HasIpv4() || smContext.PDUAddress.HasIpv6() {
				t.Errorf("after release the session holds %+v", smContext.PDUAddress)
			}
			if AllocatorHolds(dnn.UeIPAllocator, net.ParseIP("172.250.0.1")) || len(dnn.UeIpv6Allocator.used) != 0 {
				t.Errorf("the release left an address in use")
			}
			if err := smContext.ReleaseUeIpAddr(); err != nil {
				t.Fatalf("second ReleaseUeIpAddr: %v", err)
			}
		})
	}
}

// When the second family cannot be allocated, the first goes back, and the session holds none.
func TestAllocateUeAddressesRollsBack(t *testing.T) {
	dnn := dualStackDnn(t, "172.250.0.0/30", firstTestPrefix)
	first := sessionOfType(dnn, tV6)
	if err := first.AllocateUeAddresses(); err != nil {
		t.Fatal(err)
	}
	second := sessionOfType(dnn, tV4V6)
	if err := second.AllocateUeAddresses(); err == nil {
		t.Fatalf("an IPv4v6 session on an exhausted IPv6 pool was allocated %+v", second.PDUAddress)
	}
	if second.PDUAddress != nil {
		t.Errorf("a failed allocation left %+v", second.PDUAddress)
	}
	if AllocatorHolds(dnn.UeIPAllocator, net.ParseIP("172.250.0.1")) {
		t.Errorf("the IPv4 address of the failed allocation was not returned")
	}

	// A DNN without an IPv6 pool fails the same way.
	noV6 := sessionOfType(dualStackDnn(t, "172.250.0.0/30", ""), tV4V6)
	if err := noV6.AllocateUeAddresses(); err == nil {
		t.Errorf("an IPv4v6 session on a DNN without an IPv6 pool was allocated")
	}
}

func TestAllocateUeAddressesStaticFromSubscription(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		name       string
		static     models.IpAddress
		wantPrefix string
		wantIid    string // empty for a random one
		inPool     bool
		wantErr    bool
	}{
		{
			name: "prefix in the pool", static: models.IpAddress{Ipv6Prefix: str(secondTestPrefix)},
			wantPrefix: secondTestPrefix, inPool: true,
		},
		{
			name: "prefix outside the pool", static: models.IpAddress{Ipv6Prefix: str("2001:db8:900::/64")},
			wantPrefix: "2001:db8:900::/64",
		},
		{
			name: "full address", static: models.IpAddress{Ipv6Addr: str("2001:db8:500:1:a:b:c:d")},
			wantPrefix: secondTestPrefix, wantIid: "000a:000b:000c:000d", inPool: true,
		},
		{
			name: "address with a reserved identifier", static: models.IpAddress{Ipv6Addr: str("2001:db8:900::")},
			wantPrefix: "2001:db8:900::/64",
		},
		{name: "prefix of another length", static: models.IpAddress{Ipv6Prefix: str("2001:db8:500::/60")}, wantErr: true},
		{name: "not IPv6", static: models.IpAddress{Ipv6Prefix: str("10.0.0.0/8")}, wantErr: true},
		{name: "IPv4 only", static: models.IpAddress{Ipv4Addr: str("10.0.0.1")}, wantPrefix: firstTestPrefix, inPool: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dnn := dualStackDnn(t, "", "2001:db8:500::/62")
			smContext := sessionOfType(dnn, tV6)
			smContext.DnnConfiguration.StaticIpAddress = []models.IpAddress{tc.static}
			err := smContext.AllocateUeAddresses()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("allocated %+v, want an error", smContext.PDUAddress)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			addr := smContext.PDUAddress
			if addr.Ipv6Prefix.String() != tc.wantPrefix {
				t.Errorf("prefix = %s, want %s", addr.Ipv6Prefix, tc.wantPrefix)
			}
			if tc.wantIid != "" && addr.Ipv6Iid.String() != tc.wantIid {
				t.Errorf("identifier = %s, want %s", addr.Ipv6Iid, tc.wantIid)
			}
			if addr.Ipv6Iid.IsReserved() {
				t.Errorf("identifier %s is reserved", addr.Ipv6Iid)
			}
			if got := len(dnn.UeIpv6Allocator.used); got != map[bool]int{false: 0, true: 1}[tc.inPool] {
				t.Errorf("%d prefixes of the pool in use, want the static prefix's %t", got, tc.inPool)
			}

			// A second session with the same static prefix of the pool is refused.
			if tc.inPool && tc.static.Ipv4Addr == nil {
				again := sessionOfType(dnn, tV6)
				again.DnnConfiguration.StaticIpAddress = []models.IpAddress{tc.static}
				if err := again.AllocateUeAddresses(); err == nil {
					t.Errorf("the static prefix was given to a second session")
				}
			}
			if err := smContext.ReleaseUeIpAddr(); err != nil {
				t.Fatal(err)
			}
			if len(dnn.UeIpv6Allocator.used) != 0 {
				t.Errorf("the release left the pool with %d prefixes in use", len(dnn.UeIpv6Allocator.used))
			}
		})
	}
}

// The user plane allocates IPv4 only. Adopting its address releases the SMF's IPv4 address and
// leaves the session's IPv6 prefix alone.
func TestReleaseUeIpv4AddrLeavesTheIPv6Prefix(t *testing.T) {
	dnn := dualStackDnn(t, "172.250.0.0/30", "2001:db8:500::/63")
	smContext := sessionOfType(dnn, tV4V6)
	if err := smContext.AllocateUeAddresses(); err != nil {
		t.Fatal(err)
	}
	prefix := *smContext.PDUAddress.Ipv6Prefix
	if err := smContext.ReleaseUeIpv4Addr(); err != nil {
		t.Fatal(err)
	}
	if !smContext.PDUAddress.Ip.Equal(net.IPv4zero) || AllocatorHolds(dnn.UeIPAllocator, net.ParseIP("172.250.0.1")) {
		t.Errorf("IPv4 not released: %v", smContext.PDUAddress.Ip)
	}
	if !smContext.PDUAddress.HasIpv6() || *smContext.PDUAddress.Ipv6Prefix != prefix || len(dnn.UeIpv6Allocator.used) != 1 {
		t.Errorf("the IPv4 release touched the IPv6 prefix: %+v", smContext.PDUAddress)
	}
}

// The IPv4 path is the one the SMF had: the address is the pool's next, Static follows staticIpInfo,
// and nothing else is set.
func TestAllocateUeAddressesIPv4AsBefore(t *testing.T) {
	dnn := dualStackDnn(t, "172.250.0.0/24", "2001:db8:500::/56")
	dnn.UeIPAllocator.ReserveStaticIps(&map[string]string{testSupi: "172.250.0.200"})
	smContext := sessionOfType(dnn, tV4)
	if err := smContext.AllocateUeAddresses(); err != nil {
		t.Fatal(err)
	}
	want := UeIpAddr{Ip: net.ParseIP("172.250.0.200").To4(), Static: true}
	if got := *smContext.PDUAddress; !got.Ip.Equal(want.Ip) || got.Static != want.Static || got.UpfProvided ||
		got.Ipv6Prefix != nil || got.Ipv6Iid != nil {
		t.Errorf("allocated %+v, want %+v", got, want)
	}
	if len(dnn.UeIpv6Allocator.used) != 0 {
		t.Errorf("an IPv4 session took an IPv6 prefix")
	}
}

func TestStaticIpv6PrefixIgnoresOtherEntries(t *testing.T) {
	str := func(s string) *string { return &s }
	_, _, ok, err := staticIpv6Prefix([]models.IpAddress{{Ipv4Addr: str("10.0.0.1")}}, 64)
	if ok || err != nil {
		t.Errorf("an IPv4-only static address gave a prefix: %t, %v", ok, err)
	}
	p, _, ok, err := staticIpv6Prefix([]models.IpAddress{{Ipv4Addr: str("10.0.0.1")}, {Ipv6Prefix: str("2001:db8::/64")}}, 64)
	if !ok || err != nil || p != netip.MustParsePrefix("2001:db8::/64") {
		t.Errorf("staticIpv6Prefix = %s, %t, %v", p, ok, err)
	}
}
