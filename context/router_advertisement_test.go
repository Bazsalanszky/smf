// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"net/netip"
	"testing"
)

// The seam hands a sender the session's prefix and interface identifier, and only for a session
// with IPv6.
func TestAdvertiseIpv6Prefix(t *testing.T) {
	saved := RouterAdvertisementSender
	t.Cleanup(func() { RouterAdvertisementSender = saved })

	var calls int
	var gotPrefix netip.Prefix
	var gotIid InterfaceIdentifier
	RouterAdvertisementSender = func(_ *SMContext, prefix netip.Prefix, iid InterfaceIdentifier) {
		calls++
		gotPrefix, gotIid = prefix, iid
	}

	prefix := netip.MustParsePrefix(firstTestPrefix)
	iid := testIid
	(&SMContext{PDUAddress: &UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &iid}}).AdvertiseIpv6Prefix()
	if calls != 1 || gotPrefix != prefix || gotIid != testIid {
		t.Errorf("%d calls with %s %s, want one with %s %s", calls, gotPrefix, gotIid, prefix, testIid)
	}

	(&SMContext{PDUAddress: &UeIpAddr{Ip: net.ParseIP("10.0.0.1").To4()}}).AdvertiseIpv6Prefix()
	(&SMContext{}).AdvertiseIpv6Prefix()
	if calls != 1 {
		t.Errorf("a session without IPv6 was advertised")
	}

	RouterAdvertisementSender = nil
	(&SMContext{PDUAddress: &UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &iid}}).AdvertiseIpv6Prefix()
}
