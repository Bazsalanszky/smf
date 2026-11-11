// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import "net/netip"

// RouterAdvertisementSender sends the router advertisement that gives a UE its IPv6 prefix (TS
// 23.501 clause 5.8.2.2.2). The UE has only its interface identifier from the PDU address until
// it learns the prefix, so an IPv6 session carries no global traffic before one reaches it. The
// router advertisement service (package ra) sets it while the SMF's GTP-U endpoint runs; nil, the
// SMF sends none. It is called with the session's lock held.
//
// The service also answers router solicitations, which reach it through the session's UP2CP PDR;
// the advertisements go to the UE through its CP2UP PDR (see RouterAdvertisementRules).
var RouterAdvertisementSender func(smContext *SMContext, prefix netip.Prefix, iid InterfaceIdentifier)

// AdvertiseIpv6Prefix is called once the user plane path to the UE is up: when the user plane has
// accepted the access tunnel of the PDU Session Resource Setup Response. That is when an
// unsolicited router advertisement can reach the UE. It hands the session's prefix and interface
// identifier to RouterAdvertisementSender; it does nothing for a session without IPv6, or with no
// sender.
func (smContext *SMContext) AdvertiseIpv6Prefix() {
	send := RouterAdvertisementSender
	if send == nil || !smContext.PDUAddress.HasIpv6() {
		return
	}
	send(smContext, *smContext.PDUAddress.Ipv6Prefix, *smContext.PDUAddress.Ipv6Iid)
}
