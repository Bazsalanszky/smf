// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import "net/netip"

// RouterAdvertisementSender sends the router advertisement that gives a UE its IPv6 prefix (TS
// 23.501 clause 5.8.2.2.2). The UE has only its interface identifier from the PDU address until
// it learns the prefix, so an IPv6 session carries no global traffic before one reaches it. Nil
// here: the SMF sends none.
//
// TODO(ipv6-p3-ra): the SMF sends no router advertisement. The sender needs an SMF GTP-U endpoint,
// a UP2CP PDR (Source Interface Access, SDF "permit out 58 from ff02::2/128 to assigned", a
// precedence below the 255 of the default uplink PDR on the same F-TEID) with a FAR to the SMF and
// a CP2UP PDR (Source Interface CP-function) on the downlink FAR, to answer
// router solicitations, plus an unsolicited advertisement once the N3 tunnel is up: hence the
// hook in AdvertiseIpv6Prefix. See docs/lab/open5gs-ra-path.md for the Open5GS model.
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
