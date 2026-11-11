// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

// Package ndp encodes the router advertisements and decodes the router solicitations (RFC 4861)
// that the SMF exchanges with the UE of an IPv6 PDU session, through the UPF (TS 23.501 clause
// 5.8.2.2.2, TS 29.061 clause 11.2.1.3). It works on whole IPv6 packets, which is what a G-PDU
// carries.
package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipv6HeaderLen = 40

	nextHeaderHopByHop = 0
	nextHeaderRouting  = 43
	nextHeaderFragment = 44
	nextHeaderNone     = 59
	nextHeaderDestOpts = 60
	nextHeaderICMPv6   = 58

	icmpTypeRouterSolicitation  = 133
	icmpTypeRouterAdvertisement = 134

	optSourceLinkLayerAddress = 1
	optPrefixInformation      = 3
	optMTU                    = 5

	// hopLimitND is the IP hop limit of every neighbor discovery message (RFC 4861 clause 6.1.1,
	// 6.1.2): a receiver discards one with any other, which proves it was not forwarded.
	hopLimitND = 255

	// MinIPv6MTU is the smallest link MTU IPv6 allows (RFC 8200 clause 5). An MTU option below it
	// would be ignored by the UE, so none is sent.
	MinIPv6MTU = 1280

	// InfiniteLifetime is the all-ones prefix lifetime that never expires (RFC 4861 clause 4.6.2).
	InfiniteLifetime = 0xffffffff
)

// AllNodes and AllRouters are the link-local multicast groups ff02::1 and ff02::2.
var (
	AllNodes   = netip.MustParseAddr("ff02::1")
	AllRouters = netip.MustParseAddr("ff02::2")
)

// RouterSolicitation is what the SMF needs from a router solicitation: who sent it, to whom.
type RouterSolicitation struct {
	Source      netip.Addr
	Destination netip.Addr
}

// ParseRouterSolicitation validates an IPv6 packet as a router solicitation, as RFC 4861 clause
// 6.1.1 has a router do, and returns its addresses. Extension headers before ICMPv6 are walked; a
// fragment is refused, as neighbor discovery messages are never fragmented. The ICMPv6 checksum is
// checked. Options are only checked for a non-zero length; a solicitation from the unspecified
// address must not carry a Source Link-Layer Address option.
func ParseRouterSolicitation(pkt []byte) (*RouterSolicitation, error) {
	if len(pkt) < ipv6HeaderLen {
		return nil, fmt.Errorf("IPv6 header: %d octets", len(pkt))
	}
	if pkt[0]>>4 != 6 {
		return nil, fmt.Errorf("IP version %d, not 6", pkt[0]>>4)
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if ipv6HeaderLen+payloadLen > len(pkt) {
		return nil, fmt.Errorf("IPv6 payload length %d exceeds the %d octets present", payloadLen, len(pkt)-ipv6HeaderLen)
	}
	if hop := pkt[7]; hop != hopLimitND {
		return nil, fmt.Errorf("hop limit %d, not %d", hop, hopLimitND)
	}
	src := netip.AddrFrom16([16]byte(pkt[8:24]))
	dst := netip.AddrFrom16([16]byte(pkt[24:40]))

	next := pkt[6]
	payload := pkt[ipv6HeaderLen : ipv6HeaderLen+payloadLen]
	for next != nextHeaderICMPv6 {
		switch next {
		case nextHeaderHopByHop, nextHeaderRouting, nextHeaderDestOpts:
			if len(payload) < 8 {
				return nil, fmt.Errorf("extension header %d truncated", next)
			}
			n := (int(payload[1]) + 1) * 8
			if n > len(payload) {
				return nil, fmt.Errorf("extension header %d: %d octets, %d left", next, n, len(payload))
			}
			next = payload[0]
			payload = payload[n:]
		case nextHeaderFragment:
			return nil, errors.New("fragmented neighbor discovery message")
		case nextHeaderNone:
			return nil, errors.New("no next header")
		default:
			return nil, fmt.Errorf("next header %d, not ICMPv6", next)
		}
	}

	if len(payload) < 8 {
		return nil, fmt.Errorf("ICMPv6 router solicitation: %d octets, need 8", len(payload))
	}
	if payload[0] != icmpTypeRouterSolicitation {
		return nil, fmt.Errorf("ICMPv6 type %d, not a router solicitation", payload[0])
	}
	if payload[1] != 0 {
		return nil, fmt.Errorf("router solicitation code %d, not 0", payload[1])
	}
	if sum := checksum(src, dst, payload); sum != 0 {
		return nil, fmt.Errorf("ICMPv6 checksum mismatch (residue %#04x)", sum)
	}
	for opts := payload[8:]; len(opts) > 0; {
		if len(opts) < 2 || opts[1] == 0 {
			return nil, errors.New("router solicitation option with length 0")
		}
		n := int(opts[1]) * 8
		if n > len(opts) {
			return nil, fmt.Errorf("router solicitation option %d: %d octets, %d left", opts[0], n, len(opts))
		}
		if opts[0] == optSourceLinkLayerAddress && src.IsUnspecified() {
			return nil, errors.New("source link-layer address option from the unspecified address")
		}
		opts = opts[n:]
	}
	return &RouterSolicitation{Source: src, Destination: dst}, nil
}

// RouterAdvertisement holds the fields of a router advertisement with one Prefix Information
// option and an optional MTU option (RFC 4861 clauses 4.2, 4.6.2 and 4.6.4).
type RouterAdvertisement struct {
	// Prefix is the session's prefix, advertised in the Prefix Information option.
	Prefix netip.Prefix
	// ReachableTime and RetransTimer are in milliseconds; 0 leaves the UE's own values.
	ReachableTime uint32
	RetransTimer  uint32
	// ValidLifetime and PreferredLifetime are the prefix's, in seconds.
	ValidLifetime     uint32
	PreferredLifetime uint32
	// MTU is the link MTU; 0 sends no MTU option.
	MTU uint32
	// RouterLifetime is in seconds; 0 says the router is not a default router.
	RouterLifetime uint16
	// CurHopLimit is the hop limit the UE uses for its packets; 0 leaves its own.
	CurHopLimit uint8
	// Managed and Other are the M and O flags (DHCPv6 for addresses or for other configuration).
	Managed bool
	Other   bool
	// OnLink and Autonomous are the prefix's L and A flags.
	OnLink     bool
	Autonomous bool
}

// Marshal returns the advertisement as an IPv6 packet from src to dst: hop limit 255, traffic
// class and flow label 0, with the ICMPv6 checksum over the pseudo-header (RFC 4443 clause 2.3,
// RFC 8200 clause 8.1).
func (ra *RouterAdvertisement) Marshal(src, dst netip.Addr) ([]byte, error) {
	if !src.Is6() || src.Is4In6() || !dst.Is6() || dst.Is4In6() {
		return nil, fmt.Errorf("router advertisement from %s to %s: both must be IPv6", src, dst)
	}
	if !ra.Prefix.IsValid() || !ra.Prefix.Addr().Is6() || ra.Prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("router advertisement prefix %s is not an IPv6 prefix", ra.Prefix)
	}

	icmpLen := 16 + 32
	if ra.MTU != 0 {
		icmpLen += 8
	}
	pkt := make([]byte, ipv6HeaderLen+icmpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = nextHeaderICMPv6
	pkt[7] = hopLimitND
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])

	icmp := pkt[ipv6HeaderLen:]
	icmp[0] = icmpTypeRouterAdvertisement
	icmp[4] = ra.CurHopLimit
	if ra.Managed {
		icmp[5] |= 0x80
	}
	if ra.Other {
		icmp[5] |= 0x40
	}
	binary.BigEndian.PutUint16(icmp[6:8], ra.RouterLifetime)
	binary.BigEndian.PutUint32(icmp[8:12], ra.ReachableTime)
	binary.BigEndian.PutUint32(icmp[12:16], ra.RetransTimer)

	pio := icmp[16:48]
	pio[0] = optPrefixInformation
	pio[1] = 4
	pio[2] = uint8(ra.Prefix.Bits())
	if ra.OnLink {
		pio[3] |= 0x80
	}
	if ra.Autonomous {
		pio[3] |= 0x40
	}
	binary.BigEndian.PutUint32(pio[4:8], ra.ValidLifetime)
	binary.BigEndian.PutUint32(pio[8:12], ra.PreferredLifetime)
	p := ra.Prefix.Masked().Addr().As16()
	copy(pio[16:32], p[:])

	if ra.MTU != 0 {
		mtu := icmp[48:56]
		mtu[0] = optMTU
		mtu[1] = 1
		binary.BigEndian.PutUint32(mtu[4:8], ra.MTU)
	}

	binary.BigEndian.PutUint16(icmp[2:4], checksum(src, dst, icmp))
	return pkt, nil
}

// checksum is the ICMPv6 checksum of msg from src to dst (RFC 4443 clause 2.3): the one's
// complement of the one's complement sum over the IPv6 pseudo-header (RFC 8200 clause 8.1) and the
// message. Over a message that already carries its checksum it is 0.
func checksum(src, dst netip.Addr, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add(s[:])
	add(d[:])
	var lenAndNext [8]byte
	binary.BigEndian.PutUint32(lenAndNext[0:4], uint32(len(msg)))
	lenAndNext[7] = nextHeaderICMPv6
	add(lenAndNext[:])
	add(msg)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// LinkLocal returns the link-local address fe80::/64 with the interface identifier iid, the
// address the UE of a PDU session takes from the identifier in its PDU address (TS 23.501 clause
// 5.8.2.2.2).
func LinkLocal(iid [8]byte) netip.Addr {
	var a [16]byte
	a[0], a[1] = 0xfe, 0x80
	copy(a[8:], iid[:])
	return netip.AddrFrom16(a)
}
