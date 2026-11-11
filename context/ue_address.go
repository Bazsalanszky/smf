// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

// SessionHasIpv4 and SessionHasIpv6 report which families a PDU session type carries.
func SessionHasIpv4(pduSessionType uint8) bool {
	return pduSessionType == nasMessage.PDUSessionTypeIPv4 || pduSessionType == nasMessage.PDUSessionTypeIPv4IPv6
}

func SessionHasIpv6(pduSessionType uint8) bool {
	return pduSessionType == nasMessage.PDUSessionTypeIPv6 || pduSessionType == nasMessage.PDUSessionTypeIPv4IPv6
}

// AllocateUeAddresses allocates the UE's address in each family the selected PDU session type
// carries: an IPv4 address from the DNN's IPv4 pool, and an IPv6 prefix from its IPv6 pool with a
// fresh interface identifier. It runs once the type is selected, so a family the session does not
// carry is never taken from its pool. When one family cannot be allocated, the other is released
// again and the session holds no address.
func (smContext *SMContext) AllocateUeAddresses() error {
	addr := &UeIpAddr{}
	if SessionHasIpv4(smContext.SelectedPDUSessionType) {
		ip, err := smContext.DNNInfo.UeIPAllocator.Allocate(smContext.Supi)
		if err != nil {
			return err
		}
		addr.Ip = ip
		addr.Static = smContext.DNNInfo.UeIPAllocator.StaticIpForImsi(smContext.Supi) != nil
	}
	if SessionHasIpv6(smContext.SelectedPDUSessionType) {
		prefix, iid, err := smContext.allocateIpv6Prefix()
		if err != nil {
			if addr.Ip != nil {
				smContext.DNNInfo.UeIPAllocator.Release(smContext.Supi, addr.Ip)
			}
			return err
		}
		addr.Ipv6Prefix, addr.Ipv6Iid = &prefix, &iid
	}
	smContext.PDUAddress = addr
	return nil
}

// allocateIpv6Prefix takes the session's prefix: the subscription's static one when it has one
// (TS 29.503 DnnConfiguration staticIpAddress), claimed from the pool if it is one of the pool's,
// or the next free prefix of the pool. The interface identifier is random, unless the static
// address is a full IPv6 address, whose lower 64 bits are then the identifier.
func (smContext *SMContext) allocateIpv6Prefix() (netip.Prefix, InterfaceIdentifier, error) {
	allocator := smContext.DNNInfo.UeIpv6Allocator
	if !allocator.hasPool() {
		return netip.Prefix{}, InterfaceIdentifier{}, errors.New("IPv6 prefix allocation failed: this DNN has no usable UE IPv6 pool")
	}

	static, staticIid, ok, err := staticIpv6Prefix(smContext.DnnConfiguration.StaticIpAddress, allocator.PrefixLength())
	if err != nil {
		return netip.Prefix{}, InterfaceIdentifier{}, err
	}
	var prefix netip.Prefix
	if ok {
		fromPool, claimErr := allocator.Claim(static)
		if claimErr != nil {
			return netip.Prefix{}, InterfaceIdentifier{}, claimErr
		}
		smContext.SubPduSessLog.Infof("static UE IPv6 prefix %s from the subscription (from the DNN's pool: %t)",
			static, fromPool)
		prefix = static
		if staticIid != nil {
			return prefix, *staticIid, nil
		}
	} else if prefix, err = allocator.Allocate(); err != nil {
		return netip.Prefix{}, InterfaceIdentifier{}, err
	}

	iid, err := NewInterfaceIdentifier()
	if err != nil {
		allocator.Release(prefix)
		return netip.Prefix{}, InterfaceIdentifier{}, err
	}
	return prefix, iid, nil
}

// staticIpv6Prefix finds the static IPv6 prefix among a subscription's static addresses: an
// ipv6Prefix of the DNN's prefix length, or an ipv6Addr, whose prefix of that length is the
// session's and whose lower 64 bits, unless reserved, are the UE's interface identifier.
func staticIpv6Prefix(static []models.IpAddress, prefixLen int) (prefix netip.Prefix, iid *InterfaceIdentifier, ok bool, err error) {
	for _, a := range static {
		switch {
		case a.Ipv6Prefix != nil:
			p, err := netip.ParsePrefix(*a.Ipv6Prefix)
			if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
				return netip.Prefix{}, nil, false, fmt.Errorf("static UE IPv6 prefix %q is not an IPv6 prefix", *a.Ipv6Prefix)
			}
			if p.Bits() != prefixLen {
				return netip.Prefix{}, nil, false, fmt.Errorf("static UE IPv6 prefix %s: the DNN assigns /%d prefixes",
					p, prefixLen)
			}
			return p.Masked(), nil, true, nil
		case a.Ipv6Addr != nil:
			addr, err := netip.ParseAddr(*a.Ipv6Addr)
			if err != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
				return netip.Prefix{}, nil, false, fmt.Errorf("static UE IPv6 address %q is not an IPv6 address", *a.Ipv6Addr)
			}
			p := netip.PrefixFrom(addr, prefixLen).Masked()
			b := addr.As16()
			var id InterfaceIdentifier
			copy(id[:], b[8:])
			if id.IsReserved() {
				return p, nil, true, nil
			}
			return p, &id, true, nil
		}
	}
	return netip.Prefix{}, nil, false, nil
}

// ReleaseUeIpAddr returns the session's addresses to the DNN's pools: the IPv4 address, unless
// the user plane supplied it, and the IPv6 prefix. It is idempotent: an address it has released
// is not released again.
func (smContext *SMContext) ReleaseUeIpAddr() error {
	if err := smContext.ReleaseUeIpv4Addr(); err != nil {
		return err
	}
	smContext.releaseUeIpv6Prefix()
	return nil
}

// releaseUeIpv6Prefix returns the session's IPv6 prefix to the DNN's pool and clears it, with its
// interface identifier. A static prefix that is not one of the pool's is ignored by the pool.
func (smContext *SMContext) releaseUeIpv6Prefix() {
	if smContext.PDUAddress == nil || smContext.PDUAddress.Ipv6Prefix == nil {
		return
	}
	prefix := *smContext.PDUAddress.Ipv6Prefix
	smContext.SubPduSessLog.Infof("Release IPv6 prefix[%s]", prefix)
	if smContext.DNNInfo != nil {
		smContext.DNNInfo.UeIpv6Allocator.Release(prefix)
	}
	smContext.PDUAddress.Ipv6Prefix = nil
	smContext.PDUAddress.Ipv6Iid = nil
}

// Ipv6UEIPAddress adds the session's IPv6 address to a UE IP Address IE (TS 29.244 clause 8.2.62):
// V6 with the UE's full address, the prefix with the interface identifier the SMF gave the UE in
// the PDU address, and IP6PL with the prefix length. The prefix length tells the user plane to
// match the prefix, in which the UE may form other addresses as well (RFC 8981 temporary
// addresses); the identifier is what it checks a link-local source against. The Open5GS SMF sends
// the same address, without IP6PL; the Open5GS UPF keys the session on the /64 and drops a router
// solicitation whose link-local identifier differs from the address's (src/upf/gtp-path.c), so
// a prefix with a zero identifier would not do. A prefix without an identifier is sent as the
// prefix. Nothing is added when the session holds no prefix.
//
// downlink sets S/D, for a PDI whose UE address is the destination (TS 29.244 clause 8.2.62).
// It is set only with an IPv6 part: an IPv4-only IE keeps the S/D of 0 it has always had.
func (a *UeIpAddr) Ipv6UEIPAddress(ueIP *UEIPAddress, downlink bool) {
	if a == nil || a.Ipv6Prefix == nil {
		return
	}
	prefix := a.Ipv6Prefix.Masked()
	addr := prefix.Addr()
	if a.Ipv6Iid != nil {
		addr = Ipv6Address(prefix, *a.Ipv6Iid)
	}
	ueIP.V6 = true
	ueIP.Ipv6Address = net.IP(addr.AsSlice())
	ueIP.IP6PL = true
	ueIP.Ipv6PrefixLength = uint8(prefix.Bits())
	if downlink {
		ueIP.Sd = true
	}
}
