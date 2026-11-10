// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// AddressFamily names an IP address family in configuration: the family preferred for
// N4 name resolution (pfcp.preferredFamily) and the per-UPF N3/N9 transport family
// (upfTransportFamily). The zero value, AddressFamilyAuto, means "no preference".
type AddressFamily uint8

const (
	AddressFamilyAuto AddressFamily = iota
	AddressFamilyIPv4
	AddressFamilyIPv6
)

// ParseAddressFamily reads a configured family: "ipv4" or "ipv6", in any case, or "" /
// "auto" for no preference.
func ParseAddressFamily(s string) (AddressFamily, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return AddressFamilyAuto, nil
	case "ipv4":
		return AddressFamilyIPv4, nil
	case "ipv6":
		return AddressFamilyIPv6, nil
	default:
		return AddressFamilyAuto, fmt.Errorf("unknown address family %q (want ipv4, ipv6 or auto)", s)
	}
}

func (f AddressFamily) String() string {
	switch f {
	case AddressFamilyIPv4:
		return "ipv4"
	case AddressFamilyIPv6:
		return "ipv6"
	default:
		return "auto"
	}
}

// has reports whether ip belongs to family f. AddressFamilyAuto matches any address.
func (f AddressFamily) has(ip net.IP) bool {
	switch f {
	case AddressFamilyIPv4:
		return ip.To4() != nil
	case AddressFamilyIPv6:
		return ip.To4() == nil && ip.To16() != nil
	default:
		return ip != nil
	}
}

// other returns the other family; for AddressFamilyAuto it returns AddressFamilyAuto.
func (f AddressFamily) other() AddressFamily {
	switch f {
	case AddressFamilyIPv4:
		return AddressFamilyIPv6
	case AddressFamilyIPv6:
		return AddressFamilyIPv4
	default:
		return AddressFamilyAuto
	}
}

// n4PreferredFamily is the family tried first when a UPF's FQDN Node ID has addresses of
// both families. It is set once by InitSmfContext and read from every PFCP path.
var n4PreferredFamily atomic.Uint32

// SetN4PreferredFamily sets the family ResolveIP prefers. AddressFamilyAuto means IPv4.
func SetN4PreferredFamily(f AddressFamily) {
	n4PreferredFamily.Store(uint32(f))
}

// N4PreferredFamily returns the family ResolveIP prefers; it is never AddressFamilyAuto.
func N4PreferredFamily() AddressFamily {
	if f := AddressFamily(n4PreferredFamily.Load()); f == AddressFamilyIPv6 {
		return f
	}
	return AddressFamilyIPv4
}

// selectAddress picks one address out of a resolver answer: the first address of the
// preferred family, in the resolver's order, or failing that the first of the other
// family. The result is in 16-byte form, as net.ParseIP returns it, which is the form the
// DNS cache has always held. It returns nil for an empty answer.
//
// Taking the answer's first entry, as the SMF used to, left the A-versus-AAAA choice to
// the resolver's RFC 6724 sort, which depends on the host's routes, so the same name
// could resolve to a different family on two SMF replicas.
func selectAddress(ips []net.IP, preferred AddressFamily) net.IP {
	if preferred == AddressFamilyAuto {
		preferred = AddressFamilyIPv4
	}
	for _, family := range []AddressFamily{preferred, preferred.other()} {
		for _, ip := range ips {
			if family.has(ip) {
				return ip.To16()
			}
		}
	}
	return nil
}

type ipLookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// ipLookupOverride, when set, answers lookupIP instead of the system resolver. It exists so
// tests can resolve names without DNS; it is atomic because the cache refresh goroutine
// started in init resolves concurrently with them.
var ipLookupOverride atomic.Pointer[ipLookupFunc]

func lookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if f := ipLookupOverride.Load(); f != nil {
		return (*f)(ctx, network, host)
	}
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// lookupNodeAddress resolves a node's FQDN to one address, chosen by selectAddress with
// N4PreferredFamily.
func lookupNodeAddress(host string) (net.IP, error) {
	ips, err := lookupIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	ip := selectAddress(ips, N4PreferredFamily())
	if ip == nil {
		return nil, fmt.Errorf("host [%s] has no IP address", host)
	}
	return ip, nil
}

// lookupFamilyAddress resolves host to the first address of one family, for a caller that
// needs a given family rather than the preferred one (the UPF transport override).
func lookupFamilyAddress(host string, family AddressFamily) (net.IP, error) {
	network := "ip"
	switch family {
	case AddressFamilyIPv4:
		network = "ip4"
	case AddressFamilyIPv6:
		network = "ip6"
	}
	ips, err := lookupIP(context.Background(), network, host)
	if err != nil {
		return nil, err
	}
	if ip := selectAddress(ips, family); ip != nil && family.has(ip) {
		return ip, nil
	}
	return nil, fmt.Errorf("host [%s] has no %s address", host, family)
}
