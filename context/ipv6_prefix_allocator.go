// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/omec-project/smf/logger"
)

// DefaultUeIpv6PrefixLength is the length of the prefix given to each IPv6 PDU session when the
// DNN does not configure one: a /64, the prefix TS 23.501 clause 5.8.2.2.1 has the SMF allocate and
// the length stateless address autoconfiguration needs (RFC 4862 clause 5.5.3, RFC 4291 clause 2.5.1).
const DefaultUeIpv6PrefixLength = 64

// maxIpv6PrefixIndexBits bounds the number of prefixes one pool can hold, 2^63, so that a prefix's
// place in the pool fits a uint64 with room to count.
const maxIpv6PrefixIndexBits = 63

// InterfaceIdentifier is the 64-bit IPv6 interface identifier the SMF gives a UE in the PDU address
// (TS 24.501 clause 9.11.4.10). The UE uses it for its link-local address and, after the router
// advertisement, for the address it builds from the session's prefix (TS 23.501 clause 5.8.2.2.2).
//
// Its text form, used in the datastore, is four groups of four hex digits, as the lower half of an
// IPv6 address is written: "0123:4567:89ab:cdef".
type InterfaceIdentifier [8]byte

func (iid InterfaceIdentifier) String() string {
	h := hex.EncodeToString(iid[:])
	return h[0:4] + ":" + h[4:8] + ":" + h[8:12] + ":" + h[12:16]
}

// MarshalText writes the identifier in its text form.
func (iid InterfaceIdentifier) MarshalText() ([]byte, error) {
	return []byte(iid.String()), nil
}

// UnmarshalText reads the text form written by MarshalText.
func (iid *InterfaceIdentifier) UnmarshalText(text []byte) error {
	s := strings.ReplaceAll(string(text), ":", "")
	if len(s) != 2*len(iid) {
		return fmt.Errorf("interface identifier %q: want 16 hex digits", text)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("interface identifier %q: %w", text, err)
	}
	copy(iid[:], b)
	return nil
}

// IsReserved reports whether the identifier is one an address must not be built from: the
// all-zero identifier (the Subnet-Router anycast address, RFC 4291 clause 2.6.1) or one of the
// reserved identifiers RFC 5453 clause 3 lists.
func (iid InterfaceIdentifier) IsReserved() bool {
	v := binary.BigEndian.Uint64(iid[:])
	switch {
	case v == 0:
		return true
	case v >= 0x02005efffe000000 && v <= 0x02005efffeffffff:
		// The reserved IEEE EUI-64 identifiers, proxy mobile IPv6 among them.
		return true
	case v >= 0xfdffffffffffff80 && v <= 0xfdffffffffffffff:
		// The reserved subnet anycast identifiers (RFC 2526).
		return true
	}
	return false
}

// randRead is crypto/rand.Read; tests replace it to make an identifier predictable.
var randRead = rand.Read

// NewInterfaceIdentifier returns a random interface identifier that is not reserved, as the
// agreed UE addressing has it: random and non-zero, chosen per session.
func NewInterfaceIdentifier() (InterfaceIdentifier, error) {
	var iid InterfaceIdentifier
	// A reserved value is drawn with a probability of about 2^-39; a draw that keeps giving one is
	// a broken source, not bad luck.
	for range 16 {
		if _, err := randRead(iid[:]); err != nil {
			return InterfaceIdentifier{}, fmt.Errorf("interface identifier: %w", err)
		}
		if !iid.IsReserved() {
			return iid, nil
		}
	}
	return InterfaceIdentifier{}, errors.New("interface identifier: the random source keeps returning reserved values")
}

// Ipv6Address is the UE's address made of prefix and iid: the prefix's upper 64 bits followed by
// the identifier. The prefix is at most 64 bits long, so nothing of it is overwritten.
func Ipv6Address(prefix netip.Prefix, iid InterfaceIdentifier) netip.Addr {
	b := prefix.Masked().Addr().As16()
	copy(b[8:], iid[:])
	return netip.AddrFrom16(b)
}

// Ipv6PrefixAllocator hands out the per-session IPv6 prefixes of one DNN's pool: prefixes of
// PrefixLength bits taken from the pool prefix, one per IPv6 or IPv4v6 PDU session. It is the IPv6
// counterpart of IPAllocator, which a DNN keeps beside it for IPv4.
//
// Like IPAllocator it keeps its state in memory only. An SMContext read back from MongoDB carries
// an allocator that marshalled as {}, and each method answers that receiver, or a nil one, instead
// of dereferencing it.
type Ipv6PrefixAllocator struct {
	used      map[uint64]bool
	pool      netip.Prefix
	prefixLen int
	count     uint64 // how many prefixes the pool holds
	next      uint64 // where the next search starts
	mu        sync.Mutex
}

// NewIpv6PrefixAllocator builds the allocator for pool, an IPv6 prefix in CIDR notation, handing
// out prefixes of prefixLen bits. prefixLen must be at least the pool's own length and at most 64,
// because the UE's interface identifier is the lower 64 bits of its address.
func NewIpv6PrefixAllocator(pool string, prefixLen int) (*Ipv6PrefixAllocator, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(pool))
	if err != nil {
		return nil, fmt.Errorf("UE IPv6 pool %q: %w", pool, err)
	}
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return nil, fmt.Errorf("UE IPv6 pool %q is not an IPv6 prefix", pool)
	}
	if p.Addr().Zone() != "" {
		return nil, fmt.Errorf("UE IPv6 pool %q has a zone", pool)
	}
	if prefixLen < p.Bits() || prefixLen > 64 {
		return nil, fmt.Errorf("UE IPv6 prefix length /%d for pool %s: want between /%d and /64",
			prefixLen, p, p.Bits())
	}
	bits := prefixLen - p.Bits()
	if bits > maxIpv6PrefixIndexBits {
		return nil, fmt.Errorf("UE IPv6 pool %s holds more than 2^%d /%d prefixes", p, maxIpv6PrefixIndexBits, prefixLen)
	}
	return &Ipv6PrefixAllocator{
		pool:      p.Masked(),
		prefixLen: prefixLen,
		count:     uint64(1) << bits,
		used:      make(map[uint64]bool),
	}, nil
}

func (a *Ipv6PrefixAllocator) hasPool() bool {
	return a != nil && a.used != nil && a.count != 0
}

// Pool is the prefix the allocator hands out of, or the zero Prefix for an allocator with no pool.
func (a *Ipv6PrefixAllocator) Pool() netip.Prefix {
	if !a.hasPool() {
		return netip.Prefix{}
	}
	return a.pool
}

// PrefixLength is the length of each prefix handed out, or 0 for an allocator with no pool.
func (a *Ipv6PrefixAllocator) PrefixLength() int {
	if !a.hasPool() {
		return 0
	}
	return a.prefixLen
}

// prefixAt is the prefix at index i of the pool. The index occupies the bits between the pool's
// length and prefixLen, all within the upper 64 bits of the address.
func (a *Ipv6PrefixAllocator) prefixAt(i uint64) netip.Prefix {
	b := a.pool.Addr().As16()
	hi := binary.BigEndian.Uint64(b[:8]) | i<<(64-a.prefixLen)
	binary.BigEndian.PutUint64(b[:8], hi)
	return netip.PrefixFrom(netip.AddrFrom16(b), a.prefixLen)
}

// indexOf is p's index in the pool, and whether p is one of the pool's prefixes at all.
func (a *Ipv6PrefixAllocator) indexOf(p netip.Prefix) (uint64, bool) {
	if !p.IsValid() || p.Bits() != a.prefixLen || !a.pool.Contains(p.Addr()) {
		return 0, false
	}
	b := p.Masked().Addr().As16()
	return (binary.BigEndian.Uint64(b[:8]) >> (64 - a.prefixLen)) & (a.count - 1), true
}

// Allocate hands out a free prefix. The search starts after the last one handed out, as
// IPAllocator's does, so that a released prefix is not given to the next session at once.
func (a *Ipv6PrefixAllocator) Allocate() (netip.Prefix, error) {
	if !a.hasPool() {
		return netip.Prefix{}, errors.New("IPv6 prefix allocation failed: this DNN has no usable UE IPv6 pool")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if uint64(len(a.used)) >= a.count {
		return netip.Prefix{}, fmt.Errorf("IPv6 prefix allocation failed: all %d /%d prefixes of %s are in use",
			a.count, a.prefixLen, a.pool)
	}
	// A free index is at most len(used) steps away.
	for i := a.next; ; i = (i + 1) & (a.count - 1) {
		if !a.used[i] {
			a.used[i] = true
			a.next = (i + 1) & (a.count - 1)
			p := a.prefixAt(i)
			logger.CtxLog.Infof("allocated UE IPv6 prefix %s, index %d in pool %s", p, i, a.pool)
			return p, nil
		}
	}
}

// Claim takes p out of the pool for a session that holds it statically, from the subscription's
// staticIpAddress. A prefix outside the pool is the operator's to route and needs no reservation:
// Claim reports it as not from the pool and succeeds. A prefix of the pool that is already in use
// is refused.
func (a *Ipv6PrefixAllocator) Claim(p netip.Prefix) (fromPool bool, err error) {
	if !a.hasPool() {
		return false, nil
	}
	if p.Bits() == a.prefixLen && a.pool.Contains(p.Addr()) {
		i, _ := a.indexOf(p)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.used[i] {
			return true, fmt.Errorf("static UE IPv6 prefix %s is already in use", p)
		}
		a.used[i] = true
		return true, nil
	}
	if a.pool.Overlaps(p) {
		return false, fmt.Errorf("static UE IPv6 prefix %s overlaps pool %s but is not one of its /%d prefixes",
			p, a.pool, a.prefixLen)
	}
	return false, nil
}

// Release returns p to the pool. A prefix that is not the pool's is ignored.
func (a *Ipv6PrefixAllocator) Release(p netip.Prefix) {
	if !a.hasPool() {
		logger.CtxLog.Warnf("cannot release UE IPv6 prefix %s: this allocator has no pool, so the release is skipped", p)
		return
	}
	i, ok := a.indexOf(p)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, i)
}
