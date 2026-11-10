// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/omec-project/smf/logger"
)

const (
	NodeIdTypeIpv4Address uint8 = iota
	NodeIdTypeIpv6Address
	NodeIdTypeFqdn
)

type NodeID struct {
	NodeIdValue []byte
	NodeIdType  uint8 // 0x00001111
}

// dnsHostIpCacheMu guards dnsHostIpCache and dnsHostIpGen: they're read/written from
// PFCP/session handling goroutines (via ResolveNodeIdToIp) and from the periodic refresh
// goroutine below. dnsHostIpGen counts writes (inserts, refresh updates, and refresh
// deletes) per host, so a refresh that ran without the lock held can tell whether the
// entry it observed was touched by someone else in the meantime, even if that other
// write happened to land on the same value or removed the entry outright.
var (
	dnsHostIpCache   map[string]net.IP
	dnsHostIpGen     map[string]uint64
	dnsHostIpCacheMu sync.RWMutex
)

func NewNodeID(nodeID string) *NodeID {
	ip := net.ParseIP(nodeID)
	if ip == nil {
		return &NodeID{
			NodeIdType:  NodeIdTypeFqdn,
			NodeIdValue: []byte(nodeID),
		}
	} else if ip.To4() != nil {
		return &NodeID{
			NodeIdType:  NodeIdTypeIpv4Address,
			NodeIdValue: ip.To4(),
		}
	} else {
		return &NodeID{
			NodeIdType:  NodeIdTypeIpv6Address,
			NodeIdValue: ip.To16(),
		}
	}
}

func (n *NodeID) Equal(other NodeID) bool {
	if n.NodeIdType != other.NodeIdType {
		return false
	}
	return bytes.Equal(n.NodeIdValue, other.NodeIdValue)
}

// ResolveNodeIdToIp returns the address of the node: the value itself for an IP Node ID,
// and the cached or freshly resolved address for an FQDN (see ResolveIP). It returns nil
// when the name does not resolve; it used to return 0.0.0.0, which callers could not tell
// apart from a real address and which compared equal for any two unresolvable nodes.
func (n *NodeID) ResolveNodeIdToIp() net.IP {
	ip, err := n.ResolveIP()
	if err != nil {
		return nil
	}
	return ip
}

// ResolveIP is ResolveNodeIdToIp with the failure reported. An FQDN is looked up in the
// SMF DNS cache first; on a miss it is resolved and the cache updated. When the name has
// addresses of both families, the one returned is chosen by N4PreferredFamily (see
// selectAddress), so the choice no longer depends on the order the resolver happens to
// return them in.
func (n *NodeID) ResolveIP() (net.IP, error) {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		return n.NodeIdValue, nil
	case NodeIdTypeFqdn:
		host := string(n.NodeIdValue)
		if ip, err := getDnsHostIp(host); err == nil {
			logger.CtxLog.Debugf("host [%v] found in smf dns cache", host)
			return ip, nil
		}
		logger.CtxLog.Warnf("host [%v] not found in smf dns cache", host)
		ip, err := lookupNodeAddress(host)
		if err != nil {
			logger.CtxLog.Warnf("host lookup failed: %+v", err)
			return nil, err
		}
		logger.CtxLog.Infof("host [%v] dns resolved, updating smf dns cache", host)
		InsertDnsHostIp(host, ip)
		return ip, nil
	default:
		return nil, fmt.Errorf("unknown node id type %d", n.NodeIdType)
	}
}

// ValueString returns the Node ID in the text form ie.NewNodeIDHeuristic maps back to the
// same Node ID type: the address for an IPv4 or IPv6 Node ID, the name for an FQDN. Unlike
// ResolveNodeIdToIp().String() it never resolves, so an FQDN stays an FQDN on the wire.
func (n *NodeID) ValueString() string {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		// An unset value prints "<nil>", as ResolveNodeIdToIp().String() did, so an SMF
		// whose Node ID was never set still sends a (meaningless) Node ID IE rather than none.
		return net.IP(n.NodeIdValue).String()
	default:
		return string(n.NodeIdValue)
	}
}

// sameNode reports whether a and b identify the same node. Two Node IDs of one type are
// compared by value (IP addresses with net.IP.Equal, so a 4-byte and a 16-byte form of one
// IPv4 address are the same node). An FQDN and an IP Node ID are compared by the address
// the FQDN resolves to, and only when both sides have one: an unresolvable name is not
// equal to anything. An IPv4 and an IPv6 Node ID are never the same node.
//
// It replaces a reflect.DeepEqual of the two addresses' To4() forms, which is nil for any
// IPv6 address, so every IPv6 node compared equal to every other one.
func sameNode(a, b NodeID) bool {
	if a.NodeIdType == b.NodeIdType {
		if a.NodeIdType == NodeIdTypeFqdn {
			return bytes.Equal(a.NodeIdValue, b.NodeIdValue)
		}
		return net.IP(a.NodeIdValue).Equal(net.IP(b.NodeIdValue))
	}
	if a.NodeIdType != NodeIdTypeFqdn && b.NodeIdType != NodeIdTypeFqdn {
		return false
	}
	aIP := a.ResolveNodeIdToIp()
	bIP := b.ResolveNodeIdToIp()
	logger.CtxLog.Debugf("compare node ids by address: [%v] vs [%v]", aIP, bIP)
	return aIP != nil && bIP != nil && aIP.Equal(bIP)
}

// ResolveNodeIdToIpCached returns the currently known IP for the NodeID without ever
// triggering a synchronous DNS lookup: for an FQDN it returns the cached value (nil on a
// cache miss) instead of resolving on demand. Callers that can tolerate a stale/empty
// result (e.g. informational Kafka events) should prefer this over ResolveNodeIdToIp so a
// slow or unresponsive resolver can't block them.
func (n *NodeID) ResolveNodeIdToIpCached() net.IP {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		return n.NodeIdValue
	case NodeIdTypeFqdn:
		if ip, err := getDnsHostIp(string(n.NodeIdValue)); err == nil {
			return ip
		}
		return nil
	default:
		return nil
	}
}

func init() {
	dnsHostIpCache = make(map[string]net.IP)
	dnsHostIpGen = make(map[string]uint64)
	ticker := time.NewTicker(time.Minute)

	go func() {
		for {
			<-ticker.C
			RefreshDnsHostIpCache()
		}
	}()
}

func RefreshDnsHostIpCache() {
	dnsHostIpCacheMu.RLock()
	// Snapshot the generation alongside each host, not just its value: the lookups below
	// run without the lock held (so a slow/stuck resolver can't stall every other cache
	// reader, e.g. the Kafka publish path), and RefreshDnsHostIpCache can itself be called
	// concurrently (e.g. also triggered on PFCP send failure). Comparing the generation
	// on write - rather than comparing the resolved value - means this only applies its
	// result if nothing else touched the entry since it was observed, whether that other
	// write landed on the same value, a different one, or removed the entry outright; a
	// value-only comparison would let a failed lookup here delete an entry a concurrent
	// successful refresh had just installed.
	observed := make(map[string]uint64, len(dnsHostIpCache))
	for hostName := range dnsHostIpCache {
		observed[hostName] = dnsHostIpGen[hostName]
	}
	dnsHostIpCacheMu.RUnlock()

	for hostName, observedGen := range observed {
		logger.CtxLog.Debugf("refreshing DNS for host [%v]", hostName)
		newIP, err := lookupNodeAddress(hostName)
		if err != nil {
			logger.CtxLog.Warnf("host lookup failed: %+v", err)
			dnsHostIpCacheMu.Lock()
			if dnsHostIpGen[hostName] == observedGen {
				// The generation is never reclaimed, only ever incremented: deleting it would
				// let it read back as 0, and a later InsertDnsHostIp starting a host over from
				// generation 1 could then collide with a generation this (or another slow,
				// stale) refresh had already observed before the eviction, letting a stale
				// result overwrite a newer insert it was never compared against.
				delete(dnsHostIpCache, hostName)
				dnsHostIpGen[hostName]++
			}
			dnsHostIpCacheMu.Unlock()
			continue
		}
		dnsHostIpCacheMu.Lock()
		if dnsHostIpGen[hostName] == observedGen {
			if !dnsHostIpCache[hostName].Equal(newIP) {
				logger.CtxLog.Infof("smf dns cache updated for host [%v]: [%v]", hostName, newIP.String())
				dnsHostIpCache[hostName] = newIP
			}
			dnsHostIpGen[hostName]++
		}
		dnsHostIpCacheMu.Unlock()
	}
}

func getDnsHostIp(hostName string) (net.IP, error) {
	dnsHostIpCacheMu.RLock()
	defer dnsHostIpCacheMu.RUnlock()
	if ip, ok := dnsHostIpCache[hostName]; !ok {
		return nil, fmt.Errorf("host [%v] not found in smf dns cache", hostName)
	} else {
		return ip, nil
	}
}

func InsertDnsHostIp(hostName string, ip net.IP) {
	dnsHostIpCacheMu.Lock()
	defer dnsHostIpCacheMu.Unlock()
	dnsHostIpCache[hostName] = ip
	dnsHostIpGen[hostName]++
}
