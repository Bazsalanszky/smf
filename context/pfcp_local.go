// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
)

// N4Addrs is the SMF's own N4 (PFCP) address in each family it has one in. A single-stack
// SMF has one of the two; a dual-stack one, configured with an address list such as
// POD_IPS, has both.
type N4Addrs struct {
	IPv4 net.IP
	IPv6 net.IP
}

// add records ip under its family, keeping the first address seen for each.
func (a *N4Addrs) add(ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		if a.IPv4 == nil {
			a.IPv4 = ip
		}
		return
	}
	if a.IPv6 == nil && ip.To16() != nil {
		a.IPv6 = ip
	}
}

func (a N4Addrs) empty() bool { return a.IPv4 == nil && a.IPv6 == nil }

// pfcpLocal is what InitSmfContext takes from the pfcp section of the configuration.
type pfcpLocal struct {
	nodeID NodeID
	addrs  N4Addrs
	// resolveFamily is the family preferred when a UPF's FQDN has addresses of both.
	resolveFamily AddressFamily
}

// resolvePfcpLocal derives the SMF's N4 identity from the pfcp configuration:
//
//   - addr (or the environment variable it names, as helm's POD_IP) is either one address
//     or host name, resolved as before by resolvePfcpAddr, or a comma-separated list of IP
//     literals, the form Kubernetes gives status.podIPs in (POD_IPS). The first address of
//     each family becomes the SMF's N4 address in that family.
//   - nodeId, when set, is the Node ID advertised: an IPv4 or IPv6 address or an FQDN, or
//     the name of an environment variable holding one. Otherwise the Node ID is the N4
//     address: the only one, or with two, the one of preferredFamily, else the first listed.
//   - preferredFamily ("ipv4" or "ipv6") also orders UPF name resolution. Unset, IPv4 is
//     preferred, as before, unless the SMF has no IPv4 N4 address.
//
// With a single IPv4 address, the default, the Node ID, the bind address and the F-SEID
// address are the same as before. The Node ID used to be built with To4(), which is nil for
// an IPv6 address, so an IPv6 SMF advertised the FQDN "<nil>".
func resolvePfcpLocal(pfcp *factory.PFCP) (pfcpLocal, error) {
	var local pfcpLocal

	preferred, err := ParseAddressFamily(pfcp.PreferredFamily)
	if err != nil {
		return local, fmt.Errorf("pfcp.preferredFamily: %w", err)
	}

	value := pfcp.Addr
	if env := os.Getenv(pfcp.Addr); env != "" {
		value = env
	}

	var listed []net.IP
	if strings.Contains(value, ",") {
		if pfcp.Port == 0 {
			pfcp.Port = DefaultPfcpPort
		}
		logger.CtxLog.Infof("PFCP address list %q", value)
		pfcp.Addr = value
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]"))
			if ip == nil {
				return local, fmt.Errorf("pfcp.addr list entry %q is not an IP address", entry)
			}
			listed = append(listed, ip)
			local.addrs.add(ip)
		}
		if local.addrs.empty() {
			return local, fmt.Errorf("pfcp.addr list %q has no address", value)
		}
	} else {
		addr, err := resolvePfcpAddr(pfcp)
		if err != nil {
			return local, err
		}
		listed = []net.IP{addr.IP}
		local.addrs.add(addr.IP)
	}

	local.resolveFamily = preferred
	if preferred == AddressFamilyAuto && local.addrs.IPv4 == nil {
		local.resolveFamily = AddressFamilyIPv6
	}

	nodeID := pfcp.NodeID
	if env := os.Getenv(nodeID); env != "" {
		nodeID = env
	}
	if nodeID != "" {
		local.nodeID = *NewNodeID(strings.TrimSuffix(strings.TrimPrefix(nodeID, "["), "]"))
		return local, nil
	}

	nodeIP := listed[0]
	switch {
	case preferred == AddressFamilyIPv4 && local.addrs.IPv4 != nil:
		nodeIP = local.addrs.IPv4
	case preferred == AddressFamilyIPv6 && local.addrs.IPv6 != nil:
		nodeIP = local.addrs.IPv6
	}
	local.nodeID = nodeIDFromIP(nodeIP)
	return local, nil
}

// nodeIDFromIP returns the IPv4 or IPv6 Node ID for ip, in the 4- or 16-byte form NewNodeID
// uses.
func nodeIDFromIP(ip net.IP) NodeID {
	if v4 := ip.To4(); v4 != nil {
		return NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: v4}
	}
	return NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: ip.To16()}
}

// cpNodeIP returns the CPNodeID's address when it is an IP Node ID, and nil for an FQDN.
func (c *SMFContext) cpNodeIP() net.IP {
	switch c.CPNodeID.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		if len(c.CPNodeID.NodeIdValue) == 0 {
			return nil
		}
		return net.IP(c.CPNodeID.NodeIdValue)
	}
	return nil
}

// localN4Addrs returns the SMF's N4 addresses. InitSmfContext records them; a context set
// up without it (as tests do, by setting CPNodeID only) falls back to the CPNodeID address,
// which is what every N4 path used before there was anything else.
func (c *SMFContext) localN4Addrs() N4Addrs {
	if !c.N4Addrs.empty() {
		return c.N4Addrs
	}
	var a N4Addrs
	if ip := c.cpNodeIP(); ip != nil {
		a.add(ip)
	}
	return a
}

// PFCPListenAddr is the address the PFCP socket binds. With one N4 address it is that
// address, as before. With one of each family it is the wildcard, which Go opens as a
// dual-stack socket, so the SMF answers on both.
func (c *SMFContext) PFCPListenAddr() *net.UDPAddr {
	a := c.localN4Addrs()
	addr := &net.UDPAddr{Port: c.PFCPPort}
	switch {
	case a.IPv4 != nil && a.IPv6 != nil:
	case a.IPv4 != nil:
		addr.IP = a.IPv4
	case a.IPv6 != nil:
		addr.IP = a.IPv6
	}
	return addr
}

// FSEIDAddrs returns the addresses the SMF puts in its CP F-SEID: its N4 address in each
// family it has one in (TS 29.244 clause 8.2.37 allows either or both). The UPF sends
// session-related requests (reports) to this address, so it has to be one the SMF listens
// on. It used to be the CPNodeID address placed in the IPv4 slot whatever its family.
func (c *SMFContext) FSEIDAddrs() (v4, v6 net.IP) {
	a := c.localN4Addrs()
	return a.IPv4, a.IPv6
}

// AdapterRelayIP is the address the UPF adapter should relay UPF-originated messages to:
// the SMF's N4 address, when it has exactly one and it is neither the wildcard nor a
// loopback address. It returns nil otherwise, and the caller falls back to an interface
// address, which is what it always used.
func (c *SMFContext) AdapterRelayIP() net.IP {
	a := c.localN4Addrs()
	var ip net.IP
	switch {
	case a.IPv4 != nil && a.IPv6 != nil:
		return nil
	case a.IPv4 != nil:
		ip = a.IPv4
	case a.IPv6 != nil:
		ip = a.IPv6
	}
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return nil
	}
	return ip
}

// parseUpfTransportFamily reads the upfTransportFamily configuration, UPF hostname to
// "ipv4", "ipv6" or "auto". Entries set to auto are dropped.
func parseUpfTransportFamily(cfg map[string]string) (map[string]AddressFamily, error) {
	families := make(map[string]AddressFamily, len(cfg))
	for upf, value := range cfg {
		family, err := ParseAddressFamily(value)
		if err != nil {
			return nil, fmt.Errorf("UPF %s: %w", upf, err)
		}
		if family != AddressFamilyAuto {
			families[upf] = family
		}
	}
	return families, nil
}
