// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

import "net"

const (
	OuterHeaderCreationGtpUUdpIpv4 uint16 = 256
	OuterHeaderRemovalGtpUUdpIpv4  uint8  = 0
	OuterHeaderRemovalGtpUUdpIpv6  uint8  = 1
)

type OuterHeaderRemoval struct {
	OuterHeaderRemovalDescription uint8
}

type OuterHeaderCreation struct {
	Ipv4Address                    net.IP
	Ipv6Address                    net.IP
	Teid                           uint32
	PortNumber                     uint16
	OuterHeaderCreationDescription uint16
}

// SplitTransportLayerAddress splits an NGAP TransportLayerAddress (TS 38.414 clause 5.1): 32 bits
// are an IPv4 address, 128 bits an IPv6 address, and 160 bits both, IPv4 first. Any other length
// gives neither.
func SplitTransportLayerAddress(b []byte) (v4, v6 net.IP) {
	switch len(b) {
	case net.IPv4len:
		return net.IP(b), nil
	case net.IPv6len:
		if v4 := net.IP(b).To4(); v4 != nil {
			// Not an NGAP encoding, but the SMF stores and restores net.IP, which may
			// hold an IPv4 address in 16 bytes.
			return v4, nil
		}
		return nil, net.IP(b)
	case net.IPv4len + net.IPv6len:
		return net.IP(b[:net.IPv4len]), net.IP(b[net.IPv4len:])
	}
	return nil, nil
}

// AccessOuterHeaderCreation is the outer header creation towards the RAN at anAddress (as the
// RAN sent it, see SplitTransportLayerAddress) with teid, from a UPF of the given transport
// family. An address of one family is sent to as it is; of a dual-stack RAN, the IPv6 address
// is taken when the UPF's N3 is IPv6 (upfTransportFamily) and the IPv4 one otherwise, which is
// what the SMF did before it had IPv6 N3. An address of neither family keeps the old IPv4
// description, so the UPF refuses the rule rather than the SMF dropping it here.
func AccessOuterHeaderCreation(anAddress net.IP, teid uint32, family AddressFamily) *OuterHeaderCreation {
	ohc := &OuterHeaderCreation{Teid: teid}
	v4, v6 := SplitTransportLayerAddress(anAddress)
	if v6 != nil && (v4 == nil || family == AddressFamilyIPv6) {
		ohc.OuterHeaderCreationDescription = OuterHeaderCreationGtpUUdpIpv6
		ohc.Ipv6Address = v6
		return ohc
	}
	ohc.OuterHeaderCreationDescription = OuterHeaderCreationGtpUUdpIpv4
	ohc.Ipv4Address = v4
	return ohc
}

// UplinkFTEIDFamilies gives the families of the F-TEID the SMF asks a UPF to choose on N3: IPv6
// for a UPF whose transport family is IPv6, IPv4 otherwise (TS 29.244 clause 8.2.3 wants V4 or
// V6 even with CHOOSE).
func UplinkFTEIDFamilies(family AddressFamily) (v4, v6 bool) {
	if family == AddressFamilyIPv6 {
		return false, true
	}
	return true, false
}

// UplinkOuterHeaderRemoval is the outer header removal of an N3 uplink PDR: GTP-U/UDP/IPv6 when
// the UPF's F-TEID is IPv6, GTP-U/UDP/IPv4 otherwise.
func UplinkOuterHeaderRemoval(family AddressFamily) *OuterHeaderRemoval {
	if family == AddressFamilyIPv6 {
		return &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIpv6}
	}
	return &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIpv4}
}

// AssignedFTEID names the F-TEID a UPF assigned, teid at address: V4 or V6 by the address's
// family. It is nil without an address.
func AssignedFTEID(teid uint32, address net.IP) *FTEID {
	if v4 := address.To4(); v4 != nil {
		return &FTEID{V4: true, Teid: teid, Ipv4Address: v4}
	}
	if len(address) == net.IPv6len {
		return &FTEID{V6: true, Teid: teid, Ipv6Address: address}
	}
	return nil
}

// N3InterfaceFromFTEID is the N3 interface of a UPF as the F-TEID it assigned gives it: the
// F-TEID's IPv4 address, IPv6 address, or both.
func N3InterfaceFromFTEID(v4, v6 net.IP) UPFInterfaceInfo {
	n3 := UPFInterfaceInfo{}
	if v4 != nil || v6 == nil {
		// An F-TEID with neither keeps the old shape, one (nil) IPv4 address.
		n3.IPv4EndPointAddresses = append(n3.IPv4EndPointAddresses, v4)
	}
	if v6 != nil {
		n3.IPv6EndPointAddresses = append(n3.IPv6EndPointAddresses, v6)
	}
	return n3
}

// ANTransportFamily is the transport family of the UPF that terminates the session's N3, on the
// default data path; AddressFamilyAuto when there is none.
func (smContext *SMContext) ANTransportFamily() AddressFamily {
	if smContext.Tunnel == nil {
		return AddressFamilyAuto
	}
	if path := smContext.Tunnel.DataPathPool.GetDefaultPath(); path != nil &&
		path.FirstDPNode != nil && path.FirstDPNode.UPF != nil {
		return path.FirstDPNode.UPF.GetTransportFamily()
	}
	return AddressFamilyAuto
}
