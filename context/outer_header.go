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
// family. An address of one family is sent to as it is: with a dual F-TEID the RAN picks the
// family, and its downlink address says which. Of a dual-stack RAN, the IPv6 address is taken
// when the UPF's N3 is IPv6 and the IPv4 one otherwise (a dual N3 included), which is what the
// SMF did before it had IPv6 N3. An address of neither family keeps the old IPv4
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

// UplinkFTEIDFamilies gives the families of the F-TEID the SMF asks a UPF to choose on N3: both
// for a dual N3, IPv6 for an IPv6 N3, IPv4 otherwise (TS 29.244 clause 8.2.3 wants V4 and/or V6
// even with CHOOSE).
func UplinkFTEIDFamilies(n3 N3Transport) (v4, v6 bool) {
	switch {
	case n3.Dual:
		return true, true
	case n3.Family == AddressFamilyIPv6:
		return false, true
	}
	return true, false
}

// UplinkOuterHeaderRemoval is the outer header removal of an N3 uplink PDR: GTP-U/UDP/IP on a
// dual F-TEID, where uplink may arrive in either family; GTP-U/UDP/IPv6 on an IPv6 one;
// GTP-U/UDP/IPv4 otherwise.
func UplinkOuterHeaderRemoval(n3 N3Transport) *OuterHeaderRemoval {
	switch {
	case n3.Dual:
		return &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIp}
	case n3.Family == AddressFamilyIPv6:
		return &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIpv6}
	}
	return &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIpv4}
}

// AssignedFTEID names the F-TEID a UPF assigned, teid at address, where address is the N3
// TransportLayerAddress the RAN was told (see SplitTransportLayerAddress): V4, V6, or both for a
// dual F-TEID. It is nil without an address.
func AssignedFTEID(teid uint32, address net.IP) *FTEID {
	v4, v6 := SplitTransportLayerAddress(address)
	if v4 == nil && v6 == nil {
		return nil
	}
	fteid := &FTEID{Teid: teid}
	if v4 != nil {
		fteid.V4, fteid.Ipv4Address = true, v4.To4()
	}
	if v6 != nil {
		fteid.V6, fteid.Ipv6Address = true, v6
	}
	return fteid
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
		return path.FirstDPNode.UPF.GetN3Transport().Family
	}
	return AddressFamilyAuto
}
