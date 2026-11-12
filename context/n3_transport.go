// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"net"
)

// N3Advertisement is what a UPF's UP IP Resource Information (TS 29.244 clause 8.2.82) said
// about its access-side (N3) GTP-U addresses when the association was set up.
type N3Advertisement struct {
	// Known is set when the UPF sent at least one UP IP Resource Information for the access
	// side. A UPF that sends none (the IE is optional, and deprecated since Rel-16 in favour of
	// F-TEID allocation by the UP function) leaves the SMF with its configured behaviour.
	Known bool
	V4    bool
	V6    bool
}

// ParseN3Advertisement reads the UP IP Resource Information IE payloads of an Association Setup
// Request or Response. An entry counts for N3 when it is tied to the Access source interface
// (ASSOSI with Source Interface 0) or to no source interface at all. Malformed entries are
// skipped.
//
// The IE is parsed here rather than with go-pfcp's UserPlaneIPResourceInformation(): that parser
// indexes past the end of the payload when both ASSONI and ASSOSI are set, which is exactly what
// the omec UPF sends with a DNN configured (flags 0x61).
func ParseN3Advertisement(payloads [][]byte) N3Advertisement {
	var adv N3Advertisement
	for _, b := range payloads {
		v4, v6, ok := parseUPIPResourceInformation(b)
		if !ok {
			continue
		}
		adv.Known = true
		adv.V4 = adv.V4 || v4
		adv.V6 = adv.V6 || v6
	}
	return adv
}

const (
	upIPResV4     = 0x01
	upIPResV6     = 0x02
	upIPResTEIDRI = 0x1c
	upIPResASSONI = 0x20
	upIPResASSOSI = 0x40
)

// parseUPIPResourceInformation returns the address families of one UP IP Resource Information
// payload and whether it describes the access side.
func parseUPIPResourceInformation(b []byte) (v4, v6, access bool) {
	if len(b) < 1 {
		return false, false, false
	}
	flags := b[0]
	need := 1
	if flags&upIPResTEIDRI != 0 {
		need++
	}
	if flags&upIPResV4 != 0 {
		need += net.IPv4len
	}
	if flags&upIPResV6 != 0 {
		need += net.IPv6len
	}
	if flags&upIPResASSOSI != 0 {
		need++
	}
	if len(b) < need {
		return false, false, false
	}
	if flags&upIPResASSOSI != 0 && b[len(b)-1]&0x0f != 0 {
		// Tied to a source interface other than Access (0): not N3.
		return false, false, false
	}
	if flags&upIPResASSONI == 0 && flags&upIPResASSOSI == 0 && len(b) != need {
		return false, false, false
	}
	return flags&upIPResV4 != 0, flags&upIPResV6 != 0, true
}

// N3Transport is how the SMF uses a UPF's N3: one family, or both (a dual F-TEID).
type N3Transport struct {
	// Family is the single family N3 uses; AddressFamilyAuto with Dual false is the behaviour
	// the SMF had before it knew about IPv6 N3 (IPv4 when the UPF has an IPv4 address).
	Family AddressFamily
	// Dual asks the UPF for an F-TEID with both an IPv4 and an IPv6 address, and gives the RAN
	// both (a 160-bit TransportLayerAddress, TS 38.414 clause 5.1) to pick from.
	Dual bool
}

// N3TransportLocked is the N3 transport of the UPF; the caller holds UpfLock.
//
//   - upfTransportFamily ipv4 or ipv6 restricts N3 to that family, whatever the UPF advertises.
//   - Otherwise the UP IP Resource Information decides: both families give a dual F-TEID, IPv6
//     alone gives IPv6, and IPv4 alone or nothing advertised gives what the SMF always did (IPv4
//     first). An IPv4-only UPF, the omec UPF before IPv6 N3 among them, advertises V4 alone,
//     so nothing changes for it.
func (upf *UPF) N3TransportLocked() N3Transport {
	if upf.TransportFamily != AddressFamilyAuto {
		return N3Transport{Family: upf.TransportFamily}
	}
	adv := upf.N3Advertised
	switch {
	case adv.Known && adv.V4 && adv.V6:
		return N3Transport{Dual: true}
	case adv.Known && adv.V6:
		return N3Transport{Family: AddressFamilyIPv6}
	}
	return N3Transport{}
}

// GetN3Transport returns the N3 transport of the UPF for a caller that does not hold UpfLock.
func (upf *UPF) GetN3Transport() N3Transport {
	upf.UpfLock.RLock()
	defer upf.UpfLock.RUnlock()
	return upf.N3TransportLocked()
}

// SetN3Advertisement records what the UPF advertised at association; the caller holds UpfLock.
func (upf *UPF) SetN3Advertisement(adv N3Advertisement) {
	upf.N3Advertised = adv
}

// N3TransportLayerAddressLocked is the uplink N3 address the RAN is told (TS 38.413 clause
// 9.3.2.4): 4 bytes for IPv4, 16 for IPv6, and with a dual N3, 20 bytes (IPv4 then IPv6) when the
// UPF's F-TEID has both. The caller holds UpfLock.
func (upf *UPF) N3TransportLayerAddressLocked() (net.IP, error) {
	if len(upf.N3Interfaces) == 0 {
		return nil, errors.New("no N3Interfaces available in UPF node")
	}
	iface := &upf.N3Interfaces[0]
	t := upf.N3TransportLocked()
	if !t.Dual {
		return iface.TransportIP(t.Family)
	}
	v4, err4 := iface.TransportIP(AddressFamilyIPv4)
	v6, err6 := iface.TransportIP(AddressFamilyIPv6)
	switch {
	case err4 == nil && err6 == nil:
		tla := make(net.IP, 0, net.IPv4len+net.IPv6len)
		tla = append(tla, v4.To4()...)
		return append(tla, v6.To16()...), nil
	case err4 == nil:
		return v4, nil
	case err6 == nil:
		return v6, nil
	}
	return nil, err4
}

// N3TransportLayerAddress is N3TransportLayerAddressLocked for a caller that does not hold
// UpfLock.
func (upf *UPF) N3TransportLayerAddress() (net.IP, error) {
	upf.UpfLock.RLock()
	defer upf.UpfLock.RUnlock()
	return upf.N3TransportLayerAddressLocked()
}
