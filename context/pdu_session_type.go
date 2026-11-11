// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

// PDUSessionTypeRefusal is why an establishment is refused for its PDU session type. The producer
// maps each to its smferrors key and 5GSM cause.
type PDUSessionTypeRefusal int

const (
	// NotRefused: the establishment is accepted.
	NotRefused PDUSessionTypeRefusal = iota
	// RefuseIPv4OnlyAllowed is 5GSM cause #50, "PDU session type IPv4 only allowed".
	RefuseIPv4OnlyAllowed
	// RefuseIPv6OnlyAllowed is 5GSM cause #51, "PDU session type IPv6 only allowed".
	RefuseIPv6OnlyAllowed
	// RefuseUnknownPDUSessionType is 5GSM cause #28, "unknown PDU session type".
	RefuseUnknownPDUSessionType
	// RefuseNoPool is 5GSM cause #26, "insufficient resources": the type is allowed, but the DNN
	// has no pool for it. The cause the SMF gives when a pool is exhausted.
	RefuseNoPool
)

func (r PDUSessionTypeRefusal) String() string {
	switch r {
	case NotRefused:
		return "accepted"
	case RefuseIPv4OnlyAllowed:
		return "#50 PDU session type IPv4 only allowed"
	case RefuseIPv6OnlyAllowed:
		return "#51 PDU session type IPv6 only allowed"
	case RefuseUnknownPDUSessionType:
		return "#28 unknown PDU session type"
	case RefuseNoPool:
		return "#26 insufficient resources"
	}
	return fmt.Sprintf("refusal %d", int(r))
}

// PDUSessionTypeSelection is the outcome of SelectPDUSessionType.
type PDUSessionTypeSelection struct {
	// Type is the selected PDU session type, a nasMessage.PDUSessionType* value; 0 when refused.
	Type uint8
	// AcceptCause is the 5GSM cause the PDU SESSION ESTABLISHMENT ACCEPT carries, 0 for none: #50
	// or #51 when an IPv4v6 request is served with one family.
	AcceptCause uint8
	// Refusal is why the establishment is refused, NotRefused when it is accepted.
	Refusal PDUSessionTypeRefusal
	// Reason explains a refusal or a downgrade, for the log.
	Reason string
}

// sessionTypesAllowed reads the subscription's PDU session types (TS 29.503 PduSessionTypes): the
// default type and the additional allowed ones. IPv4v6 allows each family on its own as well.
func sessionTypesAllowed(sub models.PduSessionTypes) (ipv4, ipv6 bool) {
	types := append([]models.PduSessionType{}, sub.AllowedSessionTypes...)
	if sub.DefaultSessionType != nil {
		types = append(types, *sub.DefaultSessionType)
	}
	for _, t := range types {
		switch t {
		case models.PDUSESSIONTYPE_IPV4:
			ipv4 = true
		case models.PDUSESSIONTYPE_IPV6:
			ipv6 = true
		case models.PDUSESSIONTYPE_IPV4_V6:
			ipv4, ipv6 = true, true
		}
	}
	return ipv4, ipv6
}

// SelectPDUSessionType selects the PDU session type of an establishment (TS 23.501 clause 5.6.10.1,
// TS 24.501 clause 6.4.1.3) from the UE's request, the subscription and the DNN's pools.
//
// A family is offered when the subscription allows it and the DNN has a pool for it. requested is
// the PDU session type IE, absent when present is false.
//
//   - IPv4 or IPv6 requested: that type when it is offered. Otherwise the establishment is refused
//     with #50 or #51 when the other family is offered; with #26 (insufficient resources, as for an
//     exhausted pool) when the requested family is allowed and only the DNN's pool is missing; with
//     #50 or #51 when the subscription allows the other family only; and with #28 when it allows
//     no IP type at all.
//   - IPv4v6 requested: IPv4v6 when both are offered; otherwise the one offered, with #50 or #51 in
//     the accept (TS 24.501 clause 6.4.1.3); refused as above when neither is.
//   - Another type (Ethernet, Unstructured, a reserved value): refused with #28. The SMF serves IP
//     types only.
//   - No type requested: the subscription's default type, reduced to the families offered without a
//     cause, since the UE asked for none. A subscription without a default type gets IPv4, as
//     before this selection existed, or IPv6 when the DNN has only an IPv6 pool.
//
// A request that names a type when the subscription carries no default type is refused with #50,
// as it was before.
func SelectPDUSessionType(requested uint8, present bool, sub models.PduSessionTypes, ipv4Pool, ipv6Pool bool,
) PDUSessionTypeSelection {
	if !present {
		return selectDefaultPDUSessionType(sub, ipv4Pool, ipv6Pool)
	}
	if sub.DefaultSessionType == nil {
		return PDUSessionTypeSelection{
			Refusal: RefuseIPv4OnlyAllowed,
			Reason:  "the subscription has no PDU session type information",
		}
	}

	allow4, allow6 := sessionTypesAllowed(sub)
	offer4, offer6 := allow4 && ipv4Pool, allow6 && ipv6Pool

	switch requested {
	case nasMessage.PDUSessionTypeIPv4:
		if offer4 {
			return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv4}
		}
		return refuseFamily(allow4, offer6, allow6, RefuseIPv6OnlyAllowed, "IPv4")
	case nasMessage.PDUSessionTypeIPv6:
		if offer6 {
			return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv6}
		}
		return refuseFamily(allow6, offer4, allow4, RefuseIPv4OnlyAllowed, "IPv6")
	case nasMessage.PDUSessionTypeIPv4IPv6:
		switch {
		case offer4 && offer6:
			return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv4IPv6}
		case offer4:
			return PDUSessionTypeSelection{
				Type:        nasMessage.PDUSessionTypeIPv4,
				AcceptCause: nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed,
				Reason:      "IPv4v6 requested, IPv6 is not offered on this DNN",
			}
		case offer6:
			return PDUSessionTypeSelection{
				Type:        nasMessage.PDUSessionTypeIPv6,
				AcceptCause: nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed,
				Reason:      "IPv4v6 requested, IPv4 is not offered on this DNN",
			}
		case allow4 || allow6:
			return PDUSessionTypeSelection{
				Refusal: RefuseNoPool,
				Reason:  "IPv4v6 requested, the DNN has no pool for the families the subscription allows",
			}
		default:
			return PDUSessionTypeSelection{
				Refusal: RefuseUnknownPDUSessionType,
				Reason:  "IPv4v6 requested, the subscription allows no IP PDU session type",
			}
		}
	default:
		return PDUSessionTypeSelection{
			Refusal: RefuseUnknownPDUSessionType,
			Reason:  fmt.Sprintf("PDU session type %d requested; only IPv4, IPv6 and IPv4v6 are supported", requested),
		}
	}
}

// refuseFamily refuses a single-family request that is not offered: with the other family's
// "only allowed" cause when that one is offered; with #26 when the subscription allows the
// requested family and only the DNN's pool for it is missing; with the other family's cause when
// the subscription allows that one instead; and with #28 when it allows neither.
func refuseFamily(allowedItself, otherOffered, otherAllowed bool, otherOnly PDUSessionTypeRefusal, family string) PDUSessionTypeSelection {
	switch {
	case otherOffered:
		return PDUSessionTypeSelection{
			Refusal: otherOnly,
			Reason:  family + " requested, which this subscription and DNN do not offer",
		}
	case allowedItself:
		return PDUSessionTypeSelection{
			Refusal: RefuseNoPool,
			Reason:  family + " requested and allowed, but the DNN has no " + family + " pool",
		}
	case otherAllowed:
		return PDUSessionTypeSelection{
			Refusal: otherOnly,
			Reason:  family + " requested, which the subscription does not allow",
		}
	default:
		return PDUSessionTypeSelection{
			Refusal: RefuseUnknownPDUSessionType,
			Reason:  family + " requested, the subscription allows no IP PDU session type",
		}
	}
}

func selectDefaultPDUSessionType(sub models.PduSessionTypes, ipv4Pool, ipv6Pool bool) PDUSessionTypeSelection {
	if sub.DefaultSessionType == nil {
		// Before this selection the SMF answered every request without a type with IPv4,
		// whatever the subscription said; that is kept, except for a DNN with no IPv4 pool.
		if !ipv4Pool && ipv6Pool {
			return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv6}
		}
		return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv4}
	}

	allow4, allow6 := sessionTypesAllowed(sub)
	offer4, offer6 := allow4 && ipv4Pool, allow6 && ipv6Pool
	ipv4 := PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv4}
	ipv6 := PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv6}

	// The default type when it is offered, else the families of it that are, else the other one.
	switch *sub.DefaultSessionType {
	case models.PDUSESSIONTYPE_IPV4_V6:
		if offer4 && offer6 {
			return PDUSessionTypeSelection{Type: nasMessage.PDUSessionTypeIPv4IPv6}
		}
	case models.PDUSESSIONTYPE_IPV6:
		if offer6 {
			return ipv6
		}
	}
	switch {
	case offer4:
		return ipv4
	case offer6:
		return ipv6
	case allow4 || allow6:
		return PDUSessionTypeSelection{
			Refusal: RefuseNoPool,
			Reason:  "no PDU session type requested; the DNN has no pool for the families the subscription allows",
		}
	default:
		return PDUSessionTypeSelection{
			Refusal: RefuseUnknownPDUSessionType,
			Reason:  "no PDU session type requested; the subscription allows no IP PDU session type",
		}
	}
}

// PDUSessionTypeError refuses an establishment because of its PDU session type.
type PDUSessionTypeError struct {
	Reason  string
	Refusal PDUSessionTypeRefusal
}

func (e *PDUSessionTypeError) Error() string {
	return fmt.Sprintf("PDU session type refused (%s): %s", e.Refusal, e.Reason)
}
