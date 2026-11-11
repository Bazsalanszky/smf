// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

// Package gtpu is the minimal GTPv1-U (TS 29.281) the SMF needs for its own GTP-U endpoint: the
// endpoint a UPF forwards packets to the CP function on (TS 29.244 clause 5.3), which the SMF uses
// for the router solicitations and advertisements of IPv6 PDU sessions (TS 23.501 clause
// 5.8.2.2.2). It decodes G-PDUs, skipping any extension headers, answers Echo Requests and builds
// plain G-PDUs. Nothing else of GTP-U is implemented: the SMF carries no user traffic.
package gtpu

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Port is the registered GTP-U port (TS 29.281 clause 4.4.2). A UPF sends to it whatever port it
// was configured with itself, so the endpoint does not make it configurable.
const Port = 2152

// Message types used here (TS 29.281 clause 6.1).
const (
	MsgTypeEchoRequest  uint8 = 1
	MsgTypeEchoResponse uint8 = 2
	MsgTypeErrorInd     uint8 = 26
	MsgTypeEndMarker    uint8 = 254
	MsgTypeGPDU         uint8 = 255
)

// ieTypeRecovery is the Recovery IE (TS 29.281 clause 8.2), the one IE of an Echo Response.
const ieTypeRecovery uint8 = 14

const (
	flagVersion1 = 0x20 // version 1
	flagPT       = 0x10 // protocol type GTP (not GTP')
	flagE        = 0x04 // next extension header field is present
	flagS        = 0x02 // sequence number field is present
	flagPN       = 0x01 // N-PDU number field is present

	mandatoryLen = 8
	optionalLen  = 4 // sequence number, N-PDU number, next extension header type
)

// ErrNotGTPv1U is returned for a datagram that is not GTPv1-U (a GTP' or a GTPv2 message, or junk).
var ErrNotGTPv1U = errors.New("not a GTPv1-U message")

// Message is a decoded GTPv1-U header and its payload. Payload is the T-PDU of a G-PDU, after any
// extension headers, and aliases the decoded buffer.
type Message struct {
	Payload []byte
	TEID    uint32
	Seq     uint16
	Type    uint8
	// HasSeq reports whether the header carried a sequence number. An Echo Response must carry the
	// request's (TS 29.281 clause 5.1).
	HasSeq bool
}

// Parse decodes one GTPv1-U message. Extension headers are skipped rather than refused: a UPF that
// forwards a packet with a QoS flow (a QER on the PDR) adds a PDU Session Container (TS 38.415),
// and the packet behind it is still the one to act on.
func Parse(b []byte) (*Message, error) {
	if len(b) < mandatoryLen {
		return nil, fmt.Errorf("GTP-U header: %d octets, need %d", len(b), mandatoryLen)
	}
	flags := b[0]
	if flags>>5 != 1 || flags&flagPT == 0 {
		return nil, ErrNotGTPv1U
	}
	m := &Message{
		Type: b[1],
		TEID: binary.BigEndian.Uint32(b[4:8]),
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if mandatoryLen+length > len(b) {
		return nil, fmt.Errorf("GTP-U length %d exceeds the %d octets after the header", length, len(b)-mandatoryLen)
	}
	body := b[mandatoryLen : mandatoryLen+length]
	if flags&(flagE|flagS|flagPN) == 0 {
		m.Payload = body
		return m, nil
	}

	// Any one of E, S and PN makes all three optional fields present (TS 29.281 clause 5.1).
	if len(body) < optionalLen {
		return nil, fmt.Errorf("GTP-U optional fields: %d octets, need %d", len(body), optionalLen)
	}
	if flags&flagS != 0 {
		m.Seq = binary.BigEndian.Uint16(body[0:2])
		m.HasSeq = true
	}
	next := body[3]
	rest := body[optionalLen:]
	if flags&flagE == 0 {
		next = 0
	}
	for next != 0 {
		// Each extension header: a length in 4-octet units, which counts the length and the
		// next-type octets too, its content, then the type of the next one (TS 29.281 clause 5.2).
		if len(rest) < 1 || rest[0] == 0 {
			return nil, fmt.Errorf("GTP-U extension header %#x: bad length", next)
		}
		n := int(rest[0]) * 4
		if n > len(rest) {
			return nil, fmt.Errorf("GTP-U extension header %#x: %d octets, %d left", next, n, len(rest))
		}
		next = rest[n-1]
		rest = rest[n:]
	}
	m.Payload = rest
	return m, nil
}

// NewGPDU builds a G-PDU carrying payload to teid, with no optional field and no extension header:
// the form a UPF expects on a PDR whose Source Interface is CP-function.
func NewGPDU(teid uint32, payload []byte) []byte {
	b := make([]byte, mandatoryLen+len(payload))
	b[0] = flagVersion1 | flagPT
	b[1] = MsgTypeGPDU
	binary.BigEndian.PutUint16(b[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(b[4:8], teid)
	copy(b[mandatoryLen:], payload)
	return b
}

// NewEchoResponse builds the answer to an Echo Request: TEID 0, the request's sequence number and a
// Recovery IE whose restart counter is zero, as TS 29.281 clauses 7.2.2 and 8.2 require for GTP-U.
func NewEchoResponse(seq uint16) []byte {
	b := make([]byte, mandatoryLen+optionalLen+2)
	b[0] = flagVersion1 | flagPT | flagS
	b[1] = MsgTypeEchoResponse
	binary.BigEndian.PutUint16(b[2:4], optionalLen+2)
	binary.BigEndian.PutUint16(b[8:10], seq)
	b[12] = ieTypeRecovery
	b[13] = 0
	return b
}

// NewEchoRequest builds an Echo Request with sequence number seq. The SMF does not send them; the
// tests use it as a UPF would.
func NewEchoRequest(seq uint16) []byte {
	b := make([]byte, mandatoryLen+optionalLen)
	b[0] = flagVersion1 | flagPT | flagS
	b[1] = MsgTypeEchoRequest
	binary.BigEndian.PutUint16(b[2:4], optionalLen)
	binary.BigEndian.PutUint16(b[8:10], seq)
	return b
}
