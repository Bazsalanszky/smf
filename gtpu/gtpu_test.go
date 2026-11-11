// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package gtpu

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewGPDUBytes(t *testing.T) {
	// TS 29.281 clause 5.1: version 1, PT 1, no E/S/PN; type 255; length of the T-PDU; TEID.
	got := NewGPDU(0x01020304, []byte{0xde, 0xad, 0xbe})
	if want := mustHex(t, "30 ff 0003 01020304 deadbe"); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEchoBytes(t *testing.T) {
	// S set, sequence number, N-PDU and next-extension octets zero; the response carries the
	// Recovery IE (type 14) with restart counter 0 (TS 29.281 clauses 7.2.2, 8.2).
	if got, want := NewEchoRequest(0x1234), mustHex(t, "32 01 0004 00000000 1234 00 00"); !bytes.Equal(got, want) {
		t.Errorf("echo request %x, want %x", got, want)
	}
	if got, want := NewEchoResponse(0x1234), mustHex(t, "32 02 0006 00000000 1234 00 00 0e 00"); !bytes.Equal(got, want) {
		t.Errorf("echo response %x, want %x", got, want)
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		typ     uint8
		teid    uint32
		seq     uint16
		hasSeq  bool
		payload string
	}{
		{"plain G-PDU", "30 ff 0002 0000abcd 6000", MsgTypeGPDU, 0xabcd, 0, false, "6000"},
		{"echo request", "32 01 0004 00000000 beef 00 00", MsgTypeEchoRequest, 0, 0xbeef, true, ""},
		{
			// A UPF forwarding on a PDR with a QER adds a PDU Session Container (type 0x85, TS
			// 38.415): one 4-octet unit with PDU type 0 (DL) and QFI 9, then no further header.
			"G-PDU with a PDU Session Container", "34 ff 000a 00000007 0000 00 85 01 00 09 00 6000",
			MsgTypeGPDU, 7, 0, false, "6000",
		},
		{
			"two extension headers and a sequence number", "36 ff 000e 00000007 0102 00 85 01 00 09 c0 01 aa bb 00 6000",
			MsgTypeGPDU, 7, 0x0102, true, "6000",
		},
		{"trailing octets beyond the length", "30 ff 0001 00000001 60 ff ff", MsgTypeGPDU, 1, 0, false, "60"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(mustHex(t, tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if m.Type != tc.typ || m.TEID != tc.teid || m.Seq != tc.seq || m.HasSeq != tc.hasSeq ||
				!bytes.Equal(m.Payload, mustHex(t, tc.payload)) {
				t.Fatalf("got %+v", m)
			}
		})
	}
}

func TestParseRefuses(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"short", "30 ff 0000", "header"},
		{"GTPv2", "48 20 0000 00000000", "not a GTPv1-U"},
		{"GTP'", "20 ff 0000 00000000", "not a GTPv1-U"},
		{"length beyond the datagram", "30 ff 0004 00000001 60", "exceeds"},
		{"optional fields missing", "32 ff 0002 00000001 0000", "optional fields"},
		{"zero-length extension header", "34 ff 0008 00000001 0000 00 85 00 00 00 00", "bad length"},
		{"extension header past the end", "34 ff 0008 00000001 0000 00 85 02 00 00 00", "left"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(mustHex(t, tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

type received struct {
	payload []byte
	from    netip.AddrPort
	teid    uint32
}

func listenLoopback(t *testing.T) (*Endpoint, chan received) {
	t.Helper()
	got := make(chan received, 4)
	ep, err := Listen([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, 0, func(teid uint32, payload []byte, from netip.AddrPort) {
		got <- received{teid: teid, payload: append([]byte{}, payload...), from: from}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ep.Close)
	return ep, got
}

func dial(t *testing.T, ep *Endpoint) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(ep.LocalAddrs()[0]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	})
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestEndpointAnswersEcho(t *testing.T) {
	ep, got := listenLoopback(t)
	conn := dial(t, ep)
	if _, err := conn.Write(NewEchoRequest(0x4242)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], NewEchoResponse(0x4242)) {
		t.Fatalf("echo response %x", buf[:n])
	}
	select {
	case r := <-got:
		t.Fatalf("echo reached the G-PDU handler: %+v", r)
	default:
	}
}

func TestEndpointDeliversGPDUsAndSends(t *testing.T) {
	ep, got := listenLoopback(t)
	conn := dial(t, ep)
	if _, err := conn.Write(mustHex(t, "34 ff 000a 00000007 0000 00 85 01 00 09 00 6000")); err != nil {
		t.Fatal(err)
	}
	var r received
	select {
	case r = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no G-PDU delivered")
	}
	if r.teid != 7 || !bytes.Equal(r.payload, []byte{0x60, 0x00}) {
		t.Fatalf("got %+v", r)
	}
	if r.from != conn.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("from %s, want %s", r.from, conn.LocalAddr())
	}

	// The reply path: a G-PDU to the sender.
	if err := ep.SendGPDU(r.from, 0x99, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], NewGPDU(0x99, []byte{1, 2})) {
		t.Fatalf("sent %x", buf[:n])
	}
	if err := ep.SendGPDU(netip.MustParseAddrPort("[2001:db8::1]:2152"), 1, nil); err == nil {
		t.Fatal("an IPv4-only endpoint sent to an IPv6 address")
	}
	if ep.HasFamily(netip.MustParseAddr("2001:db8::1")) || !ep.HasFamily(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("HasFamily")
	}
}

func TestEndpointDropsOtherMessages(t *testing.T) {
	ep, got := listenLoopback(t)
	conn := dial(t, ep)
	for _, m := range []string{
		"30 1a 0000 00000001",           // Error Indication: not handled
		"48 20 0000 00000000",           // GTPv2: not GTP-U
		"30 ff 0009 00000001 60",        // truncated
		"30 ff 0002 00000005 6000 ffff", // a valid one last
	} {
		if _, err := conn.Write(mustHex(t, m)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case r := <-got:
		if r.teid != 5 {
			t.Fatalf("got %+v first", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("valid G-PDU not delivered")
	}
}

func TestListenRefusesNoAddressAndCloses(t *testing.T) {
	if _, err := Listen(nil, 0, nil); err == nil {
		t.Fatal("no error")
	}
	ep, err := Listen([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := ep.LocalAddrs()[0]
	ep.Close()
	ep.Close()
	// The port is free again once Close has returned.
	again, err := Listen([]netip.Addr{addr.Addr()}, addr.Port(), nil)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}
