// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pfcp_test

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// These tests run N4 between the SMF's real PFCP socket and a stand-in UPF on the loopback
// interface: association, heartbeats both ways, and a session establishment request, over
// [::1] and over a dual-stack SMF socket.

func nativeDatapath(t *testing.T) {
	t.Helper()
	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })
	enabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: &enabled},
			EnableUpfAdapter: false,
		},
	}

	retries, req, rsp := udp.GetRetryTimingForTest()
	udp.SetRetryTimingForTest(3, 300*time.Millisecond, 300*time.Millisecond)
	t.Cleanup(func() { udp.SetRetryTimingForTest(retries, req, rsp) })
}

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	conn.Close()
}

// startSmf runs the SMF's PFCP socket with the given N4 addresses and the real dispatcher.
func startSmf(t *testing.T, nodeID string, addrs context.N4Addrs) *net.UDPAddr {
	t.Helper()
	self := context.SMF_Self()
	prevNodeID, prevAddrs, prevPort := self.CPNodeID, self.N4Addrs, self.PFCPPort

	free, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("reserving a port for the SMF: %v", err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	self.CPNodeID = *context.NewNodeID(nodeID)
	self.N4Addrs = addrs
	self.PFCPPort = port
	// Run hands each message to a goroutine of its own and does not wait for it. The gate lets the
	// cleanup wait for those still handling a message, and turns away any that start after.
	var gate sync.RWMutex
	closed := false
	udp.Run(func(msg *udp.Message) {
		gate.RLock()
		defer gate.RUnlock()
		if !closed {
			pfcp.Dispatch(msg)
		}
	})
	if err := udp.WaitForServer(); err != nil {
		t.Fatalf("starting the SMF's PFCP socket: %v", err)
	}
	t.Cleanup(func() {
		// No handler may be running when the transactions are waited for: a handler's send adds a
		// transaction, and adding one while they are waited for is a race.
		gate.Lock()
		closed = true
		gate.Unlock()
		udp.WaitForAllTransactions()
		if server := udp.GetServer(); server != nil {
			server.Conn.Close()
			<-server.Done
			udp.SetServer(nil)
		}
		self.CPNodeID, self.N4Addrs, self.PFCPPort = prevNodeID, prevAddrs, prevPort
	})
	return udp.GetServer().Conn.LocalAddr().(*net.UDPAddr)
}

type fakeUPF struct {
	t      *testing.T
	conn   *net.UDPConn
	nodeID string
	upf    *context.UPF
}

func newFakeUPF(t *testing.T, ip string) *fakeUPF {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatalf("standing in for the UPF on %s: %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })
	upf := context.NewUPF(context.NewNodeID(ip), nil)
	upf.Port = uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(upf.NodeID) })
	return &fakeUPF{t: t, conn: conn, nodeID: ip, upf: upf}
}

func (u *fakeUPF) read() (message.Message, *net.UDPAddr) {
	u.t.Helper()
	if err := u.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		u.t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, from, err := u.conn.ReadFromUDP(buf)
	if err != nil {
		u.t.Fatalf("UPF %s received nothing: %v", u.nodeID, err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		u.t.Fatalf("UPF %s could not parse what it received: %v", u.nodeID, err)
	}
	return msg, from
}

// quiet reports whether nothing arrives for d: a request the SMF retransmits is one whose
// response it did not match.
func (u *fakeUPF) quiet(d time.Duration) bool {
	u.t.Helper()
	if err := u.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		u.t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_, _, err := u.conn.ReadFromUDP(buf)
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (u *fakeUPF) send(msg message.Message, to *net.UDPAddr) {
	u.t.Helper()
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		u.t.Fatal(err)
	}
	if _, err := u.conn.WriteToUDP(b, to); err != nil {
		u.t.Fatalf("UPF %s sending to %v: %v", u.nodeID, to, err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func checkNodeIDIE(t *testing.T, what string, nodeIDIE *ie.IE, want string) {
	t.Helper()
	if nodeIDIE == nil {
		t.Fatalf("%s: no Node ID", what)
	}
	got, err := nodeIDIE.NodeID()
	if err != nil || got != want {
		t.Errorf("%s: Node ID = %q, %v; want %q", what, got, err, want)
	}
	wantType := ie.NodeIDIPv4Address
	if ip := net.ParseIP(want); ip == nil {
		wantType = ie.NodeIDFQDN
	} else if ip.To4() == nil {
		wantType = ie.NodeIDIPv6Address
	}
	if nodeIDIE.Payload[0] != wantType {
		t.Errorf("%s: Node ID type = %d, want %d", what, nodeIDIE.Payload[0], wantType)
	}
}

// associate runs an SMF-initiated association with u and returns the SMF's address as u saw it.
func (u *fakeUPF) associate(smfNodeID string) *net.UDPAddr {
	u.t.Helper()
	t := u.t
	upNodeID := *context.NewNodeID(u.nodeID)
	u.upf.UpfLock.Lock()
	err := pfcp_message.SendPfcpAssociationSetupRequest(upNodeID, u.upf.Port)
	u.upf.UpfLock.Unlock()
	if err != nil {
		t.Fatalf("association setup request to %s: %v", u.nodeID, err)
	}

	msg, smfAddr := u.read()
	req, ok := msg.(*message.AssociationSetupRequest)
	if !ok {
		t.Fatalf("UPF %s expected an association setup request, got %s", u.nodeID, msg.MessageTypeName())
	}
	checkNodeIDIE(t, "association setup request", req.NodeID, smfNodeID)

	u.send(message.NewAssociationSetupResponse(req.Sequence(),
		ie.NewNodeIDHeuristic(u.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(time.Now()),
	), smfAddr)

	waitFor(t, "UPF "+u.nodeID+" to be associated", func() bool {
		u.upf.UpfLock.RLock()
		defer u.upf.UpfLock.RUnlock()
		return u.upf.UPFStatus == context.AssociatedSetUpSuccess
	})
	return smfAddr
}

// heartbeats sends a heartbeat each way: the SMF's must be answered back into its handler, and
// the UPF's must be answered at the address it came from.
func (u *fakeUPF) heartbeats(smfAddr *net.UDPAddr) {
	u.t.Helper()
	t := u.t
	u.upf.UpfLock.Lock()
	u.upf.NHeartBeat = 1
	err := pfcp_message.SendHeartbeatRequest(*context.NewNodeID(u.nodeID), u.upf.Port)
	u.upf.UpfLock.Unlock()
	if err != nil {
		t.Fatalf("heartbeat request to %s: %v", u.nodeID, err)
	}
	msg, from := u.read()
	if msg.MessageType() != message.MsgTypeHeartbeatRequest {
		t.Fatalf("UPF %s expected a heartbeat request, got %s", u.nodeID, msg.MessageTypeName())
	}
	u.send(message.NewHeartbeatResponse(msg.Sequence(), ie.NewRecoveryTimeStamp(u.upf.HeldRecovery())), from)
	waitFor(t, "the SMF to take the heartbeat response from "+u.nodeID, func() bool {
		u.upf.UpfLock.RLock()
		defer u.upf.UpfLock.RUnlock()
		return u.upf.NHeartBeat == 0
	})

	u.send(message.NewHeartbeatRequest(0x10, ie.NewRecoveryTimeStamp(u.upf.HeldRecovery()), nil), smfAddr)
	msg, _ = u.read()
	if msg.MessageType() != message.MsgTypeHeartbeatResponse || msg.Sequence() != 0x10 {
		t.Errorf("UPF %s expected the SMF's heartbeat response, got %s seq %d", u.nodeID, msg.MessageTypeName(), msg.Sequence())
	}
}

func TestN4OverIPv6Loopback(t *testing.T) {
	requireIPv6Loopback(t)
	nativeDatapath(t)
	startSmf(t, "::1", context.N4Addrs{IPv6: net.IPv6loopback})

	upf := newFakeUPF(t, "::1")
	smfAddr := upf.associate("::1")
	if smfAddr.IP.To4() != nil || !smfAddr.IP.Equal(net.IPv6loopback) {
		t.Errorf("the SMF sent from %v, want [::1]", smfAddr)
	}
	upf.heartbeats(smfAddr)

	// Session establishment: the request carries an IPv6 Node ID and an F-SEID with the SMF's
	// address in the IPv6 slot.
	smContext := context.NewSMContext("imsi-001010000000601", 6)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	upNodeID := *context.NewNodeID("::1")
	smContext.SMLock.Lock()
	smContext.PFCPContext["::1"] = &context.PFCPSessionContext{NodeID: upNodeID, LocalSEID: 0x6006}
	err := pfcp_message.SendPfcpSessionEstablishmentRequest(upNodeID, smContext, "::1", nil, nil, nil, nil, upf.upf.Port)
	smContext.SMLock.Unlock()
	if err != nil {
		t.Fatalf("session establishment request: %v", err)
	}
	msg, from := upf.read()
	req, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		t.Fatalf("expected a session establishment request, got %s", msg.MessageTypeName())
	}
	checkNodeIDIE(t, "session establishment request", req.NodeID, "::1")
	f, err := req.CPFSEID.FSEID()
	if err != nil {
		t.Fatalf("CP F-SEID: %v", err)
	}
	if f.SEID != 0x6006 || f.HasIPv4() || !f.HasIPv6() || !f.IPv6Address.Equal(net.IPv6loopback) {
		t.Errorf("CP F-SEID = %+v, want SEID 0x6006 at ::1 in the IPv6 slot only", f)
	}
	upf.send(message.NewSessionEstablishmentResponse(0, 0, f.SEID, req.Sequence(), 0,
		ie.NewNodeIDHeuristic("::1"),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(0x7007, nil, net.IPv6loopback),
	), from)
	// The response matched the request's transaction, so it is not retransmitted.
	if !upf.quiet(time.Second) {
		t.Error("the SMF retransmitted the establishment request: it did not match the response")
	}
}

// A dual-stack SMF binds the wildcard and serves an IPv4 and an IPv6 UPF from one socket. A
// response to a request sent from a wildcard socket used to be looked up under the address the
// SMF asked to bind, not the one the socket has ("0.0.0.0:8805" against "[::]:8805"), found no
// transaction, and was dropped.
func TestN4DualStackSmfServesBothFamilies(t *testing.T) {
	requireIPv6Loopback(t)
	nativeDatapath(t)
	local := startSmf(t, "127.0.0.1", context.N4Addrs{IPv4: net.ParseIP("127.0.0.1"), IPv6: net.IPv6loopback})
	if !local.IP.IsUnspecified() {
		t.Fatalf("a dual-stack SMF bound %v, want the wildcard", local)
	}

	v4 := newFakeUPF(t, "127.0.0.1")
	v6 := newFakeUPF(t, "::1")
	if smfAddr := v4.associate("127.0.0.1"); smfAddr.IP.To4() == nil {
		t.Errorf("the SMF reached the IPv4 UPF from %v", smfAddr)
	} else {
		v4.heartbeats(smfAddr)
	}
	if smfAddr := v6.associate("127.0.0.1"); smfAddr.IP.To4() != nil {
		t.Errorf("the SMF reached the IPv6 UPF from %v", smfAddr)
	} else {
		v6.heartbeats(smfAddr)
	}
}

// The old wildcard default, pfcp.addr unset: the socket is the same dual-stack wildcard, and
// responses are matched now.
func TestN4WildcardDefaultMatchesResponses(t *testing.T) {
	nativeDatapath(t)
	startSmf(t, "0.0.0.0", context.N4Addrs{IPv4: net.IPv4zero})
	upf := newFakeUPF(t, "127.0.0.1")
	upf.heartbeats(upf.associate("0.0.0.0"))
}
