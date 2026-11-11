// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package ra

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/gtpu"
	"github.com/omec-project/smf/ndp"
)

// The router solicitations of ndp's tests: from fe80::1234:5678:9abc:def0, and from the unspecified
// address, to ff02::2.
const (
	solicitation            = "6000000000083afffe80000000000000123456789abcdef0ff02000000000000000000000000000285009add00000000"
	solicitationUnspecified = "6000000000083aff00000000000000000000000000000000ff0200000000000000000000000000028500" + "7bb800000000"
)

const (
	testSEID    = 0x1234
	testUPFTEID = 0x99
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testSession is an IPv6 session whose router advertisement rules are installed and whose CP2UP
// F-TEID is testUPFTEID at upf.
func testSession(upf netip.Addr) *context.SMContext {
	prefix := netip.MustParsePrefix("2001:db8:500::/64")
	iid := context.InterfaceIdentifier{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	smContext := context.NewSMContext("imsi-208930000000001", 5)
	smContext.PDUAddress = &context.UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &iid}
	smContext.DNNInfo = &context.SnssaiSmfDnnInfo{MTU: 1400}
	rules := &context.RouterAdvertisementRules{
		Solicitation: &context.PDR{PDRID: 3, FAR: &context.FAR{ForwardingParameters: &context.ForwardingParameters{
			OuterHeaderCreation: &context.OuterHeaderCreation{Teid: testSEID},
		}}},
		Advertisement: &context.PDR{PDRID: 4, PDI: context.PDI{LocalFTeid: &context.FTEID{
			Ch: true, Teid: testUPFTEID, Ipv4Address: net.IP(upf.AsSlice()),
		}}},
	}
	node := &context.DataPathNode{UPF: context.NewUPF(context.NewNodeID(upf.String()), nil), RouterAdvertisement: rules}
	smContext.Tunnel = &context.UPTunnel{DataPathPool: context.DataPathPool{1: {IsDefaultPath: true, FirstDPNode: node}}}
	return smContext
}

// fakeUPF is the UPF's N3 socket the service sends advertisements to.
type fakeUPF struct {
	conn *net.UDPConn
}

func newFakeUPF(t *testing.T) *fakeUPF {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeUPF{conn: conn}
}

func (u *fakeUPF) port() uint16 { return u.conn.LocalAddr().(*net.UDPAddr).AddrPort().Port() }

// receive returns the next G-PDU, or nil when none arrives within wait.
func (u *fakeUPF) receive(t *testing.T, wait time.Duration) *gtpu.Message {
	t.Helper()
	if err := u.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, err := u.conn.Read(b)
	if err != nil {
		return nil
	}
	msg, err := gtpu.Parse(b[:n])
	if err != nil {
		t.Fatalf("not GTP-U: %v", err)
	}
	return msg
}

func (u *fakeUPF) send(t *testing.T, to netip.AddrPort, teid uint32, payload []byte) {
	t.Helper()
	if _, err := u.conn.WriteToUDPAddrPort(gtpu.NewGPDU(teid, payload), to); err != nil {
		t.Fatal(err)
	}
}

// startService runs a service on 127.0.0.1 that finds smContext by testSEID and sends to upf.
func startService(t *testing.T, upf *fakeUPF, smContext *context.SMContext) (*Service, netip.AddrPort) {
	t.Helper()
	s, err := listen([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, 0, upf.port(), func(seid uint64) *context.SMContext {
		if seid == testSEID {
			return smContext
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.endpoint.Close()
		s.wg.Wait()
	})
	return s, s.endpoint.LocalAddrs()[0]
}

// checkAdvertisement checks pkt is a router advertisement of the test session's prefix from the
// router's link-local address to dst, as the UE's stack would read it.
func checkAdvertisement(t *testing.T, msg *gtpu.Message, dst netip.Addr) {
	t.Helper()
	if msg == nil {
		t.Fatal("no router advertisement")
	}
	if msg.Type != gtpu.MsgTypeGPDU || msg.TEID != testUPFTEID {
		t.Fatalf("GTP-U type %d TEID %#x, want a G-PDU to %#x", msg.Type, msg.TEID, testUPFTEID)
	}
	pkt := msg.Payload
	if len(pkt) < 40+16+32 || pkt[0]>>4 != 6 || pkt[6] != 58 || pkt[7] != 255 {
		t.Fatalf("not an ICMPv6 packet with hop limit 255: % x", pkt)
	}
	if src := netip.AddrFrom16([16]byte(pkt[8:24])); src != netip.MustParseAddr("fe80::1") {
		t.Errorf("source %s", src)
	}
	if got := netip.AddrFrom16([16]byte(pkt[24:40])); got != dst {
		t.Errorf("destination %s, want %s", got, dst)
	}
	icmp := pkt[40:]
	if icmp[0] != 134 || icmp[4] != curHopLimit || icmp[5] != 0 {
		t.Errorf("type %d, hop limit %d, flags %#x", icmp[0], icmp[4], icmp[5])
	}
	pio := icmp[16:]
	if pio[0] != 3 || pio[2] != 64 || pio[3] != 0x40 {
		t.Errorf("prefix option type %d, length %d, flags %#x; want 3, /64, A only", pio[0], pio[2], pio[3])
	}
	if p := netip.AddrFrom16([16]byte(pio[16:32])); p != netip.MustParseAddr("2001:db8:500::") {
		t.Errorf("prefix %s", p)
	}
}

// A router solicitation the UPF forwards with the session's TEID is answered with an advertisement
// of the session's prefix, sent to the UPF's CP2UP F-TEID: unicast to the solicitation's source,
// or to all nodes when the source is unspecified.
func TestASolicitationIsAnsweredOnTheCP2UPFTEID(t *testing.T) {
	upf := newFakeUPF(t)
	_, smf := startService(t, upf, testSession(netip.MustParseAddr("127.0.0.1")))

	upf.send(t, smf, testSEID, mustHex(t, solicitation))
	checkAdvertisement(t, upf.receive(t, 5*time.Second), netip.MustParseAddr("fe80::1234:5678:9abc:def0"))

	upf.send(t, smf, testSEID, mustHex(t, solicitationUnspecified))
	checkAdvertisement(t, upf.receive(t, 5*time.Second), ndp.AllNodes)
}

// Nothing is answered for a TEID that names no session, for one the session's rules no longer
// name, or for a packet that is not a router solicitation.
func TestOnlyTheSessionsSolicitationsAreAnswered(t *testing.T) {
	upf := newFakeUPF(t)
	smContext := testSession(netip.MustParseAddr("127.0.0.1"))
	_, smf := startService(t, upf, smContext)

	upf.send(t, smf, testSEID+1, mustHex(t, solicitation))
	notRS := mustHex(t, solicitation)
	notRS[40] = 128 // an echo request
	upf.send(t, smf, testSEID, notRS)
	// As a session's rules change: under its lock.
	smContext.SMLock.Lock()
	smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.RouterAdvertisement.Solicitation.FAR.
		ForwardingParameters.OuterHeaderCreation.Teid = testSEID + 2
	smContext.SMLock.Unlock()
	upf.send(t, smf, testSEID, mustHex(t, solicitation))
	if msg := upf.receive(t, 300*time.Millisecond); msg != nil {
		t.Fatalf("answered: TEID %#x", msg.TEID)
	}
}

// The unsolicited advertisement, once the access tunnel is up, goes to all nodes.
func TestTheUnsolicitedAdvertisementGoesToAllNodes(t *testing.T) {
	upf := newFakeUPF(t)
	smContext := testSession(netip.MustParseAddr("127.0.0.1"))
	s, _ := startService(t, upf, smContext)

	s.sendUnsolicited(smContext, *smContext.PDUAddress.Ipv6Prefix, *smContext.PDUAddress.Ipv6Iid)
	checkAdvertisement(t, upf.receive(t, 5*time.Second), ndp.AllNodes)

	// Before the UPF has given the CP2UP F-TEID there is nowhere to send one.
	smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.RouterAdvertisement.Advertisement.PDI.LocalFTeid.Teid = 0
	s.sendUnsolicited(smContext, *smContext.PDUAddress.Ipv6Prefix, *smContext.PDUAddress.Ipv6Iid)
	if msg := upf.receive(t, 300*time.Millisecond); msg != nil {
		t.Fatalf("sent without an F-TEID: TEID %#x", msg.TEID)
	}
}

func TestTheAdvertisementCarriesTheDNNsMTU(t *testing.T) {
	path := &context.RouterAdvertisementPath{Prefix: netip.MustParsePrefix("2001:db8::/64"), LinkMTU: 1400}
	ra := Advertisement(path)
	if ra.MTU != 1400 || ra.OnLink || !ra.Autonomous || ra.Managed || ra.Other ||
		ra.ValidLifetime != ndp.InfiniteLifetime || ra.PreferredLifetime != ndp.InfiniteLifetime ||
		ra.RouterLifetime != routerLifetime || ra.CurHopLimit != curHopLimit {
		t.Errorf("%+v", ra)
	}
	for _, mtu := range []uint16{0, 1279} {
		path.LinkMTU = mtu
		if got := Advertisement(path).MTU; got != 0 {
			t.Errorf("MTU %d advertised as %d, want no MTU option", mtu, got)
		}
	}
}

func TestTheRouterNeverTakesTheUEsLinkLocalAddress(t *testing.T) {
	if got := RouterLinkLocal(context.InterfaceIdentifier{1, 2, 3, 4, 5, 6, 7, 8}); got != netip.MustParseAddr("fe80::1") {
		t.Errorf("router %s", got)
	}
	if got := RouterLinkLocal(context.InterfaceIdentifier{7: 1}); got != netip.MustParseAddr("fe80::2") {
		t.Errorf("router %s for the UE fe80::1", got)
	}
}

func TestParseAddrs(t *testing.T) {
	const v4, v6, both = "[10.0.0.5]", "[fd00::5]", "[10.0.0.5 fd00::5]"
	t.Setenv("RA_TEST_POD_IPS", "10.0.0.5,fd00::5")
	for value, want := range map[string]string{
		"10.0.0.5":            v4,
		"fd00::5":             v6,
		"[fd00::5]":           v6,
		"fd00::5, 10.0.0.5":   both,
		"::ffff:10.0.0.5":     v4,
		"RA_TEST_POD_IPS":     both,
		"10.0.0.5,":           v4,
		"":                    "",
		"0.0.0.0":             "",
		"::":                  "",
		"fe80::1%eth0":        "",
		"10.0.0.5,10.0.0.6":   "",
		"gtpu.example":        "",
		"fd00::5,fd00::6,1.2": "",
	} {
		addrs, err := ParseAddrs(value)
		got := ""
		if err == nil {
			got = fmtAddrs(addrs)
		}
		if got != want {
			t.Errorf("ParseAddrs(%q) = %s (%v), want %q", value, got, err, want)
		}
	}
}

func fmtAddrs(addrs []netip.Addr) string {
	s := "["
	for i, a := range addrs {
		if i > 0 {
			s += " "
		}
		s += a.String()
	}
	return s + "]"
}
