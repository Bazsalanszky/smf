// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

const (
	testUeIpv4   = "172.250.0.9"
	testUeV6Pfx  = "2001:db8:500:7::/64"
	testCpNodeID = "10.0.0.5"

	testDnnName    = "internet"
	defaultPdrName = "default"
)

// establishmentRules activates a session's default uplink and downlink PDR on upf, as the
// datapath does, and returns them with their FARs and the session QER.
func establishmentRules(t *testing.T, smContext *context.SMContext, upf *context.UPF) ([]*context.PDR, []*context.FAR, []*context.QER) {
	t.Helper()
	smContext.Dnn = testDnnName
	smContext.Tunnel = &context.UPTunnel{ANInformation: struct {
		IPAddress net.IP
		TEID      uint32
	}{IPAddress: net.IP{10, 0, 0, 1}, TEID: 0x1234}}
	qer := &context.QER{QERID: 1, QFI: context.QFI{QFI: 9}, GateStatus: &context.GateStatus{}, MBR: &context.MBR{ULMBR: 1000, DLMBR: 2000}}
	ul := &context.PDR{PDRID: 1, FAR: &context.FAR{FARID: 1}}
	dl := &context.PDR{PDRID: 2, FAR: &context.FAR{FARID: 2}}
	node := &context.DataPathNode{
		UPF:            upf,
		UpLinkTunnel:   &context.GTPTunnel{PDR: map[string]*context.PDR{defaultPdrName: ul}},
		DownLinkTunnel: &context.GTPTunnel{PDR: map[string]*context.PDR{defaultPdrName: dl}},
	}
	if err := node.ActivateUpLinkPdr(smContext, qer, 255); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}
	if err := node.ActivateDlLinkPdr(smContext, qer, 255, &context.DataPath{FirstDPNode: node}); err != nil {
		t.Fatalf("ActivateDlLinkPdr: %v", err)
	}
	return []*context.PDR{ul, dl}, []*context.FAR{ul.FAR, dl.FAR}, []*context.QER{qer}
}

func allocatingUPF() *context.UPF {
	return &context.UPF{UPFunctionFeatures: &context.UPFunctionFeatures{SupportedFeatures1: context.UpFunctionFeatures1Ueip}}
}

// session is a session of the PDU session type with the addresses that type carries.
func session(typ uint8) *context.SMContext {
	addr := &context.UeIpAddr{}
	if typ != nasMessage.PDUSessionTypeIPv6 {
		addr.Ip = net.ParseIP(testUeIpv4).To4()
	}
	if typ == nasMessage.PDUSessionTypeIPv6 || typ == nasMessage.PDUSessionTypeIPv4IPv6 {
		prefix := netip.MustParsePrefix(testUeV6Pfx)
		iid := context.InterfaceIdentifier{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
		addr.Ipv6Prefix, addr.Ipv6Iid = &prefix, &iid
	}
	return &context.SMContext{SelectedPDUSessionType: typ, PDUAddress: addr}
}

// establishmentRequest builds the session's establishment request on upf as
// SendPfcpSessionEstablishmentRequest does, and returns it in bytes.
func establishmentRequest(t *testing.T, smContext *context.SMContext, upf *context.UPF) []byte {
	t.Helper()
	pdrs, fars, qers := establishmentRules(t, smContext, upf)
	msg, err := message.BuildPfcpSessionEstablishmentRequestOfPDNType(message.PDNType(smContext.SelectedPDUSessionType),
		43, testCpNodeID, net.ParseIP(testCpNodeID), 7, pdrs, fars, qers)
	if err != nil {
		t.Fatal(err)
	}
	b, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The establishment request of an IPv4 session, byte for byte as the SMF built it before IPv6
// sessions, the UPF allocating or not; and of a session with no PDU session type, which is IPv4.
func TestIPv4EstablishmentRequestIsEncodedAsBefore(t *testing.T) {
	golden := map[bool]string{
		false: "2332012d000000000000000000002b00003c0005000a0000050039000d0200000000000000070a00000500010048003800020001001d0004000000ff000200200014000100001500020d0100160008696e7465726e6574005d000502acfa0009005f00020000006c000400000001006d00040000000100010034003800020002001d0004000000ff00020012001400010100160000005d000502acfa0009006c000400000002006d00040000000100030022006c000400000001002c00010200040011002a00010200160008696e7465726e657400030030006c000400000002002c0001000004001f002a00010000160008696e7465726e65740054000a0100000012340a00000100070020006d0004000000010019000100007c000109001a000a00000003e800000007d00071000101",
		true:  "23320125000000000000000000002b00003c0005000a0000050039000d0200000000000000070a00000500010044003800020001001d0004000000ff0002001c0014000100001500020d0100160008696e7465726e6574005d000110005f00020000006c000400000001006d00040000000100010030003800020002001d0004000000ff0002000e001400010100160000005d000110006c000400000002006d00040000000100030022006c000400000001002c00010200040011002a00010200160008696e7465726e657400030030006c000400000002002c0001000004001f002a00010000160008696e7465726e65740054000a0100000012340a00000100070020006d0004000000010019000100007c000109001a000a00000003e800000007d00071000101",
	}
	for _, typ := range []uint8{nasMessage.PDUSessionTypeIPv4, 0} {
		for _, upfAllocates := range []bool{false, true} {
			upf := &context.UPF{}
			if upfAllocates {
				upf = allocatingUPF()
			}
			smContext := session(nasMessage.PDUSessionTypeIPv4)
			smContext.SelectedPDUSessionType = typ
			if got := hex.EncodeToString(establishmentRequest(t, smContext, upf)); got != golden[upfAllocates] {
				t.Errorf("type %d, UPF allocates %t:\n got %s\nwant %s", typ, upfAllocates, got, golden[upfAllocates])
			}
		}
	}
}

func TestPDNType(t *testing.T) {
	for pduSessionType, want := range map[uint8]uint8{
		nasMessage.PDUSessionTypeIPv4:         ie.PDNTypeIPv4,
		nasMessage.PDUSessionTypeIPv6:         ie.PDNTypeIPv6,
		nasMessage.PDUSessionTypeIPv4IPv6:     ie.PDNTypeIPv4v6,
		0:                                     ie.PDNTypeIPv4,
		nasMessage.PDUSessionTypeUnstructured: ie.PDNTypeIPv4,
		nasMessage.PDUSessionTypeEthernet:     ie.PDNTypeIPv4,
	} {
		if got := message.PDNType(pduSessionType); got != want {
			t.Errorf("PDNType(%d) = %d, want %d", pduSessionType, got, want)
		}
	}
}

// ueIPAddressIEs returns the UE IP Address IE of each Create PDR of a parsed request, in bytes
// and decoded, by PDR ID.
func ueIPAddressIEs(t *testing.T, req *pfcp_message.SessionEstablishmentRequest) (map[uint16]string, map[uint16]*ie.UEIPAddressFields) {
	t.Helper()
	raw, decoded := map[uint16]string{}, map[uint16]*ie.UEIPAddressFields{}
	for _, createPDR := range req.CreatePDR {
		id, err := createPDR.PDRID()
		if err != nil {
			t.Fatal(err)
		}
		pdi, err := createPDR.PDI()
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range pdi {
			if x.Type != ie.UEIPAddress {
				continue
			}
			raw[id] = hex.EncodeToString(x.Payload)
			if decoded[id], err = x.UEIPAddress(); err != nil {
				t.Fatalf("PDR %d: decoding the UE IP Address: %v", id, err)
			}
		}
	}
	return raw, decoded
}

// The PDN Type and the UE IP Address IE of each PDR (TS 29.244 clauses 8.2.79 and 8.2.62) on the
// wire, and as go-pfcp decodes them: PDR 1 is the uplink, PDR 2 the downlink. The IPv6 part is
// V6 (bit 1) with the UE's address, the /64 and the identifier from the PDU address, and IP6PL
// (bit 7) with the length 64, and S/D (bit 3) on the downlink.
func TestUEIPAddressAndPDNTypeOnTheWire(t *testing.T) {
	const (
		v4 = "acfa0009"
		v6 = "20010db805000007" + "0123456789abcdef" + "40" // the prefix, the UE's identifier, the length
	)
	for _, tc := range []struct {
		name         string
		typ          uint8
		upfAllocates bool
		pdnType      uint8
		ul, dl       string
	}{
		{name: "IPv4", typ: nasMessage.PDUSessionTypeIPv4, pdnType: ie.PDNTypeIPv4, ul: "02" + v4, dl: "02" + v4},
		{name: "IPv4, the UPF allocates", typ: nasMessage.PDUSessionTypeIPv4, upfAllocates: true, pdnType: ie.PDNTypeIPv4, ul: "10", dl: "10"},
		{name: "IPv6", typ: nasMessage.PDUSessionTypeIPv6, pdnType: ie.PDNTypeIPv6, ul: "41" + v6, dl: "45" + v6},
		{name: "IPv6, the UPF allocates", typ: nasMessage.PDUSessionTypeIPv6, upfAllocates: true, pdnType: ie.PDNTypeIPv6, ul: "41" + v6, dl: "45" + v6},
		{name: "IPv4v6", typ: nasMessage.PDUSessionTypeIPv4IPv6, pdnType: ie.PDNTypeIPv4v6, ul: "43" + v4 + v6, dl: "47" + v4 + v6},
		{name: "IPv4v6, the UPF allocates", typ: nasMessage.PDUSessionTypeIPv4IPv6, upfAllocates: true, pdnType: ie.PDNTypeIPv4v6, ul: "51" + v6, dl: "55" + v6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upf := &context.UPF{}
			if tc.upfAllocates {
				upf = allocatingUPF()
			}
			req, err := pfcp_message.ParseSessionEstablishmentRequest(establishmentRequest(t, session(tc.typ), upf))
			if err != nil {
				t.Fatalf("parsing the request: %v", err)
			}
			if req.PDNType == nil {
				t.Fatal("no PDN Type")
			}
			if got, err := req.PDNType.PDNType(); err != nil || got != tc.pdnType {
				t.Errorf("PDN Type %d (%v), want %d", got, err, tc.pdnType)
			}

			raw, decoded := ueIPAddressIEs(t, req)
			if raw[1] != tc.ul || raw[2] != tc.dl {
				t.Errorf("UE IP Address\n uplink   %s, want %s\n downlink %s, want %s", raw[1], tc.ul, raw[2], tc.dl)
			}
			for id, f := range decoded {
				hasV4 := tc.typ != nasMessage.PDUSessionTypeIPv6 && !tc.upfAllocates
				if hasV4 != f.IPv4Address.Equal(net.ParseIP(testUeIpv4)) {
					t.Errorf("PDR %d: IPv4 %v", id, f.IPv4Address)
				}
				hasV6 := tc.typ != nasMessage.PDUSessionTypeIPv4
				if hasV6 && (!f.IPv6Address.Equal(net.ParseIP("2001:db8:500:7:123:4567:89ab:cdef")) || f.IPv6PrefixLength != 64) {
					t.Errorf("PDR %d: IPv6 %v/%d, want the UE address /64", id, f.IPv6Address, f.IPv6PrefixLength)
				}
				if !hasV6 && f.IPv6Address != nil {
					t.Errorf("PDR %d: an IPv4 session's rule carries IPv6 %v", id, f.IPv6Address)
				}
			}
		})
	}
}
