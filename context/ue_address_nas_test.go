// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasConvert"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

const (
	testUeIpv4      = "172.250.0.7"
	testDnsIpv4     = "8.8.8.8"
	testDnsIpv6     = "2001:db8:53::53"
	testPcscfIpv6   = "2001:db8:5c::1"
	testGlobalPcscf = "2001:db8::99"
	testDnnName     = "internet"
)

// establishmentFixture is a session as far as the establishment accept and the setup request
// transfer need it: an AMBR, an N3 address, a DNN with an IPv4 DNS server and an MTU, and the UE
// asking for the DNS servers and the MTU. It uses nothing the SMF had before IPv6 sessions, so
// the IPv4 goldens below were taken with it from the SMF before this change.
func establishmentFixture(pduSessionType, acceptCause uint8, ip net.IP) *SMContext {
	node := NewDataPathNode()
	node.UPF = &UPF{N3Interfaces: []UPFInterfaceInfo{{IPv4EndPointAddresses: []net.IP{net.ParseIP("192.168.252.3")}}}}
	node.UpLinkTunnel.TEID = 0x01020304

	snssai := models.NewSnssai(1)
	snssai.SetSd("010203")
	smContext := &SMContext{
		Supi:                    testSupi,
		PDUSessionID:            5,
		Pti:                     7,
		Dnn:                     testDnnName,
		Snssai:                  snssai,
		SelectedPDUSessionType:  pduSessionType,
		EstAcceptCause5gSMValue: acceptCause,
		PDUAddress:              &UeIpAddr{Ip: ip},
		DNNInfo:                 &SnssaiSmfDnnInfo{MTU: 1400, DNS: DNS{IPv4Addr: net.ParseIP(testDnsIpv4).To4()}},
		ProtocolConfigurationOptions: &ProtocolConfigurationOptions{
			DNSIPv4Request: true, DNSIPv6Request: true, IPv4LinkMTURequest: true,
		},
		SmPolicyUpdates: []*qos.PolicyUpdate{{}},
		Tunnel: &UPTunnel{DataPathPool: DataPathPool{
			1: &DataPath{IsDefaultPath: true, FirstDPNode: node},
		}},
	}
	ambr := models.NewAmbr("100 Mbps", "200 Mbps")
	sessionRule := models.NewSessionRuleWithDefaults()
	sessionRule.SetAuthSessAmbr(*ambr)
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = sessionRule
	smContext.initLogTags()
	return smContext
}

// The IPv4 establishment accept and setup request transfer, byte for byte as the SMF built them
// before IPv6 sessions: an IPv4 request, and an IPv4v6 request served with IPv4 and cause #50.
// The UE asks for an IPv6 DNS server as well, which an IPv4 session never received.
func TestIPv4EstablishmentIsEncodedAsBefore(t *testing.T) {
	// The setup request transfer is the same for both: AMBR, N3 tunnel, PDU Session Type IPv4.
	const transfer = "0000030082000a0c0bebc2003005f5e100008b000a01f0c0a8fc03010203040086000100"
	for _, tc := range []struct {
		name, accept string
		cause        uint8
	}{
		{
			name:   nameIPv4,
			accept: "2e0507c2110000060600c8060064290501acfa00072204010102037900007b000d80000d04080808080010020578250908696e7465726e6574",
		},
		{
			name:   "IPv4v6 requested, IPv4 served",
			cause:  c50,
			accept: "2e0507c2110000060600c80600645932290501acfa00072204010102037900007b000d80000d04080808080010020578250908696e7465726e6574",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := establishmentFixture(tV4, tc.cause, net.ParseIP(testUeIpv4).To4())
			accept, err := BuildGSMPDUSessionEstablishmentAccept(smContext)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(accept); got != tc.accept {
				t.Errorf("establishment accept\n got %s\nwant %s", got, tc.accept)
			}
			b, err := BuildPDUSessionResourceSetupRequestTransfer(smContext)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(b); got != transfer {
				t.Errorf("setup request transfer\n got %s\nwant %s", got, transfer)
			}
		})
	}
}

// ueIid is a copy of testIid for a session to hold.
func ueIid() *InterfaceIdentifier {
	iid := testIid
	return &iid
}

// The PDU address information of TS 24.501 clause 9.11.4.10, for each PDU session type.
func TestPDUAddressToNAS(t *testing.T) {
	prefix := netip.MustParsePrefix(firstTestPrefix)
	for _, tc := range []struct {
		name    string
		typ     uint8
		ip      net.IP
		v6      bool
		want    string
		wantLen uint8
	}{
		{name: nameIPv4, typ: tV4, ip: net.ParseIP(testUeIpv4).To4(), want: "acfa0007" + "0000000000000000", wantLen: 5},
		// A 16-byte IPv4 address, as a session restored from the datastore holds it, is
		// encoded as the same 4 bytes.
		{name: "IPv4, 16-byte form", typ: tV4, ip: net.ParseIP(testUeIpv4), want: "acfa0007" + "0000000000000000", wantLen: 5},
		{name: nameIPv6, typ: tV6, v6: true, want: "0123456789abcdef" + "00000000", wantLen: 9},
		{name: nameIPv4v6, typ: tV4V6, ip: net.ParseIP(testUeIpv4).To4(), v6: true, want: "0123456789abcdef" + "acfa0007", wantLen: 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := &SMContext{SelectedPDUSessionType: tc.typ, PDUAddress: &UeIpAddr{Ip: tc.ip}}
			if tc.v6 {
				smContext.PDUAddress.Ipv6Prefix, smContext.PDUAddress.Ipv6Iid = &prefix, ueIid()
			}
			addr, addrLen := smContext.PDUAddressToNAS()
			if got := hex.EncodeToString(addr[:]); got != tc.want || addrLen != tc.wantLen {
				t.Errorf("PDU address %s length %d, want %s length %d", got, addrLen, tc.want, tc.wantLen)
			}
		})
	}
}

// decodeAccept decodes an establishment accept the way the UE does.
func decodeAccept(t *testing.T, b []byte) *nasMessage.PDUSessionEstablishmentAccept {
	t.Helper()
	m := nas.NewMessage()
	if err := m.GsmMessageDecode(&b); err != nil {
		t.Fatalf("decoding the accept: %v", err)
	}
	if m.PDUSessionEstablishmentAccept == nil {
		t.Fatalf("message type %#x is not an establishment accept", m.GsmHeader.GetMessageType())
	}
	return m.PDUSessionEstablishmentAccept
}

// pcoContainers decodes the accept's extended PCO into its containers, by identifier.
func pcoContainers(t *testing.T, accept *nasMessage.PDUSessionEstablishmentAccept) map[uint16][]byte {
	t.Helper()
	containers := map[uint16][]byte{}
	if accept.ExtendedProtocolConfigurationOptions == nil {
		return containers
	}
	pco := nasConvert.NewProtocolConfigurationOptions()
	if err := pco.UnMarshal(accept.GetExtendedProtocolConfigurationOptionsContents()); err != nil {
		t.Fatalf("decoding the PCO: %v", err)
	}
	for _, c := range pco.ProtocolOrContainerList {
		containers[c.ProtocolOrContainerID] = c.Contents
	}
	return containers
}

// The accept of an IPv6 and an IPv4v6 session, as the UE decodes it: the PDU session type, the
// PDU address IE with the interface identifier, and the IPv6 DNS server and P-CSCF in the PCO
// next to the IPv4 ones.
func TestIPv6EstablishmentAccept(t *testing.T) {
	prefix := netip.MustParsePrefix(firstTestPrefix)
	for _, tc := range []struct {
		name      string
		typ       uint8
		ip        net.IP
		wantAddr  string
		wantIPv4  bool
		wantCause uint8
	}{
		{name: nameIPv6, typ: tV6, wantAddr: "0123456789abcdef", wantCause: c51},
		{name: nameIPv4v6, typ: tV4V6, ip: net.ParseIP(testUeIpv4).To4(), wantAddr: "0123456789abcdef" + "acfa0007", wantIPv4: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := establishmentFixture(tc.typ, tc.wantCause, tc.ip)
			smContext.PDUAddress.Ipv6Prefix, smContext.PDUAddress.Ipv6Iid = &prefix, ueIid()
			smContext.DNNInfo.DNS.IPv6Addr = net.ParseIP(testDnsIpv6)
			smContext.DNNInfo.PCSCFIPv6 = net.ParseIP(testPcscfIpv6)
			smContext.ProtocolConfigurationOptions.PCSCFIPv6Request = true

			b, err := BuildGSMPDUSessionEstablishmentAccept(smContext)
			if err != nil {
				t.Fatal(err)
			}
			accept := decodeAccept(t, b)
			if got := accept.GetPDUSessionType(); got != tc.typ {
				t.Errorf("selected PDU session type %d, want %d", got, tc.typ)
			}
			if accept.PDUAddress == nil {
				t.Fatal("no PDU address IE")
			}
			if got := accept.GetPDUSessionTypeValue(); got != tc.typ {
				t.Errorf("PDU address type %d, want %d", got, tc.typ)
			}
			info := accept.GetPDUAddressInformation()
			if got := hex.EncodeToString(info[:accept.PDUAddress.GetLen()-1]); got != tc.wantAddr {
				t.Errorf("PDU address information %s, want %s", got, tc.wantAddr)
			}
			if got := (accept.Cause5GSM != nil); got != (tc.wantCause != 0) ||
				(got && accept.GetCauseValue() != tc.wantCause) {
				t.Errorf("accept cause present %t, want %d", got, tc.wantCause)
			}

			containers := pcoContainers(t, accept)
			for id, want := range map[uint16]net.IP{
				nasMessage.DNSServerIPv6AddressDL: net.ParseIP(testDnsIpv6),
				nasMessage.PCSCFIPv6AddressDL:     net.ParseIP(testPcscfIpv6),
				nasMessage.DNSServerIPv4AddressDL: net.ParseIP(testDnsIpv4).To4(),
			} {
				if got, ok := containers[id]; !ok || !bytes.Equal(got, want) {
					t.Errorf("PCO container %#04x = %x (present %t), want %x", id, got, ok, []byte(want))
				}
			}
		})
	}
}

// The PCO's IPv6 containers in bytes (TS 24.008 clause 10.5.6.3): the container identifier, the
// length 16 and the address.
func TestIPv6PCOContainersBytes(t *testing.T) {
	prefix := netip.MustParsePrefix(firstTestPrefix)
	smContext := establishmentFixture(tV6, 0, nil)
	smContext.PDUAddress.Ipv6Prefix, smContext.PDUAddress.Ipv6Iid = &prefix, ueIid()
	smContext.DNNInfo.DNS.IPv6Addr = net.ParseIP(testDnsIpv6)
	smContext.DNNInfo.PCSCFIPv6 = net.ParseIP(testPcscfIpv6)
	smContext.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{DNSIPv6Request: true, PCSCFIPv6Request: true}

	b, err := BuildGSMPDUSessionEstablishmentAccept(smContext)
	if err != nil {
		t.Fatal(err)
	}
	accept := decodeAccept(t, b)
	got := hex.EncodeToString(accept.GetExtendedProtocolConfigurationOptionsContents())
	const want = "80" + // configuration protocol
		"0003" + "10" + "20010db8005300000000000000000053" + // DNS server IPv6 address
		"0001" + "10" + "20010db8005c00000000000000000001" // P-CSCF IPv6 address
	if got != want {
		t.Errorf("PCO\n got %s\nwant %s", got, want)
	}
}

// An IPv4 session gets neither IPv6 container, whatever the UE asks for: it has no way to reach
// them. The P-CSCF IPv6 request is not even recorded, so that the session is stored as before.
func TestIPv4SessionGetsNoIPv6Containers(t *testing.T) {
	smContext := establishmentFixture(tV4, 0, net.ParseIP(testUeIpv4).To4())
	smContext.DNNInfo.DNS.IPv6Addr = net.ParseIP(testDnsIpv6)
	smContext.DNNInfo.PCSCFIPv6 = net.ParseIP(testPcscfIpv6)
	smContext.ProtocolConfigurationOptions.PCSCFIPv6Request = true
	b, err := BuildGSMPDUSessionEstablishmentAccept(smContext)
	if err != nil {
		t.Fatal(err)
	}
	containers := pcoContainers(t, decodeAccept(t, b))
	for _, id := range []uint16{nasMessage.DNSServerIPv6AddressDL, nasMessage.PCSCFIPv6AddressDL} {
		if c, ok := containers[id]; ok {
			t.Errorf("an IPv4 session was sent container %#04x %x", id, c)
		}
	}

	// The request handler leaves PCSCFIPv6Request unset for an IPv4 session.
	handled := &SMContext{
		DNNInfo:                      dualStackDnn(t, "172.250.0.0/24", testUeIpv6Pool),
		DnnConfiguration:             models.DnnConfiguration{PduSessionTypes: subV4V6},
		ProtocolConfigurationOptions: &ProtocolConfigurationOptions{},
	}
	handled.initLogTags()
	for _, typ := range []uint8{tV4, tV6} {
		req := nasMessage.NewPDUSessionEstablishmentRequest(0)
		req.SetPDUSessionID(5)
		req.PDUSessionType = nasType.NewPDUSessionType(nasMessage.PDUSessionEstablishmentRequestPDUSessionTypeType)
		req.SetPDUSessionTypeValue(typ)
		pco := nasConvert.NewProtocolConfigurationOptions()
		pco.ProtocolOrContainerList = append(pco.ProtocolOrContainerList,
			&nasConvert.ProtocolOrContainerUnit{ProtocolOrContainerID: nasMessage.PCSCFIPv6AddressRequestUL})
		contents := pco.Marshal()
		req.ExtendedProtocolConfigurationOptions = nasType.NewExtendedProtocolConfigurationOptions(
			nasMessage.PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType)
		req.ExtendedProtocolConfigurationOptions.SetLen(uint16(len(contents)))
		req.SetExtendedProtocolConfigurationOptionsContents(contents)

		handled.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{}
		if err := handled.HandlePDUSessionEstablishmentRequest(req); err != nil {
			t.Fatal(err)
		}
		if got, want := handled.ProtocolConfigurationOptions.PCSCFIPv6Request, typ == tV6; got != want {
			t.Errorf("type %d: PCSCFIPv6Request %t, want %t", typ, got, want)
		}
	}
}

// The P-CSCF IPv6 address: the DNN's, else the SMF's pcscfInfos.ipv6 when that is IPv6.
func TestPcscfIPv6(t *testing.T) {
	saved := SMF_Self().PCSCFInfo
	t.Cleanup(func() { SMF_Self().PCSCFInfo = saved })
	for _, tc := range []struct {
		name, dnn, global, want string
	}{
		{name: "the DNN's", dnn: testPcscfIpv6, global: testGlobalPcscf, want: testPcscfIpv6},
		{name: "the SMF's", global: testGlobalPcscf, want: testGlobalPcscf},
		{name: "an IPv4 global", global: "198.51.100.17"},
		{name: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SMF_Self().PCSCFInfo.IPv6Addr = tc.global
			smContext := &SMContext{DNNInfo: &SnssaiSmfDnnInfo{PCSCFIPv6: net.ParseIP(tc.dnn)}}
			got := smContext.pcscfIPv6()
			if (got == nil) != (tc.want == "") || (got != nil && !got.Equal(net.ParseIP(tc.want))) {
				t.Errorf("pcscfIPv6 = %v, want %q", got, tc.want)
			}
		})
	}
}

// decodeTransferPDUSessionType decodes a setup request transfer the way the gNB does and returns
// its PDU Session Type IE.
func decodeTransferPDUSessionType(t *testing.T, b []byte) aper.Enumerated {
	t.Helper()
	var transfer ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(b, &transfer, "valueExt"); err != nil {
		t.Fatalf("decoding the transfer: %v", err)
	}
	for _, ie := range transfer.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDPDUSessionType {
			return ie.Value.PDUSessionType.Value
		}
	}
	t.Fatal("the transfer has no PDU Session Type IE")
	return 0
}

// The setup request transfer tells the gNB the selected PDU session type (TS 38.413 clause
// 9.3.1.52), which was IPv4 for every session.
func TestSetupRequestTransferPDUSessionType(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
		want aper.Enumerated
	}{
		{nameIPv4, tV4, ngapType.PDUSessionTypePresentIpv4},
		{nameIPv6, tV6, ngapType.PDUSessionTypePresentIpv6},
		{nameIPv4v6, tV4V6, ngapType.PDUSessionTypePresentIpv4v6},
		{"unset", 0, ngapType.PDUSessionTypePresentIpv4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ngapPDUSessionType(tc.typ); got != tc.want {
				t.Errorf("ngapPDUSessionType(%d) = %d, want %d", tc.typ, got, tc.want)
			}
			b, err := BuildPDUSessionResourceSetupRequestTransfer(establishmentFixture(tc.typ, 0, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeTransferPDUSessionType(t, b); got != tc.want {
				t.Errorf("transfer PDU Session Type %d, want %d", got, tc.want)
			}
		})
	}
}
