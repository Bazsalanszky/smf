// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

// These tests decode what the builders put on the wire and compare it with the layout TS 29.244
// gives each IE. A UPF parses the bytes, not the SMF's rule structs, and a strict one refuses a
// whole request over one IE of the wrong length.

// establishmentOnTheWire builds a Session Establishment Request, marshals it and parses it back.
func establishmentOnTheWire(t *testing.T, pdrs []*context.PDR, fars []*context.FAR) *pfcp_message.SessionEstablishmentRequest {
	t.Helper()
	msg, err := message.BuildPfcpSessionEstablishmentRequest(1, cpNodeID, net.ParseIP(cpNodeID), 1, pdrs, fars, nil)
	if err != nil {
		t.Fatalf("building the establishment request: %v", err)
	}
	buf := make([]byte, msg.MarshalLen())
	if err = msg.MarshalTo(buf); err != nil {
		t.Fatalf("marshalling the establishment request: %v", err)
	}
	req, err := pfcp_message.ParseSessionEstablishmentRequest(buf)
	if err != nil {
		t.Fatalf("parsing the establishment request: %v", err)
	}
	return req
}

// modificationOnTheWire builds a Session Modification Request, marshals it and parses it back.
func modificationOnTheWire(t *testing.T, fars []*context.FAR) *pfcp_message.SessionModificationRequest {
	t.Helper()
	msg, err := message.BuildPfcpSessionModificationRequest(1, 1, 2, net.ParseIP(cpNodeID), nil, fars, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("building the modification request: %v", err)
	}
	buf := make([]byte, msg.MarshalLen())
	if err = msg.MarshalTo(buf); err != nil {
		t.Fatalf("marshalling the modification request: %v", err)
	}
	req, err := pfcp_message.ParseSessionModificationRequest(buf)
	if err != nil {
		t.Fatalf("parsing the modification request: %v", err)
	}
	return req
}

// childIE returns the first IE of type typ among ies.
func childIE(t *testing.T, ies []*ie.IE, typ uint16) *ie.IE {
	t.Helper()
	for _, x := range ies {
		if x.Type == typ {
			return x
		}
	}
	t.Fatalf("no IE of type %d among %d IEs", typ, len(ies))
	return nil
}

// TS 29.244 clause 8.2.26: Apply Action has two octets since Rel-16, DROP to DFRT in the first and
// EDRT, BDPN and DDPN in the second. A one-octet IE is refused by a UPF that checks the length
// (Open5GS: "Invalid TLV length 1. It should be 2"), and with it every establishment.
func TestApplyActionIsTwoOctetsOnTheWire(t *testing.T) {
	forward := context.ApplyAction{Forw: true}
	buffer := context.ApplyAction{Buff: true, Nocp: true}

	req := establishmentOnTheWire(t, nil, []*context.FAR{
		{FARID: 1, ApplyAction: forward, ForwardingParameters: &context.ForwardingParameters{}},
	})
	if len(req.CreateFAR) != 1 {
		t.Fatalf("%d Create FARs on the wire, want 1", len(req.CreateFAR))
	}
	createFAR, err := req.CreateFAR[0].CreateFAR()
	if err != nil {
		t.Fatalf("decoding the Create FAR: %v", err)
	}
	checkApplyAction(t, "Create FAR", childIE(t, createFAR, ie.ApplyAction), 0x02)

	mod := modificationOnTheWire(t, []*context.FAR{
		{FARID: 1, ApplyAction: buffer, State: context.RULE_UPDATE},
	})
	if len(mod.UpdateFAR) != 1 {
		t.Fatalf("%d Update FARs on the wire, want 1", len(mod.UpdateFAR))
	}
	updateFAR, err := mod.UpdateFAR[0].UpdateFAR()
	if err != nil {
		t.Fatalf("decoding the Update FAR: %v", err)
	}
	checkApplyAction(t, "Update FAR", childIE(t, updateFAR, ie.ApplyAction), 0x0c)
}

func checkApplyAction(t *testing.T, where string, applyAction *ie.IE, wantFirst uint8) {
	t.Helper()
	if applyAction.Length != 2 {
		t.Errorf("%s: Apply Action length %d, want 2", where, applyAction.Length)
	}
	flags, err := applyAction.ApplyAction()
	if err != nil {
		t.Fatalf("%s: decoding Apply Action: %v", where, err)
	}
	if len(flags) != 2 || flags[0] != wantFirst || flags[1] != 0 {
		t.Errorf("%s: Apply Action octets %#v, want [%#x 0x00]", where, flags, wantFirst)
	}
}

// The anchor's uplink FAR goes to Core, the uplink direction (TS 29.244 clause 8.2.24, NOTE 1),
// with 3GPP Interface Type N6 (clause 8.2.118) to say it leaves for the data network; the uplink
// PDI comes from Access with type N3 3GPP Access. Open5GS delivers uplink to the data network only
// for Core with N6, and buffered every packet of the SGi-LAN/N6-LAN FAR the SMF used to send.
func TestTheUplinkRulesNameTheirInterfaceTypesOnTheWire(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)},
		Dnn:        "internet",
	}
	far := &context.FAR{FARID: 1}
	dpNode := &context.DataPathNode{
		UPF: &context.UPF{},
		UpLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{"ALLOW-ALL": {PDRID: 1, FAR: far}},
		},
	}
	if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{QERID: 1}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}

	req := establishmentOnTheWire(t, []*context.PDR{dpNode.UpLinkTunnel.PDR["ALLOW-ALL"]}, []*context.FAR{far})
	if len(req.CreatePDR) != 1 || len(req.CreateFAR) != 1 {
		t.Fatalf("%d Create PDRs and %d Create FARs on the wire, want 1 and 1", len(req.CreatePDR), len(req.CreateFAR))
	}

	pdi, err := req.CreatePDR[0].PDI()
	if err != nil {
		t.Fatalf("decoding the PDI: %v", err)
	}
	checkInterface(t, "uplink PDI", pdi, ie.SourceInterface, ie.SrcInterfaceAccess, ie.TGPPInterfaceTypeN33GPPAccess)

	fwd, err := req.CreateFAR[0].ForwardingParameters()
	if err != nil {
		t.Fatalf("decoding the forwarding parameters: %v", err)
	}
	checkInterface(t, "uplink FAR", fwd, ie.DestinationInterface, ie.DstInterfaceCore, ie.TGPPInterfaceTypeN6)
}

// An Update FAR carries the interface type too: a rule's FAR is rebuilt in a modification.
func TestAnUpdatedUplinkFARKeepsItsInterfaceType(t *testing.T) {
	n6 := context.InterfaceTypeN6
	mod := modificationOnTheWire(t, []*context.FAR{{
		FARID:       1,
		State:       context.RULE_UPDATE,
		ApplyAction: context.ApplyAction{Forw: true},
		ForwardingParameters: &context.ForwardingParameters{
			DestinationInterface:     context.DestinationInterface{InterfaceValue: context.DestinationInterfaceCore},
			NetworkInstance:          []byte("internet"),
			DestinationInterfaceType: &n6,
		},
	}})
	if len(mod.UpdateFAR) != 1 {
		t.Fatalf("%d Update FARs on the wire, want 1", len(mod.UpdateFAR))
	}
	fwd, err := mod.UpdateFAR[0].UpdateForwardingParameters()
	if err != nil {
		t.Fatalf("decoding the update forwarding parameters: %v", err)
	}
	checkInterface(t, "updated uplink FAR", fwd, ie.DestinationInterface, ie.DstInterfaceCore, ie.TGPPInterfaceTypeN6)
}

// checkInterface checks the Source or Destination Interface among ies, and the 3GPP Interface Type
// that goes with it.
func checkInterface(t *testing.T, where string, ies []*ie.IE, ifaceIE uint16, wantIface, wantType uint8) {
	t.Helper()
	iface := childIE(t, ies, ifaceIE)
	if len(iface.Payload) != 1 || iface.Payload[0]&0x0f != wantIface {
		t.Errorf("%s: interface octets %#v, want value %d", where, iface.Payload, wantIface)
	}
	typ, err := childIE(t, ies, ie.TGPPInterfaceType).TGPPInterfaceType()
	if err != nil {
		t.Fatalf("%s: decoding the 3GPP Interface Type: %v", where, err)
	}
	if typ != wantType {
		t.Errorf("%s: 3GPP Interface Type %d, want %d", where, typ, wantType)
	}
}
