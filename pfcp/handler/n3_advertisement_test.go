// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The UP IP Resource Information of each association decides the N3 transport, and is recorded
// afresh: a UPF that re-associates without IPv6 on N3 goes back to IPv4.
func TestTheAssociationRecordsTheUPFsN3Families(t *testing.T) {
	configured()
	nodeIP := "10.41.0.3"
	unchanged := time.Now().Add(-time.Hour)
	upf := upfHolding(t, nodeIP, unchanged)

	respond := func(seq uint32, res ...*ie.IE) {
		pfcp_message.InsertPfcpTxn(seq, context.NewNodeID(nodeIP))
		ies := append([]*ie.IE{
			ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
			ie.NewRecoveryTimeStamp(unchanged),
		}, res...)
		HandlePfcpAssociationSetupResponse(&udp.Message{
			RemoteAddr:  at(nodeIP),
			PfcpMessage: message.NewAssociationSetupResponse(seq, ies...),
		})
	}

	// What the omec UPF sends with a DNN and both N3 addresses (flags 0x63).
	respond(92, ie.NewUserPlaneIPResourceInformation(0x63, 0, "10.10.3.1", "2001:db8:630::1",
		string(ie.NewNetworkInstanceFQDN("internet").Payload), ie.SrcInterfaceAccess))
	if got := upf.GetN3Transport(); got != (context.N3Transport{Dual: true}) {
		t.Errorf("both families advertised: N3 transport %+v, want dual", got)
	}

	respond(93, ie.NewUserPlaneIPResourceInformation(0x41, 0, "10.10.3.1", "", "", ie.SrcInterfaceAccess))
	if got := upf.GetN3Transport(); got != (context.N3Transport{}) {
		t.Errorf("IPv4 advertised: N3 transport %+v, want the default", got)
	}

	// An association the UPF sets up carries its own.
	HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupRequest(5,
			ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(unchanged),
			ie.NewUserPlaneIPResourceInformation(0x42, 0, "", "2001:db8:630::1", "", ie.SrcInterfaceAccess)),
	})
	if got := upf.GetN3Transport(); got != (context.N3Transport{Family: context.AddressFamilyIPv6}) {
		t.Errorf("IPv6 advertised by the UPF's request: N3 transport %+v, want IPv6", got)
	}

	respond(94)
	if got := upf.GetN3Transport(); got != (context.N3Transport{}) {
		t.Errorf("nothing advertised: N3 transport %+v, want the default", got)
	}
}
