// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestNewCPFSEID(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	tests := []struct {
		name           string
		addrs          []net.IP
		wantV4, wantV6 net.IP
	}{
		{"IPv4 SMF", []net.IP{v4}, v4, nil},
		{"IPv4 SMF, 4-byte form", []net.IP{v4.To4()}, v4, nil},
		{"IPv6 SMF: the address goes in the IPv6 slot, not the IPv4 one", []net.IP{v6}, nil, v6},
		{"dual-stack SMF", []net.IP{v4, v6}, v4, v6},
		{"dual-stack SMF without an IPv4 argument", []net.IP{nil, v6}, nil, v6},
		{"first of each family wins", []net.IP{v6, v4, net.ParseIP("2001:db8::2"), net.ParseIP("192.0.2.2")}, v4, v6},
		{"no address", []net.IP{nil}, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkFSEID(t, message.NewCPFSEID(42, tc.addrs...), 42, tc.wantV4, tc.wantV6)
		})
	}
}

// The session requests put the SMF's address in the F-SEID slot of its family, and a
// dual-stack SMF's addresses in both.
func TestSessionRequestsFSEIDByFamily(t *testing.T) {
	v4, v6 := net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")
	for _, tc := range []struct {
		name           string
		first          net.IP
		more           []net.IP
		wantV4, wantV6 net.IP
	}{
		{"IPv4", v4, nil, v4, nil},
		{"IPv6", v6, nil, nil, v6},
		{"IPv6 after an absent IPv4", nil, []net.IP{v6}, nil, v6},
		{"dual-stack", v4, []net.IP{v6}, v4, v6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			est, err := message.BuildPfcpSessionEstablishmentRequest(1, "fd00::1", tc.first, 7,
				[]*context.PDR{}, []*context.FAR{}, []*context.QER{}, tc.more...)
			if err != nil {
				t.Fatal(err)
			}
			checkFSEID(t, est.CPFSEID, 7, tc.wantV4, tc.wantV6)

			mod, err := message.BuildPfcpSessionModificationRequest(2, 7, 8, tc.first,
				nil, nil, nil, nil, nil, nil, tc.more...)
			if err != nil {
				t.Fatal(err)
			}
			checkFSEID(t, mod.CPFSEID, 7, tc.wantV4, tc.wantV6)

			del := message.BuildPfcpSessionDeletionRequest(3, 7, 8, tc.first, tc.more...)
			if len(del.IEs) != 1 {
				t.Fatalf("deletion request has %d IEs, want the F-SEID only", len(del.IEs))
			}
			checkFSEID(t, del.IEs[0], 7, tc.wantV4, tc.wantV6)
		})
	}
}

// The Node ID IE carries the SMF's Node ID in its own type: an IPv6 Node ID used to reach
// the wire as the FQDN "<nil>" (it was set with To4()), and an FQDN one could not be set.
func TestNodeIDIEType(t *testing.T) {
	for _, tc := range []struct {
		nodeID   string
		wantType uint8
	}{
		{"10.0.0.1", ie.NodeIDIPv4Address},
		{"2001:db8::1", ie.NodeIDIPv6Address},
		{"smf.example.org", ie.NodeIDFQDN},
	} {
		t.Run(tc.nodeID, func(t *testing.T) {
			nodeID := context.NewNodeID(tc.nodeID)
			req := message.BuildPfcpAssociationSetupRequest(1, time.Now(), nodeID.ValueString(), false)
			if req.NodeID == nil || len(req.NodeID.Payload) == 0 {
				t.Fatal("no Node ID IE")
			}
			if got := req.NodeID.Payload[0]; got != tc.wantType {
				t.Errorf("Node ID type = %d, want %d", got, tc.wantType)
			}
			got, err := req.NodeID.NodeID()
			if err != nil || got != tc.nodeID {
				t.Errorf("Node ID = %q, %v; want %q", got, err, tc.nodeID)
			}
		})
	}
}

func checkFSEID(t *testing.T, fseidIE *ie.IE, wantSEID uint64, wantV4, wantV6 net.IP) {
	t.Helper()
	if fseidIE == nil {
		t.Fatal("no F-SEID IE")
	}
	// Through the wire format, as the UPF reads it.
	b, err := fseidIE.Marshal()
	if err != nil {
		t.Fatalf("marshalling the F-SEID: %v", err)
	}
	parsed, err := ie.Parse(b)
	if err != nil {
		t.Fatalf("parsing the F-SEID: %v", err)
	}
	f, err := parsed.FSEID()
	if err != nil {
		t.Fatalf("reading the F-SEID: %v", err)
	}
	if f.SEID != wantSEID {
		t.Errorf("SEID = %d, want %d", f.SEID, wantSEID)
	}
	if f.HasIPv4() != (wantV4 != nil) || (wantV4 != nil && !f.IPv4Address.Equal(wantV4)) {
		t.Errorf("IPv4 slot = %t %v, want %v", f.HasIPv4(), f.IPv4Address, wantV4)
	}
	if f.HasIPv6() != (wantV6 != nil) || (wantV6 != nil && !f.IPv6Address.Equal(wantV6)) {
		t.Errorf("IPv6 slot = %t %v, want %v", f.HasIPv6(), f.IPv6Address, wantV6)
	}
}
