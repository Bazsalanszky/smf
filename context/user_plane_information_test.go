// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"strconv"
	"testing"

	"github.com/omec-project/openapi/v2/nfConfigApi"
)

func makeTestSessionConfig(sliceName, mcc, mnc, sst, sd, dnn, ueSubnet, upfName string, gnbNames []string) nfConfigApi.SessionManagement {
	sstParsed, err := strconv.ParseInt(sst, 10, 32)
	if err != nil {
		sstParsed = 1
	}
	sstUint := int32(sstParsed)
	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId:    nfConfigApi.PlmnId{Mcc: mcc, Mnc: mnc},
		Snssai:    nfConfigApi.Snssai{Sst: sstUint, Sd: &sd},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  dnn,
				DnsIpv4:  "8.8.8.8",
				UeSubnet: ueSubnet,
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: upfName,
			Port:     func() *int32 { p := int32(8805); return &p }(),
		},
		GnbNames: gnbNames,
	}
}

func TestBuildUserPlaneInformation_DefaultPathScenarios(t *testing.T) {
	tests := []struct {
		name       string
		existing   *UserPlaneInformation
		config     []nfConfigApi.SessionManagement
		assertions func(t *testing.T, upi *UserPlaneInformation)
	}{
		{
			name:     "Single slice basic default path",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "02", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{testGnb1}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.DefaultUserPlanePath) == 0 {
					t.Error("expected default user plane path to be set")
				}
			},
		},
		{
			name:     "No AN nodes in config",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "002", "01", "2", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.AccessNetwork) != 0 {
					t.Error("expected no AN nodes")
				}
			},
		},
		{
			name:     "Multiple slices with overlapping gNBs",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{testGnb1, testGnb2}),
				makeTestSessionConfig("slice2", "001", "01", "1", "010102", "iot", "10.0.1.0/24", "10.1.1.2", []string{testGnb1}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if _, ok := upi.AccessNetwork[testGnb1]; !ok {
					t.Error("expected gnb1 to be in AccessNetwork")
				}
				if len(upi.UPFs) != 2 {
					t.Errorf("expected 2 UPFs, got %d", len(upi.UPFs))
				}
				// A UPF serving two gNBs must be linked to both. Asserting only
				// AccessNetwork membership left the link list unchecked, which
				// is why this case did not catch gNB names collapsing onto one
				// another when they failed to resolve.
				if got := len(upi.UPNodes["10.1.1.1"].Links); got != 2 {
					t.Errorf("len(UPNodes[10.1.1.1].Links) = %d, want 2", got)
				}
				if got := len(upi.UPNodes[testGnb1].Links); got != 2 {
					t.Errorf("len(UPNodes[gnb1].Links) = %d, want 2", got)
				}
			},
		},
		{
			name:     "DNNs are merged into the same SNSSAI entry",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{testGnb1}),
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "iot", "10.0.2.0/24", "10.1.1.1", []string{testGnb2}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.UPFs) != 1 {
					t.Errorf("expected 1 UPF, got %d", len(upi.UPFs))
				}
				if len(upi.UPFs["10.1.1.1"].UPF.SNssaiInfos[0].DnnList) != 2 {
					t.Errorf("expected 2 DNN entries for merged SNSSAI")
				}
			},
		},
		{
			name:     "Invalid UPF hostname",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "invalid_host*name", []string{testGnb1}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				upf := upi.UPFs["invalid_host*name"]
				if upf == nil || upf.NodeID.NodeIdType != NodeIdTypeFqdn {
					t.Error("expected UPF NodeIdType to be FQDN for invalid hostname")
				}
			},
		},
		{
			name: "Reusing existing UserPlaneInformation",
			existing: BuildUserPlaneInformationFromSessionManagement(nil, []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{testGnb1}),
			}),
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice2", "001", "01", "1", "010102", "iot", "10.0.1.0/24", "10.1.1.2", []string{testGnb2}),
			},
			// The configuration is the whole set of slices, so a UPF it no longer names is gone
			// from every map. UPFs used to keep it while UPNodes had dropped it.
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.UPFs) != 1 {
					t.Errorf("expected 1 UPF, got %d", len(upi.UPFs))
				}
				if _, ok := upi.UPFs["10.1.1.2"]; !ok {
					t.Error("the new UPF should exist")
				}
				if _, ok := upi.UPFs["10.1.1.1"]; ok {
					t.Error("the original UPF should be gone from UPFs")
				}
				if _, ok := upi.UPNodes["10.1.1.1"]; ok {
					t.Error("the original UPF should be gone from UPNodes")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upi := BuildUserPlaneInformationFromSessionManagement(tt.existing, tt.config)
			tt.assertions(t, upi)
		})
	}
}

// TestNodeInLinksDistinguishesUnresolvableFqdnNodes pins the behaviour that
// link membership is decided by node identity rather than by a resolved
// address.
//
// AN nodes carry the gNB name as an FQDN NodeID, and gNB names come from the
// slice's site-info as configuration labels — they are not hostnames and do not
// resolve. The previous implementation compared ResolveNodeIdToIp() strings, so
// every unresolvable name collapsed to "0.0.0.0" and any two of them compared
// equal: the second gNB was reported as already linked and its AN-UPF link was
// silently dropped. It also paid a full DNS timeout per comparison, delaying
// the SMF's PFCP association with the UPF.
func TestNodeInLinksDistinguishesUnresolvableFqdnNodes(t *testing.T) {
	fqdnNode := func(name string) *UPNode {
		return &UPNode{
			Type: UPNODE_AN,
			NodeID: NodeID{
				NodeIdType:  NodeIdTypeFqdn,
				NodeIdValue: []byte(name),
			},
		}
	}

	gnb1 := fqdnNode(testGnb1)
	gnb2 := fqdnNode(testGnb2)
	links := []*UPNode{gnb1}

	if !nodeInLinks(links, gnb1) {
		t.Error("nodeInLinks(links, gnb1) = false, want true: gnb1 is linked")
	}
	if nodeInLinks(links, gnb2) {
		t.Error("nodeInLinks(links, gnb2) = true, want false: distinct gNB names must not collapse onto one another")
	}

	// A separately constructed value for the same gNB is the same node.
	if !nodeInLinks(links, fqdnNode(testGnb1)) {
		t.Error("nodeInLinks(links, equal-valued gnb1) = false, want true: membership is NodeID equality, not pointer identity")
	}
}

// TestLinkUpfToGnbNodesLinksEveryGnb covers the user-visible consequence: a UPF
// configured with several gNBs must end up linked to all of them.
func TestLinkUpfToGnbNodesLinksEveryGnb(t *testing.T) {
	gnbNames := []string{testGnb1, testGnb2, "gnb3"}
	upi := &UserPlaneInformation{
		UPNodes:       make(map[string]*UPNode),
		AccessNetwork: make(map[string]*UPNode),
	}
	upf := &UPNode{Type: UPNODE_UPF, NodeID: NodeID{NodeIdType: NodeIdTypeFqdn, NodeIdValue: []byte("upf")}}
	upi.UPNodes["upf"] = upf
	for _, name := range gnbNames {
		n := &UPNode{Type: UPNODE_AN, NodeID: NodeID{NodeIdType: NodeIdTypeFqdn, NodeIdValue: []byte(name)}}
		upi.UPNodes[name] = n
		upi.AccessNetwork[name] = n
	}

	linkUpfToGnbNodes(upi, upf, gnbNames)

	if len(upf.Links) != len(gnbNames) {
		t.Errorf("len(upf.Links) = %d, want %d: every configured gNB must be linked", len(upf.Links), len(gnbNames))
	}
	// Compare the linked names directly rather than calling nodeInLinks, which
	// is the function under test: against the unfixed implementation every
	// unresolvable name compares equal, so using it as the oracle would report
	// success for any set of links.
	linked := make(map[string]bool, len(upf.Links))
	for _, l := range upf.Links {
		linked[string(l.NodeID.NodeIdValue)] = true
	}
	for _, name := range gnbNames {
		if !linked[name] {
			t.Errorf("gNB %s missing from upf.Links", name)
		}
	}
}

// defaultPathUPFs lists the UPF nodes the default paths go through.
func defaultPathUPFs(upi *UserPlaneInformation) map[*UPNode]bool {
	nodes := map[*UPNode]bool{}
	for _, path := range upi.DefaultUserPlanePath {
		for _, node := range path {
			if node.Type == UPNODE_UPF {
				nodes[node] = true
			}
		}
	}
	return nodes
}

// linksOnlyTo reports whether node links to want and nothing else.
func linksOnlyTo(node, want *UPNode) bool {
	return node != nil && want != nil && len(node.Links) == 1 && node.Links[0] == want
}

// A slice moved to another UPF (in the lab, BESS's "upf" to "upf-open5gs") must take the old UPF out
// of the SMF's selection. The maps were rebuilt before the old node was removed, so UPFs and the
// default paths kept it, and new PDU sessions were put on a UPF the configuration had dropped until
// the SMF restarted. Moving back must link the returning UPF to its gNB again.
func TestASliceChangeDropsTheUPFItNoLongerNames(t *testing.T) {
	const oldUPF, newUPF = "10.1.1.1", "10.1.1.2"
	slice := func(upf string) []nfConfigApi.SessionManagement {
		return []nfConfigApi.SessionManagement{
			makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", upf, []string{testGnb1}),
		}
	}

	upi := BuildUserPlaneInformationFromSessionManagement(nil, slice(oldUPF))
	upi = BuildUserPlaneInformationFromSessionManagement(upi, slice(newUPF))

	if _, ok := upi.UPFs[oldUPF]; ok || len(upi.UPFs) != 1 {
		t.Errorf("UPFs after the change: %v, want %s only", upi.UPFs, newUPF)
	}
	if _, ok := upi.UPNodes[oldUPF]; ok {
		t.Errorf("UPNodes still has %s", oldUPF)
	}
	if got := defaultPathUPFs(upi); len(got) != 1 || !got[upi.UPNodes[newUPF]] {
		t.Errorf("default paths go through %d UPFs, want %s only", len(got), newUPF)
	}
	if !linksOnlyTo(upi.UPNodes[testGnb1], upi.UPNodes[newUPF]) {
		t.Errorf("gnb1 has %d links, want one, to %s", len(upi.UPNodes[testGnb1].Links), newUPF)
	}

	// And back: the old UPF returns under its name, as a new node, and gnb1 has to link to that
	// node. A stale link to the removed one has the same NodeID, so it used to stop the new link.
	upi = BuildUserPlaneInformationFromSessionManagement(upi, slice(oldUPF))
	if !linksOnlyTo(upi.UPNodes[testGnb1], upi.UPNodes[oldUPF]) {
		t.Errorf("gnb1 has %d links after the move back, want one, to the %s in UPNodes",
			len(upi.UPNodes[testGnb1].Links), oldUPF)
	}
	if got := defaultPathUPFs(upi); len(got) != 1 || !got[upi.UPNodes[oldUPF]] {
		t.Errorf("default paths go through %d UPFs after the move back, want %s only", len(got), oldUPF)
	}
}

// A gNB the configuration no longer names leaves AccessNetwork and its UPF's links.
func TestAGnbChangeDropsTheGnbItNoLongerNames(t *testing.T) {
	const upf = "10.1.1.1"
	slice := func(gnb string) []nfConfigApi.SessionManagement {
		return []nfConfigApi.SessionManagement{
			makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", upf, []string{gnb}),
		}
	}

	upi := BuildUserPlaneInformationFromSessionManagement(nil, slice(testGnb1))
	upi = BuildUserPlaneInformationFromSessionManagement(upi, slice(testGnb2))

	if _, ok := upi.AccessNetwork[testGnb1]; ok {
		t.Errorf("AccessNetwork still has %s", testGnb1)
	}
	if _, ok := upi.UPNodes[testGnb1]; ok {
		t.Errorf("UPNodes still has %s", testGnb1)
	}
	if !linksOnlyTo(upi.UPNodes[upf], upi.UPNodes[testGnb2]) {
		t.Errorf("the UPF has %d links, want one, to %s", len(upi.UPNodes[upf].Links), testGnb2)
	}
}
