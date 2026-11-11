// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/json"
	"math"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const (
	raTestLocalSEID = 0x1234
	// raDefaultPDR is the key the datapath gives a tunnel's default PDR.
	raDefaultPDR = "default"
)

var (
	raTestSMFv4 = net.ParseIP("10.0.0.9").To4()
	raTestSMFv6 = net.ParseIP("fd00::9")
)

// raFixture is an IPv6 session with one data path: an access node whose uplink and downlink PDRs
// are allocated from its UPF, the uplink one asking for the tunnel's F-TEID, and a PFCP session on
// the UPF with local SEID raTestLocalSEID. The SMF's GTP-U endpoint runs at raTestSMFv4/raTestSMFv6.
func raFixture(t *testing.T) (*SMContext, *DataPathNode, *QER) {
	t.Helper()
	SetCPGtpuEndpoint(&CPGtpuAddrs{IPv4: raTestSMFv4, IPv6: raTestSMFv6})
	t.Cleanup(func() { SetCPGtpuEndpoint(nil) })

	upf := NewUPF(NewNodeID("10.0.0.3"), nil)
	upf.UPFStatus = AssociatedSetUpSuccess
	ul, err := upf.AddPDR()
	if err != nil {
		t.Fatal(err)
	}
	ul.Precedence = 255
	ul.PDI.LocalFTeid = &FTEID{V4: true, Ch: true, Chid: true, ChooseId: uplinkTunnelChooseId}
	dl, err := upf.AddPDR()
	if err != nil {
		t.Fatal(err)
	}
	dl.Precedence = 255
	qer, err := upf.AddQER()
	if err != nil {
		t.Fatal(err)
	}
	ul.QER, dl.QER = []*QER{qer}, []*QER{qer}

	node := &DataPathNode{
		UPF:            upf,
		UpLinkTunnel:   &GTPTunnel{PDR: map[string]*PDR{raDefaultPDR: ul}, TEID: 0x77},
		DownLinkTunnel: &GTPTunnel{PDR: map[string]*PDR{raDefaultPDR: dl}},
	}

	prefix := netip.MustParsePrefix(firstTestPrefix)
	iid := testIid
	smContext := NewSMContext(testSupi, 12)
	smContext.Dnn = testDnnName
	smContext.PDUAddress = &UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &iid}
	smContext.DNNInfo = &SnssaiSmfDnnInfo{MTU: 1400}
	smContext.PFCPContext[upf.NodeID.ResolveNodeIdToIp().String()] = &PFCPSessionContext{
		PDRs:      map[uint16]*PDR{ul.PDRID: ul, dl.PDRID: dl},
		NodeID:    upf.NodeID,
		LocalSEID: raTestLocalSEID,
	}
	smContext.Tunnel = &UPTunnel{DataPathPool: DataPathPool{1: {IsDefaultPath: true, Activated: true, FirstDPNode: node}}}
	return smContext, node, qer
}

// The UP2CP PDR takes router solicitations off the session's uplink F-TEID ahead of every other
// uplink PDR and sends them to the SMF over GTP-U with the session's TEID; the CP2UP PDR takes
// advertisements from the SMF on an F-TEID of its own to the UE with the downlink FAR.
func TestAnIPv6SessionGetsTheRouterAdvertisementRules(t *testing.T) {
	smContext, node, qer := raFixture(t)
	node.addRouterAdvertisementRules(smContext, qer)

	rules := node.RouterAdvertisement
	if rules == nil || rules.Solicitation == nil || rules.Advertisement == nil {
		t.Fatalf("rules %+v", rules)
	}
	ul, dl := node.UpLinkTunnel.PDR[raDefaultPDR], node.DownLinkTunnel.PDR[raDefaultPDR]

	rs := rules.Solicitation
	if rs.Precedence != 0 || rs.Precedence >= ul.Precedence {
		t.Errorf("UP2CP precedence %d, want 0, ahead of the uplink PDR's %d", rs.Precedence, ul.Precedence)
	}
	if rs.PDI.SourceInterface.InterfaceValue != SourceInterfaceAccess {
		t.Errorf("UP2CP source interface %d", rs.PDI.SourceInterface.InterfaceValue)
	}
	if f := rs.PDI.LocalFTeid; f == nil || f == ul.PDI.LocalFTeid || !reflect.DeepEqual(*f, *ul.PDI.LocalFTeid) {
		t.Errorf("UP2CP F-TEID %+v, want a copy of the uplink PDR's %+v", f, ul.PDI.LocalFTeid)
	}
	if rs.PDI.SDFFilter == nil || string(rs.PDI.SDFFilter.FlowDescription) != "permit out 58 from ff02::2/128 to assigned" ||
		!rs.PDI.SDFFilter.Fd || int(rs.PDI.SDFFilter.LengthOfFlowDescription) != len(RouterSolicitationFlowDescription) {
		t.Errorf("UP2CP SDF filter %+v", rs.PDI.SDFFilter)
	}
	if rs.PDI.UEIPAddress != nil || len(rs.QER) != 0 {
		t.Errorf("UP2CP has a UE IP address %+v or QERs %v", rs.PDI.UEIPAddress, rs.QER)
	}
	if rs.OuterHeaderRemoval == nil || rs.OuterHeaderRemoval.OuterHeaderRemovalDescription != OuterHeaderRemovalGtpUUdpIp {
		t.Errorf("UP2CP outer header removal %+v", rs.OuterHeaderRemoval)
	}
	if rs.FAR == nil || rs.FAR == ul.FAR || rs.FAR == dl.FAR || !rs.FAR.ApplyAction.Forw || rs.FAR.ForwardingParameters == nil {
		t.Fatalf("UP2CP FAR %+v", rs.FAR)
	}
	fp := rs.FAR.ForwardingParameters
	if fp.DestinationInterface.InterfaceValue != DestinationInterfaceCPFunction || string(fp.NetworkInstance) != testDnnName {
		t.Errorf("UP2CP forwarding %+v", fp)
	}
	ohc := fp.OuterHeaderCreation
	if ohc == nil || ohc.OuterHeaderCreationDescription != OuterHeaderCreationGtpUUdpIpv4|OuterHeaderCreationGtpUUdpIpv6 ||
		ohc.Teid != raTestLocalSEID || !ohc.Ipv4Address.Equal(raTestSMFv4) || !ohc.Ipv6Address.Equal(raTestSMFv6) {
		t.Errorf("UP2CP outer header creation %+v", ohc)
	}

	ra := rules.Advertisement
	if ra.Precedence != 0 || ra.PDI.SourceInterface.InterfaceValue != SourceInterfaceCPFunction {
		t.Errorf("CP2UP precedence %d, source interface %d", ra.Precedence, ra.PDI.SourceInterface.InterfaceValue)
	}
	if f := ra.PDI.LocalFTeid; f == nil || !f.Ch || f.Chid || !f.V4 || !f.V6 || f.Teid != 0 {
		t.Errorf("CP2UP F-TEID %+v, want CHOOSE without a CHOOSE ID, in both families", f)
	}
	if ra.FAR != dl.FAR {
		t.Errorf("CP2UP FAR %+v, want the downlink PDR's %+v", ra.FAR, dl.FAR)
	}
	if len(ra.QER) != 1 || ra.QER[0] != qer {
		t.Errorf("CP2UP QERs %v, want the session QER", ra.QER)
	}
	if ra.OuterHeaderRemoval == nil || ra.OuterHeaderRemoval.OuterHeaderRemovalDescription != OuterHeaderRemovalGtpUUdpIp {
		t.Errorf("CP2UP outer header removal %+v", ra.OuterHeaderRemoval)
	}

	ids := map[uint16]bool{ul.PDRID: true, dl.PDRID: true}
	for _, pdr := range []*PDR{rs, ra} {
		if ids[pdr.PDRID] {
			t.Errorf("PDR ID %d reused", pdr.PDRID)
		}
		ids[pdr.PDRID] = true
	}
	session := smContext.PFCPContext["10.0.0.3"]
	if session.PDRs[rs.PDRID] != rs || session.PDRs[ra.PDRID] != ra {
		t.Errorf("the rules are not in the PFCP session: %v", session.PDRs)
	}

	pdrs, fars := node.RouterAdvertisementPDRs()
	if len(pdrs) != 2 || pdrs[0] != rs || pdrs[1] != ra || len(fars) != 1 || fars[0] != rs.FAR {
		t.Errorf("RouterAdvertisementPDRs = %v, %v", pdrs, fars)
	}

	// Once is enough.
	node.addRouterAdvertisementRules(smContext, qer)
	if node.RouterAdvertisement != rules {
		t.Error("a second call replaced the rules")
	}
}

// An endpoint in one family gives an outer header creation and a CP2UP F-TEID in that family only.
func TestTheRouterAdvertisementRulesFollowTheEndpointsFamilies(t *testing.T) {
	smContext, node, qer := raFixture(t)
	SetCPGtpuEndpoint(&CPGtpuAddrs{IPv6: raTestSMFv6})
	node.addRouterAdvertisementRules(smContext, qer)

	ohc := node.RouterAdvertisement.Solicitation.FAR.ForwardingParameters.OuterHeaderCreation
	if ohc.OuterHeaderCreationDescription != OuterHeaderCreationGtpUUdpIpv6 || ohc.Ipv4Address != nil {
		t.Errorf("outer header creation %+v", ohc)
	}
	if f := node.RouterAdvertisement.Advertisement.PDI.LocalFTeid; f.V4 || !f.V6 {
		t.Errorf("CP2UP F-TEID %+v", f)
	}
}

// Without IPv6, or without the endpoint, a session's rules are what they were.
func TestNoRouterAdvertisementRulesWithoutIPv6OrAnEndpoint(t *testing.T) {
	smContext, node, qer := raFixture(t)
	before, _ := countAllocated(node.UPF)

	SetCPGtpuEndpoint(nil)
	node.addRouterAdvertisementRules(smContext, qer)
	if node.RouterAdvertisement != nil {
		t.Error("rules without an endpoint")
	}

	SetCPGtpuEndpoint(&CPGtpuAddrs{IPv4: raTestSMFv4})
	smContext.PDUAddress = &UeIpAddr{Ip: net.ParseIP("10.1.0.1").To4()}
	node.addRouterAdvertisementRules(smContext, qer)
	if node.RouterAdvertisement != nil {
		t.Error("rules for an IPv4 session")
	}

	if after, _ := countAllocated(node.UPF); after != before {
		t.Errorf("%d PDRs allocated, want %d", after, before)
	}
}

// A session without the rules does not go without its IPv4 service: a rule that cannot be built
// is logged, and nothing it allocated is kept.
func TestRouterAdvertisementRulesThatCannotBeBuiltLeaveNothingBehind(t *testing.T) {
	for name, breakIt := range map[string]func(*SMContext, *DataPathNode){
		"no PFCP session":    func(s *SMContext, _ *DataPathNode) { delete(s.PFCPContext, "10.0.0.3") },
		"SEID beyond 32 bit": func(s *SMContext, _ *DataPathNode) { s.PFCPContext["10.0.0.3"].LocalSEID = math.MaxUint32 + 1 },
		"no uplink F-TEID":   func(_ *SMContext, n *DataPathNode) { n.UpLinkTunnel.PDR[raDefaultPDR].PDI.LocalFTeid = nil },
		"no downlink FAR":    func(_ *SMContext, n *DataPathNode) { n.DownLinkTunnel.PDR = map[string]*PDR{} },
	} {
		t.Run(name, func(t *testing.T) {
			smContext, node, qer := raFixture(t)
			breakIt(smContext, node)
			pdrs, fars := countAllocated(node.UPF)
			node.addRouterAdvertisementRules(smContext, qer)
			if node.RouterAdvertisement != nil {
				t.Fatal("rules were built")
			}
			if p, f := countAllocated(node.UPF); p != pdrs || f != fars {
				t.Errorf("%d PDRs and %d FARs allocated, want %d and %d", p, f, pdrs, fars)
			}
		})
	}
}

// Removing the rules takes them out of the PFCP session and gives their identifiers back, except
// the CP2UP PDR's FAR, which is the downlink PDR's.
func TestRemovingTheRouterAdvertisementRulesFreesWhatTheyAllocated(t *testing.T) {
	smContext, node, qer := raFixture(t)
	pdrs, fars := countAllocated(node.UPF)
	node.addRouterAdvertisementRules(smContext, qer)
	rules := node.RouterAdvertisement

	node.removeRouterAdvertisementRules(smContext)
	if node.RouterAdvertisement != nil {
		t.Error("the rules are still on the node")
	}
	session := smContext.PFCPContext["10.0.0.3"]
	if _, ok := session.PDRs[rules.Solicitation.PDRID]; ok {
		t.Error("the UP2CP PDR is still in the PFCP session")
	}
	if _, ok := session.PDRs[rules.Advertisement.PDRID]; ok {
		t.Error("the CP2UP PDR is still in the PFCP session")
	}
	if p, f := countAllocated(node.UPF); p != pdrs || f != fars {
		t.Errorf("%d PDRs and %d FARs allocated after removal, want %d and %d", p, f, pdrs, fars)
	}
	dl := node.DownLinkTunnel.PDR[raDefaultPDR].FAR
	if _, ok := node.UPF.farPool.Load(dl.FARID); !ok {
		t.Error("the downlink FAR was freed with the CP2UP PDR")
	}
}

func TestRouterAdvertisementTEIDIsTheLocalSEID(t *testing.T) {
	for seid, want := range map[uint64]bool{0: false, 1: true, math.MaxUint32: true, math.MaxUint32 + 1: false} {
		teid, ok := RouterAdvertisementTEID(seid)
		if ok != want || (ok && uint64(teid) != seid) {
			t.Errorf("RouterAdvertisementTEID(%#x) = %#x, %t", seid, teid, ok)
		}
	}
}

// Router advertisements take the downlink FAR of the default PDR, or without one that of the
// catch-all, chosen the same way whatever the map order.
func TestRouterAdvertisementsTakeTheDefaultOrTheCatchAllDownlinkFAR(t *testing.T) {
	def := &PDR{PDRID: 9, Precedence: 255, FAR: &FAR{}}
	low := &PDR{PDRID: 3, Precedence: 10, FAR: &FAR{}}
	high := &PDR{PDRID: 5, Precedence: 200, FAR: &FAR{}}
	tie := &PDR{PDRID: 4, Precedence: 200, FAR: &FAR{}}
	if got := routerAdvertisementDownlinkPDR(&GTPTunnel{PDR: map[string]*PDR{raDefaultPDR: def, "a": high}}); got != def {
		t.Errorf("with a default PDR: %+v", got)
	}
	for range 20 {
		if got := routerAdvertisementDownlinkPDR(&GTPTunnel{PDR: map[string]*PDR{"a": low, "b": high, "c": tie, "d": {PDRID: 1}}}); got != tie {
			t.Fatalf("without one: %+v", got)
		}
	}
	if routerAdvertisementDownlinkPDR(nil) != nil || routerAdvertisementDownlinkPDR(&GTPTunnel{}) != nil {
		t.Error("a PDR from no tunnel")
	}
}

// The UPF's choice of CP2UP F-TEID is recorded from the Created PDR naming the CP2UP PDR on that
// UPF, and only from that one; it then gives the path router advertisements take.
func TestTheCP2UPFTEIDGivesTheRouterAdvertisementPath(t *testing.T) {
	smContext, node, qer := raFixture(t)
	if _, err := smContext.RouterAdvertisementPath(nil); err == nil || !strings.Contains(err.Error(), "no router advertisement rules") {
		t.Errorf("path without rules: %v", err)
	}
	node.addRouterAdvertisementRules(smContext, qer)
	ra := node.RouterAdvertisement.Advertisement
	if _, err := smContext.RouterAdvertisementPath(nil); err == nil || !strings.Contains(err.Error(), "not given the CP2UP F-TEID") {
		t.Errorf("path before the F-TEID: %v", err)
	}

	upfV4, upfV6 := net.ParseIP("10.0.0.3").To4(), net.ParseIP("fd00::3")
	if smContext.RecordRouterAdvertisementFTEID(node.UPF.NodeID, ra.PDRID+100, 0x99, upfV4, upfV6, true) {
		t.Error("recorded for another PDR")
	}
	if smContext.RecordRouterAdvertisementFTEID(*NewNodeID("10.0.0.4"), ra.PDRID, 0x99, upfV4, upfV6, true) {
		t.Error("recorded for another UPF")
	}
	if !smContext.RecordRouterAdvertisementFTEID(node.UPF.NodeID, ra.PDRID, 0, nil, nil, false) {
		t.Error("a CP2UP Created PDR without an F-TEID was not claimed")
	}
	if ra.PDI.LocalFTeid.Teid != 0 {
		t.Error("an absent F-TEID was recorded")
	}
	if !smContext.RecordRouterAdvertisementFTEID(node.UPF.NodeID, ra.PDRID, 0x99, upfV4, upfV6, true) {
		t.Fatal("the CP2UP F-TEID was not recorded")
	}
	if f := ra.PDI.LocalFTeid; f.Teid != 0x99 || !f.Ipv4Address.Equal(upfV4) || !f.Ipv6Address.Equal(upfV6) || !f.Ch {
		t.Errorf("CP2UP F-TEID %+v", f)
	}

	path, err := smContext.RouterAdvertisementPath(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := RouterAdvertisementPath{
		UPF:      netip.MustParseAddr("10.0.0.3"),
		UPFTEID:  0x99,
		SMFTEID:  raTestLocalSEID,
		Prefix:   netip.MustParsePrefix(firstTestPrefix),
		Iid:      testIid,
		LinkMTU:  1400,
		Rules:    node.RouterAdvertisement,
		NodeName: "10.0.0.3",
	}
	if !reflect.DeepEqual(*path, want) {
		t.Errorf("path %+v, want %+v", *path, want)
	}

	SetCPGtpuEndpoint(&CPGtpuAddrs{IPv4: raTestSMFv4, IPv6: raTestSMFv6, PreferIPv6: true})
	if path, err := smContext.RouterAdvertisementPath(nil); err != nil || path.UPF != netip.MustParseAddr("fd00::3") {
		t.Errorf("preferring IPv6: %+v, %v", path, err)
	}
	SetCPGtpuEndpoint(&CPGtpuAddrs{IPv4: raTestSMFv4, IPv6: raTestSMFv6})
	onlyV6 := func(a netip.Addr) bool { return a.Is6() }
	if path, err := smContext.RouterAdvertisementPath(onlyV6); err != nil || path.UPF != netip.MustParseAddr("fd00::3") {
		t.Errorf("with an IPv6 socket only: %+v, %v", path, err)
	}
	if _, err := smContext.RouterAdvertisementPath(func(netip.Addr) bool { return false }); err == nil {
		t.Error("a path with no socket to send from")
	}
}

// A stored session keeps its router advertisement rules, and its CP2UP PDR forwards with the
// downlink PDR's FAR again once restored, not with a second FAR of the same identifier. A node
// without them is stored as before.
func TestStoredRouterAdvertisementRulesForwardWithTheDownlinkFAR(t *testing.T) {
	smContext, node, qer := raFixture(t)

	plain, err := json.Marshal(DataPathNodeInDB{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "RouterAdvertisement") {
		t.Errorf("a node without the rules is stored with them: %s", plain)
	}

	node.addRouterAdvertisementRules(smContext, qer)
	stored, err := json.Marshal(DataPathNodeInDB{RouterAdvertisement: node.RouterAdvertisement})
	if err != nil {
		t.Fatal(err)
	}
	var back DataPathNodeInDB
	if err := json.Unmarshal(stored, &back); err != nil {
		t.Fatal(err)
	}
	restored := &DataPathNode{DownLinkTunnel: node.DownLinkTunnel, RouterAdvertisement: back.RouterAdvertisement}
	if restored.RouterAdvertisement.Advertisement.FAR == node.DownLinkTunnel.PDR[raDefaultPDR].FAR {
		t.Fatal("decoding shared the FAR already; the test proves nothing")
	}
	restored.relinkRouterAdvertisementFAR()
	if restored.RouterAdvertisement.Advertisement.FAR != node.DownLinkTunnel.PDR[raDefaultPDR].FAR {
		t.Error("the restored CP2UP PDR has a FAR of its own")
	}
	if got := restored.RouterAdvertisement.Solicitation.FAR.ForwardingParameters.OuterHeaderCreation.Teid; got != raTestLocalSEID {
		t.Errorf("restored UP2CP TEID %#x", got)
	}
}
