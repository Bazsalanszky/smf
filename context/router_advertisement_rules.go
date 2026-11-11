// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/smf/logger"
)

// The CP-function interface values (TS 29.244 clauses 8.2.2 and 8.2.24), and the outer header
// removal that covers GTP-U over either family (clause 8.2.64).
const (
	SourceInterfaceCPFunction      uint8 = 3
	DestinationInterfaceCPFunction uint8 = 3

	OuterHeaderRemovalGtpUUdpIp    uint8  = 6
	OuterHeaderCreationGtpUUdpIpv6 uint16 = 0x0200
)

// RouterSolicitationFlowDescription matches the router solicitations of a session: ICMPv6 to the
// all-routers group. It is written as a PCC flow description, from the remote side to the UE; on a
// PDR with Source Interface Access the UPF reads it with source and destination swapped (TS 29.244
// clause 5.2.1A.2A), so it matches next header 58 to ff02::2. It is exactly what the Open5GS SMF
// sends, the form the Open5GS UPF's filter parser accepts. The ICMPv6 type is checked by the SMF.
const RouterSolicitationFlowDescription = "permit out 58 from ff02::2/128 to assigned"

// RouterAdvertisementPrecedence is the precedence of both router advertisement PDRs. The UP2CP PDR
// shares the uplink F-TEID with every uplink PDR of the session, and a UPF tries those in precedence
// order: it has to come first, or the default uplink PDR (precedence 255) or a PCC rule's (1 and
// up) takes the solicitation to the data network. 0 is the highest precedence and is never given to
// a PCC rule's PDR (BuildCreatePdrFromPccRule), so it cannot tie with one. The filter only matches
// link-local multicast, which is never routed, so it takes nothing from any other rule.
const RouterAdvertisementPrecedence uint32 = 0

// CPGtpuAddrs is the SMF's own GTP-U endpoint as advertised to UPFs: its address in each family it
// has one in.
type CPGtpuAddrs struct {
	IPv4 net.IP
	IPv6 net.IP
	// PreferIPv6 picks the family the SMF sends router advertisements in when the UPF gave an address
	// in both.
	PreferIPv6 bool
}

var cpGtpuEndpoint atomic.Pointer[CPGtpuAddrs]

// SetCPGtpuEndpoint records the SMF's running GTP-U endpoint, or with nil that none runs. Sessions
// established while one runs get the router advertisement rules; others do not.
func SetCPGtpuEndpoint(addrs *CPGtpuAddrs) {
	cpGtpuEndpoint.Store(addrs)
}

// CPGtpuEndpoint returns the SMF's running GTP-U endpoint, nil when none runs.
func CPGtpuEndpoint() *CPGtpuAddrs {
	return cpGtpuEndpoint.Load()
}

// RouterAdvertisementRules are the two rules that give the SMF the router solicitations of an IPv6
// session and carry its router advertisements back (TS 29.244 clause 5.3, TS 23.501 clause
// 5.8.2.2.2). They sit on the access node of the default path: the UPF the RAN's tunnel ends at.
// Kept apart from the tunnels' PDR maps, whose every member the uplink and downlink code treats as
// an ordinary uplink or downlink rule.
type RouterAdvertisementRules struct {
	// Solicitation is the UP2CP PDR: Source Interface Access, on the session's uplink F-TEID (one
	// CHOOSE ID with the uplink PDRs), the router solicitation filter, and its own FAR forwarding to
	// the CP function over GTP-U, to the SMF's endpoint with TEID RouterAdvertisementTEID.
	Solicitation *PDR
	// Advertisement is the CP2UP PDR: Source Interface CP-function, with an F-TEID of its own that
	// the UPF chooses, which the SMF sends router advertisements to. It forwards with a downlink FAR
	// of the session, the same FAR, so every change to the access tunnel (setup, idle, service
	// request, handover) applies to router advertisements without a rule of their own to update. It
	// carries the session QER, so the advertisement reaches the RAN on the default QoS flow.
	//
	// Once the UPF has answered, LocalFTeid also holds the TEID and addresses it chose. The CHOOSE
	// flag stays set, so a re-establishment on a restarted UPF asks for a new one.
	Advertisement *PDR
}

// ForwardsToAccess reports whether the CP2UP PDR's FAR, the session's downlink FAR, forwards to the
// access tunnel. Until the UPF has the AN's F-TEID from the PDU Session Resource Setup Response that
// FAR drops (or buffers, after an AN release), so an advertisement sent to the CP2UP F-TEID cannot
// reach the UE. A UE can still solicit in that window: its uplink works as soon as it has the setup
// request, before the SMF has sent the UPF the access tunnel. Open5GS then buffers the advertisement
// and sends a Downlink Data Report, which the SMF rejects. The update that installs the access
// tunnel sets this FAR and sends the unsolicited advertisement under the session's lock, so a
// solicitation answered under that lock sees either the old FAR or one the UPF has accepted.
func (rules *RouterAdvertisementRules) ForwardsToAccess() bool {
	if rules == nil || rules.Advertisement == nil || rules.Advertisement.FAR == nil {
		return false
	}
	far := rules.Advertisement.FAR
	return far.ApplyAction.Forw && far.ForwardingParameters != nil && far.ForwardingParameters.OuterHeaderCreation != nil
}

// RouterAdvertisementTEID is the TEID the UPF sends a session's router solicitations to the SMF
// with: the session's local SEID on that UPF. A local SEID is unique within the SMF (and across SMF
// instances when the SEID pool is shared), survives a restart in the stored session, and finds the
// session through GetSMContextBySEID. Allocated SEIDs fit in 32 bits: the shared pool hands out
// 32-bit identifiers, and the local counter would have to pass 2^32 sessions first.
func RouterAdvertisementTEID(localSEID uint64) (uint32, bool) {
	if localSEID == 0 || localSEID > math.MaxUint32 {
		return 0, false
	}
	return uint32(localSEID), true
}

// addPDRSharingFAR allocates a PDR that forwards with an existing FAR, which stays the other PDR's.
func (upf *UPF) addPDRSharingFAR(far *FAR) (*PDR, error) {
	id, err := upf.pdrID()
	if err != nil {
		return nil, err
	}
	pdr := &PDR{PDRID: id, FAR: far}
	upf.pdrPool.Store(id, pdr)
	return pdr, nil
}

// routerAdvertisementDownlinkPDR picks the downlink PDR whose FAR router advertisements take: the
// default one, or without one the PCC rule matched last (highest precedence value, the catch-all),
// lowest PDR ID on a tie so the choice does not follow map order.
func routerAdvertisementDownlinkPDR(tunnel *GTPTunnel) *PDR {
	if tunnel == nil {
		return nil
	}
	if pdr := tunnel.PDR["default"]; pdr != nil && pdr.FAR != nil {
		return pdr
	}
	var chosen *PDR
	for _, pdr := range tunnel.PDR {
		if pdr == nil || pdr.FAR == nil {
			continue
		}
		if chosen == nil || pdr.Precedence > chosen.Precedence ||
			(pdr.Precedence == chosen.Precedence && pdr.PDRID < chosen.PDRID) {
			chosen = pdr
		}
	}
	return chosen
}

// addRouterAdvertisementRules installs the router advertisement rules on node, the access node of
// the default path, for a session with IPv6 while the SMF's GTP-U endpoint runs. sessQER is the
// session QER the node's PDRs carry. Without IPv6 or without an endpoint nothing is added, so an
// IPv4 session's rules are what they always were. A failure is logged and the session goes on
// without router advertisements: an IPv4v6 session keeps its IPv4 service, and an IPv6 one can be
// configured by hand from the prefix and identifier.
func (node *DataPathNode) addRouterAdvertisementRules(smContext *SMContext, sessQER *QER) {
	endpoint := CPGtpuEndpoint()
	if node.RouterAdvertisement != nil || endpoint == nil || !smContext.PDUAddress.HasIpv6() || node.UPF == nil {
		return
	}
	if err := node.buildRouterAdvertisementRules(smContext, sessQER, endpoint); err != nil {
		smContext.SubPduSessLog.Warnf("no router advertisement for UE [%s] on UPF [%s]: %v",
			smContext.Supi, node.GetNodeIP(), err)
	}
}

func (node *DataPathNode) buildRouterAdvertisementRules(smContext *SMContext, sessQER *QER, endpoint *CPGtpuAddrs) error {
	key, ok := smContext.PFCPContextKeyForNode(node.UPF.NodeID)
	if !ok {
		return fmt.Errorf("no PFCP session")
	}
	rxTEID, ok := RouterAdvertisementTEID(smContext.PFCPContext[key].LocalSEID)
	if !ok {
		return fmt.Errorf("local SEID %d gives no TEID", smContext.PFCPContext[key].LocalSEID)
	}
	var uplinkFTEID *FTEID
	for _, pdr := range node.UpLinkTunnel.PDR {
		if pdr != nil && pdr.PDI.LocalFTeid != nil {
			uplinkFTEID = pdr.PDI.LocalFTeid
			break
		}
	}
	if uplinkFTEID == nil {
		return fmt.Errorf("no uplink F-TEID")
	}
	downlink := routerAdvertisementDownlinkPDR(node.DownLinkTunnel)
	if downlink == nil {
		return fmt.Errorf("no downlink FAR")
	}

	ohc := &OuterHeaderCreation{Teid: rxTEID}
	if endpoint.IPv4 != nil {
		ohc.OuterHeaderCreationDescription |= OuterHeaderCreationGtpUUdpIpv4
		ohc.Ipv4Address = endpoint.IPv4
	}
	if endpoint.IPv6 != nil {
		ohc.OuterHeaderCreationDescription |= OuterHeaderCreationGtpUUdpIpv6
		ohc.Ipv6Address = endpoint.IPv6
	}
	if ohc.OuterHeaderCreationDescription == 0 {
		return fmt.Errorf("the GTP-U endpoint has no address")
	}

	solicitation, err := node.UPF.AddPDR()
	if err != nil {
		return fmt.Errorf("UP2CP PDR: %w", err)
	}
	advertisement, err := node.UPF.addPDRSharingFAR(downlink.FAR)
	if err != nil {
		node.freeRouterAdvertisementPDR(solicitation, true)
		return fmt.Errorf("CP2UP PDR: %w", err)
	}

	sharedFTEID := *uplinkFTEID
	solicitation.Precedence = RouterAdvertisementPrecedence
	solicitation.PDI = PDI{
		SourceInterface: SourceInterface{InterfaceValue: SourceInterfaceAccess},
		LocalFTeid:      &sharedFTEID,
		NetworkInstance: nasType.Dnn(smContext.Dnn),
		SDFFilter: &SDFFilter{
			Fd:                      true,
			FlowDescription:         []byte(RouterSolicitationFlowDescription),
			LengthOfFlowDescription: uint16(len(RouterSolicitationFlowDescription)),
		},
	}
	solicitation.OuterHeaderRemoval = &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIp}
	// No QER: with one, the UPF adds a PDU Session Container towards the SMF and counts the
	// solicitation against the session's rates; the Open5GS SMF leaves it out too.
	solicitation.FAR.ApplyAction = ApplyAction{Forw: true}
	solicitation.FAR.ForwardingParameters = &ForwardingParameters{
		DestinationInterface: DestinationInterface{InterfaceValue: DestinationInterfaceCPFunction},
		NetworkInstance:      []byte(smContext.Dnn),
		OuterHeaderCreation:  ohc,
	}

	advertisement.Precedence = RouterAdvertisementPrecedence
	advertisement.PDI = PDI{
		SourceInterface: SourceInterface{InterfaceValue: SourceInterfaceCPFunction},
		// A TEID of its own (CHOOSE without a CHOOSE ID), in each family the SMF can send from.
		LocalFTeid:      &FTEID{V4: endpoint.IPv4 != nil, V6: endpoint.IPv6 != nil, Ch: true},
		NetworkInstance: nasType.Dnn(smContext.Dnn),
	}
	advertisement.OuterHeaderRemoval = &OuterHeaderRemoval{OuterHeaderRemovalDescription: OuterHeaderRemovalGtpUUdpIp}
	if sessQER != nil {
		advertisement.QER = []*QER{sessQER}
	}

	node.RouterAdvertisement = &RouterAdvertisementRules{Solicitation: solicitation, Advertisement: advertisement}
	if err := smContext.PutPDRtoPFCPSession(node.UPF.NodeID, map[string]*PDR{
		"router solicitation": solicitation, "router advertisement": advertisement,
	}); err != nil {
		node.removeRouterAdvertisementRules(smContext)
		return err
	}
	logger.CtxLog.Infof("router advertisement rules for UE [%s]: UP2CP PDR %d (FAR %d, TEID %#x to %v/%v), CP2UP PDR %d on FAR %d",
		smContext.Supi, solicitation.PDRID, solicitation.FAR.FARID, rxTEID, endpoint.IPv4, endpoint.IPv6,
		advertisement.PDRID, advertisement.FAR.FARID)
	return nil
}

// freeRouterAdvertisementPDR returns a router advertisement PDR's identifier, and with ownFAR its
// FAR's, to the UPF's pools.
func (node *DataPathNode) freeRouterAdvertisementPDR(pdr *PDR, ownFAR bool) {
	if pdr == nil || node.UPF == nil {
		return
	}
	if err := node.UPF.RemovePDR(pdr); err != nil {
		logger.CtxLog.Warnf("router advertisement PDR %d: %v", pdr.PDRID, err)
	}
	if ownFAR && pdr.FAR != nil {
		if err := node.UPF.RemoveFAR(pdr.FAR); err != nil {
			logger.CtxLog.Warnf("router advertisement FAR %d: %v", pdr.FAR.FARID, err)
		}
	}
}

// removeRouterAdvertisementRules takes the router advertisement rules off node, as the tunnels'
// deactivation does with theirs: the PDRs leave the PFCP session, and their identifiers go back to
// the UPF's pools unless an earlier incarnation allocated them. The CP2UP PDR's FAR and QER are the
// downlink PDR's and the session's, freed with those.
func (node *DataPathNode) removeRouterAdvertisementRules(smContext *SMContext) {
	rules := node.RouterAdvertisement
	if rules == nil {
		return
	}
	node.RouterAdvertisement = nil
	if node.UPF == nil {
		return
	}
	for _, pdr := range []*PDR{rules.Solicitation, rules.Advertisement} {
		if pdr != nil {
			smContext.RemovePDRfromPFCPSession(node.UPF.NodeID, pdr)
		}
	}
	if smContext.restoredFromStore {
		return
	}
	node.freeRouterAdvertisementPDR(rules.Solicitation, true)
	node.freeRouterAdvertisementPDR(rules.Advertisement, false)
}

// relinkRouterAdvertisementFAR makes a restored CP2UP PDR forward with the downlink PDR's FAR again,
// not with the copy the stored session decoded for it: the session would otherwise hold two FARs
// with one identifier, and send both.
func (node *DataPathNode) relinkRouterAdvertisementFAR() {
	if node == nil || node.RouterAdvertisement == nil || node.RouterAdvertisement.Advertisement == nil ||
		node.DownLinkTunnel == nil {
		return
	}
	advertisement := node.RouterAdvertisement.Advertisement
	if advertisement.FAR == nil {
		return
	}
	for _, pdr := range node.DownLinkTunnel.PDR {
		if pdr != nil && pdr.FAR != nil && pdr.FAR.FARID == advertisement.FAR.FARID {
			advertisement.FAR = pdr.FAR
			return
		}
	}
}

// RouterAdvertisementRulesOf returns the router advertisement rules of the session's data paths, by
// node; each is on the access node of the default path, so there is at most one.
func (pool DataPathPool) RouterAdvertisementRulesOf() map[*DataPathNode]*RouterAdvertisementRules {
	out := map[*DataPathNode]*RouterAdvertisementRules{}
	for _, path := range pool {
		if path == nil {
			continue
		}
		for node := path.FirstDPNode; node != nil; node = node.Next() {
			if node.RouterAdvertisement != nil {
				out[node] = node.RouterAdvertisement
			}
		}
	}
	return out
}

// RouterAdvertisementPDRs returns the router advertisement PDRs on node, and the UP2CP PDR's FAR
// (the only FAR of their own), for the PFCP requests that carry a node's whole rule set.
func (node *DataPathNode) RouterAdvertisementPDRs() ([]*PDR, []*FAR) {
	if node == nil || node.RouterAdvertisement == nil {
		return nil, nil
	}
	var pdrs []*PDR
	var fars []*FAR
	if pdr := node.RouterAdvertisement.Solicitation; pdr != nil {
		pdrs = append(pdrs, pdr)
		if pdr.FAR != nil {
			fars = append(fars, pdr.FAR)
		}
	}
	if pdr := node.RouterAdvertisement.Advertisement; pdr != nil {
		pdrs = append(pdrs, pdr)
	}
	return pdrs, fars
}

// RecordRouterAdvertisementFTEID stores the F-TEID the UPF identified by nodeID chose for pdrID, if
// that is the session's CP2UP PDR on it, and reports whether it was. A Created PDR it reports is not
// one of the uplink tunnel's: its F-TEID is not the one the RAN is told. haveFTEID is false when the
// Created PDR carried none.
func (smContext *SMContext) RecordRouterAdvertisementFTEID(nodeID NodeID, pdrID uint16, teid uint32, ipv4, ipv6 net.IP, haveFTEID bool) bool {
	if smContext.Tunnel == nil {
		return false
	}
	for node, rules := range smContext.Tunnel.DataPathPool.RouterAdvertisementRulesOf() {
		advertisement := rules.Advertisement
		if advertisement == nil || advertisement.PDRID != pdrID || node.UPF == nil || !node.UPF.NodeID.Equal(nodeID) {
			continue
		}
		if !haveFTEID {
			smContext.SubPfcpLog.Warnf("UPF [%s] created CP2UP PDR %d without an F-TEID: no router advertisement can be sent",
				node.GetNodeIP(), pdrID)
			return true
		}
		if advertisement.PDI.LocalFTeid == nil {
			advertisement.PDI.LocalFTeid = &FTEID{Ch: true}
		}
		advertisement.PDI.LocalFTeid.Teid = teid
		advertisement.PDI.LocalFTeid.Ipv4Address = ipv4
		advertisement.PDI.LocalFTeid.Ipv6Address = ipv6
		smContext.SubPfcpLog.Infof("router advertisements for UE [%s] go to TEID %#x at %v/%v", smContext.Supi, teid, ipv4, ipv6)
		return true
	}
	return false
}

// RouterAdvertisementPath is where the SMF sends a session's router advertisements, and the TEID
// its solicitations arrive with.
type RouterAdvertisementPath struct {
	UPF      netip.Addr
	UPFTEID  uint32
	SMFTEID  uint32
	Prefix   netip.Prefix
	Iid      InterfaceIdentifier
	LinkMTU  uint16
	Rules    *RouterAdvertisementRules
	NodeName string
}

// RouterAdvertisementPath returns the session's router advertisement path, or an error saying why it
// has none (no IPv6, no rules, or no F-TEID from the UPF yet). canSend reports whether the SMF's
// endpoint has a socket of an address's family; of the F-TEID's addresses the first it can send to
// is used, the preferred family first.
func (smContext *SMContext) RouterAdvertisementPath(canSend func(netip.Addr) bool) (*RouterAdvertisementPath, error) {
	if !smContext.PDUAddress.HasIpv6() {
		return nil, fmt.Errorf("the session has no IPv6 prefix")
	}
	if smContext.Tunnel == nil {
		return nil, fmt.Errorf("the session has no user plane")
	}
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode == nil || defaultPath.FirstDPNode.RouterAdvertisement == nil {
		return nil, fmt.Errorf("the session has no router advertisement rules")
	}
	node := defaultPath.FirstDPNode
	rules := node.RouterAdvertisement
	if rules.Advertisement == nil || rules.Advertisement.PDI.LocalFTeid == nil || rules.Advertisement.PDI.LocalFTeid.Teid == 0 {
		return nil, fmt.Errorf("the UPF has not given the CP2UP F-TEID yet")
	}
	fteid := rules.Advertisement.PDI.LocalFTeid
	var smfTEID uint32
	if rules.Solicitation != nil && rules.Solicitation.FAR != nil && rules.Solicitation.FAR.ForwardingParameters != nil &&
		rules.Solicitation.FAR.ForwardingParameters.OuterHeaderCreation != nil {
		smfTEID = rules.Solicitation.FAR.ForwardingParameters.OuterHeaderCreation.Teid
	}

	var candidates []netip.Addr
	v4, ok4 := netip.AddrFromSlice(fteid.Ipv4Address.To4())
	v6, ok6 := netip.AddrFromSlice(fteid.Ipv6Address.To16())
	ok6 = ok6 && fteid.Ipv6Address.To4() == nil
	preferV6 := false
	if endpoint := CPGtpuEndpoint(); endpoint != nil {
		preferV6 = endpoint.PreferIPv6
	}
	if preferV6 {
		if ok6 {
			candidates = append(candidates, v6)
		}
		if ok4 {
			candidates = append(candidates, v4)
		}
	} else {
		if ok4 {
			candidates = append(candidates, v4)
		}
		if ok6 {
			candidates = append(candidates, v6)
		}
	}
	for _, addr := range candidates {
		if canSend == nil || canSend(addr) {
			var mtu uint16
			if smContext.DNNInfo != nil {
				mtu = smContext.DNNInfo.MTU
			}
			return &RouterAdvertisementPath{
				UPF:      addr,
				UPFTEID:  fteid.Teid,
				SMFTEID:  smfTEID,
				Prefix:   *smContext.PDUAddress.Ipv6Prefix,
				Iid:      *smContext.PDUAddress.Ipv6Iid,
				LinkMTU:  mtu,
				Rules:    rules,
				NodeName: node.GetNodeIP(),
			}, nil
		}
	}
	return nil, fmt.Errorf("the CP2UP F-TEID (%v/%v) has no address the SMF can send to", fteid.Ipv4Address, fteid.Ipv6Address)
}
