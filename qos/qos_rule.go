// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

const (
	OperationCodeCreateNewQoSRule                                   uint8 = 1
	OperationCodeDeleteExistingQoSRule                              uint8 = 2
	OperationCodeModifyExistingQoSRuleAndAddPacketFilters           uint8 = 3
	OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters    uint8 = 4
	OperationCodeModifyExistingQoSRuleAndDeletePacketFilters        uint8 = 5
	OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters uint8 = 6
)

const (
	PacketFilterDirectionDownlink      uint8 = 1
	PacketFilterDirectionUplink        uint8 = 2
	PacketFilterDirectionBidirectional uint8 = 3
)

const (
	// DQR is the "Delete QoS Rule" flag (TS 24.501). It must be set when encoding
	// OperationCodeDeleteExistingQoSRule.
	DefaultDQR uint8 = 1

	// QFI is not included for delete (see MarshalBinary), keep as zero for clarity.
	DefaultQFI uint8 = 0
)

// TS 24.501 Table 9.11.4.13.1
const (
	PFComponentTypeMatchAll                       uint8 = 0x01
	PFComponentTypeIPv4RemoteAddress              uint8 = 0x10
	PFComponentTypeIPv4LocalAddress               uint8 = 0x11
	PFComponentTypeIPv6RemoteAddress              uint8 = 0x21
	PFComponentTypeIPv6LocalAddress               uint8 = 0x23
	PFComponentTypeProtocolIdentifierOrNextHeader uint8 = 0x30
	PFComponentTypeSingleLocalPort                uint8 = 0x40
	PFComponentTypeLocalPortRange                 uint8 = 0x41
	PFComponentTypeSingleRemotePort               uint8 = 0x50
	PFComponentTypeRemotePortRange                uint8 = 0x51
	PFComponentTypeSecurityParameterIndex         uint8 = 0x60
	PFComponentTypeTypeOfServiceOrTrafficClass    uint8 = 0x70
	PFComponentTypeFlowLabel                      uint8 = 0x80
	PFComponentTypeDestinationMACAddress          uint8 = 0x81
	PFComponentTypeSourceMACAddress               uint8 = 0x82
	PFComponentType8021Q_CTAG_VID                 uint8 = 0x83
	PFComponentType8021Q_STAG_VID                 uint8 = 0x84
	PFComponentType8021Q_CTAG_PCPOrDEI            uint8 = 0x85
	PFComponentType8021Q_STAG_PCPOrDEI            uint8 = 0x86
	PFComponentTypeEthertype                      uint8 = 0x87
)

const (
	PacketFilterIdBitmask uint8 = 0x0f
)

type IPFilterRulePortRange struct {
	lowLimit  string
	highLimit string
}

// IPFilterRuleIpAddr is one side of an IPFilterRule: an IPv4 or IPv6 address with an optional
// prefix length, or one of the keywords "any" and "assigned" (RFC 6733 section 4.3, as used by
// the flowDescription of TS 29.512 subclause 5.6.3.2). It holds the text as written; prefix
// reads it.
type IPFilterRuleIpAddr struct {
	addr string
	mask string
}

type IPFilterRule struct {
	protoId                string
	sPort, dPort           string
	sPortRange, dPortRange IPFilterRulePortRange
	sAddr, dAddr           IPFilterRuleIpAddr
}

type PacketFilterComponent struct {
	ComponentValue []byte
	ComponentType  uint8
}

type PacketFilter struct {
	Content       []PacketFilterComponent
	Direction     uint8
	Identifier    uint8 // only 0-15
	ContentLength uint8
}

type QosRule struct {
	PacketFilterList []PacketFilter
	Identifier       uint8 // 0 0 0 0 0 0 0 1	QRI 1 to 1 1 1 1 1 1 1 1	QRI 255
	OperationCode    uint8
	DQR              uint8
	Segregation      uint8
	Precedence       uint8
	QFI              uint8
	Length           uint8
}

func BuildAddDefaultQosRule(defQFI uint8) *QosRule {
	defQosRule := &QosRule{
		Identifier:    255,
		DQR:           0x00,
		OperationCode: OperationCodeCreateNewQoSRule,
		Precedence:    255,
		QFI:           defQFI,
		PacketFilterList: []PacketFilter{
			{
				Identifier: 255,
				Direction:  PacketFilterDirectionBidirectional,
			},
		},
	}

	defPfc := PacketFilterComponent{
		ComponentType: PFComponentTypeMatchAll,
		// ComponentValue: NA for Match All
	}
	defQosRule.PacketFilterList[0].Content = []PacketFilterComponent{defPfc}
	defQosRule.PacketFilterList[0].ContentLength = 0x01

	return defQosRule
}

func BuildQosRules(smPolicyUpdates *PolicyUpdate) QoSRules {
	qosRules := QoSRules{}

	smPolicyDecision := smPolicyUpdates.SmPolicyDecision
	pccRulesUpdate := smPolicyUpdates.PccRuleUpdate

	// New Rules to be added
	if pccRulesUpdate != nil && pccRulesUpdate.add != nil {
		for pccRuleName, pccRuleVal := range pccRulesUpdate.add {
			logger.QosLog.Infof("building QoS Rule from PCC rule [%s]", pccRuleName)
			if len(pccRuleVal.GetRefQosData()) == 0 {
				logger.QosLog.Warnf("skip QoS rule build for PCC rule [%s]: missing QoS reference", pccRuleName)
				continue
			}
			refQosData := GetQoSDataFromPolicyDecision(smPolicyDecision, pccRuleVal.RefQosData[0])
			qosRule := BuildAddQoSRuleFromPccRule(pccRuleVal, refQosData, OperationCodeCreateNewQoSRule)
			if qosRule == nil {
				logger.QosLog.Warnf("skip QoS rule build for PCC rule [%s]: no QoS data, or no flows to build packet filters from", pccRuleName)
				continue
			}
			qosRules = append(qosRules, *qosRule)
		}
	}

	if pccRulesUpdate != nil && pccRulesUpdate.mod != nil {
		for pccRuleName, pccRuleVal := range pccRulesUpdate.mod {
			logger.QosLog.Infof("building QoS Rule from modified PCC rule [%s]", pccRuleName)
			if len(pccRuleVal.GetRefQosData()) == 0 {
				logger.QosLog.Warnf("skip QoS rule modify for PCC rule [%s]: missing QoS reference", pccRuleName)
				continue
			}
			refQosData := GetQoSDataFromPolicyDecision(smPolicyDecision, pccRuleVal.RefQosData[0])
			qosRule := BuildModifyQosRuleFromPccRule(pccRuleVal, refQosData, OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters)
			if qosRule == nil {
				logger.QosLog.Warnf("skip QoS rule modify for PCC rule [%s]: no QoS data, or no flows to build packet filters from", pccRuleName)
				continue
			}
			qosRules = append(qosRules, *qosRule)
		}
	}

	// Rules to be deleted
	if pccRulesUpdate != nil && pccRulesUpdate.del != nil {
		for id := range pccRulesUpdate.del {
			logger.QosLog.Infof("building delete QoS Rule for PCC rule [%s]", id)

			qosRule := BuildDeleteQosRuleFromPccRule(id)
			if qosRule != nil {
				qosRules = append(qosRules, *qosRule)
			}
		}
	}
	return qosRules
}

// BuildQosRulesPDUMod constructs a list of QoS rules for a PDU Session Modification Command
// based on policy updates (add, modify, delete) from the SM Policy Decision.
// It returns a slice of QoSRules ready to be encoded in NAS messages.
func BuildQosRulesPDUMod(smPolicyUpdates *PolicyUpdate) QoSRules {
	qosRules := QoSRules{}

	// Extract the SM Policy Decision and PCC Rule updates
	smPolicyDecision := smPolicyUpdates.SmPolicyDecision
	pccRulesUpdate := smPolicyUpdates.PccRuleUpdate

	// ===============================
	// Add new QoS rules
	// ===============================
	if pccRulesUpdate != nil && pccRulesUpdate.add != nil {
		for pccRuleName, pccRuleVal := range pccRulesUpdate.add {
			logger.QosLog.Infof("building QoS Rule from PCC rule [%s]", pccRuleName)

			if len(pccRuleVal.GetRefQosData()) == 0 {
				logger.QosLog.Warnf("skip QoS rule build for PCC rule [%s]: missing QoS reference", pccRuleName)
				continue
			}
			// Get reference QoS data from SM Policy Decision using the RefQosData index
			refQosData := GetQoSDataFromPolicyDecision(smPolicyDecision, pccRuleVal.RefQosData[0])

			// Build a new QoS rule from the PCC rule and reference QoS data
			qosRule := BuildAddQoSRuleFromPccRule(pccRuleVal, refQosData, OperationCodeCreateNewQoSRule)
			if qosRule == nil {
				logger.QosLog.Warnf("skip QoS rule build for PCC rule [%s]: no QoS data, or no flows to build packet filters from", pccRuleName)
				continue
			}
			// Append the constructed rule to the list
			qosRules = append(qosRules, *qosRule)
		}
	}

	// ===============================
	// Modify existing QoS rules
	// ===============================
	if pccRulesUpdate != nil && pccRulesUpdate.mod != nil {
		for pccRuleName, pccRuleVal := range pccRulesUpdate.mod {
			logger.QosLog.Infof("building QoS Rule from modified PCC rule [%s]", pccRuleName)

			// Get reference QoS data for modification
			if len(pccRuleVal.GetRefQosData()) == 0 {
				logger.QosLog.Warnf("skip QoS rule modify for PCC rule [%s]: missing QoS reference", pccRuleName)
				continue
			}
			refQosData := GetQoSDataFromPolicyDecision(smPolicyDecision, pccRuleVal.RefQosData[0])

			// Build a QoS rule for modification (OperationCode can be same as create depending on implementation)
			qosRule := BuildModifyQosRuleFromPccRule(pccRuleVal, refQosData, OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters)
			if qosRule == nil {
				logger.QosLog.Warnf("skip QoS rule modify for PCC rule [%s]: no QoS data, or no flows to build packet filters from", pccRuleName)
				continue
			}

			// Append modified rule to the list
			qosRules = append(qosRules, *qosRule)
		}
	}

	// ===============================
	//  Delete QoS rules
	// ===============================
	if pccRulesUpdate != nil && pccRulesUpdate.del != nil {
		for id, pccRuleName := range pccRulesUpdate.del {
			logger.QosLog.Infof("Processing PCC rule deletion: ID='%s', Rule=%+v", id, pccRuleName)

			// Build a delete QoS rule based on the PCC rule ID
			qosRule := BuildDeleteQosRuleFromPccRule(id)

			// Only append if the rule was successfully created
			if qosRule != nil {
				qosRules = append(qosRules, *qosRule)

				logger.QosLog.Infof(
					"Built Delete QoS Rule -> Identifier=%d, OperationCode=%d, DQR=%d, QFI=%d",
					qosRule.Identifier, qosRule.OperationCode, qosRule.DQR, qosRule.QFI,
				)
			} else {
				logger.QosLog.Warnf("Skipping QoS rule build for PCC rule ID='%s' (nil returned)", id)
			}
		}

		for i, qr := range qosRules {
			logger.QosLog.Infof("Final QoS Rule[%d] -> Identifier=%d, OperationCode=%d, DQR=%d, QFI=%d",
				i, qr.Identifier, qr.OperationCode, qr.DQR, qr.QFI)
		}

		logger.QosLog.Infof("Total delete QoS Rules built: %d", len(qosRules))
	}

	// Return the complete list of QoS rules (added, modified, deleted)
	return qosRules
}

func BuildAddQoSRuleFromPccRule(pccRule *models.PccRule, qosData *models.QosData, pccRuleOpCode uint8) *QosRule {
	if pccRule == nil || qosData == nil {
		return nil
	}

	// A rule that names no flows carries no packet filters, and a rule that creates or replaces
	// all of them without one is not a rule the UE can install (TS 24.501 subclause 9.11.4.13).
	// The user plane refuses the same shape -- BuildCreatePdrFromPccRule has no flow to build a
	// PDI from -- so building it here would announce to the UE a rule nothing enforces.
	if len(pccRule.FlowInfos) == 0 {
		return nil
	}

	qRule := QosRule{
		Identifier:    GetQosRuleIdFromPccRuleId(pccRule.GetPccRuleId()),
		DQR:           btou(qosData.GetDefQosFlowIndication()),
		OperationCode: pccRuleOpCode,
		Precedence:    uint8(pccRule.GetPrecedence()),
		QFI:           GetQosFlowIdFromQosId(qosData.GetQosId()),
	}

	qRule.BuildPacketFilterListFromPccRule(pccRule)

	// Every flow may have been refused (see SetPfContent), and a rule that creates QoS without a
	// packet filter is no more installable than one built from no flows.
	if len(qRule.PacketFilterList) == 0 {
		return nil
	}

	return &qRule
}

// BuildModifyQosRuleFromPccRule constructs a QoSRule modification based on
// PCC rule updates and QoS data.
func BuildModifyQosRuleFromPccRule(pccRule *models.PccRule, qosData *models.QosData, pccRuleOpCode uint8) *QosRule {
	if pccRule == nil || qosData == nil {
		return nil
	}

	// A rule that names no flows carries no packet filters, and a rule that creates or replaces
	// all of them without one is not a rule the UE can install (TS 24.501 subclause 9.11.4.13).
	// The user plane refuses the same shape -- BuildCreatePdrFromPccRule has no flow to build a
	// PDI from -- so building it here would announce to the UE a rule nothing enforces.
	if len(pccRule.FlowInfos) == 0 {
		return nil
	}

	qRule := QosRule{
		Identifier:    GetQosRuleIdFromPccRuleId(pccRule.GetPccRuleId()),
		DQR:           0,
		OperationCode: pccRuleOpCode,
		Precedence:    uint8(pccRule.GetPrecedence()),
		QFI:           GetQosFlowIdFromQosId(qosData.GetQosId()),
	}

	// Only build packet filter list if the operation involves packet filter changes
	switch pccRuleOpCode {
	case OperationCodeModifyExistingQoSRuleAndAddPacketFilters,
		OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters,
		OperationCodeModifyExistingQoSRuleAndDeletePacketFilters:
		qRule.BuildPacketFilterListFromPccRule(pccRule)
		// As for a new rule: none of the flows could be encoded.
		if len(qRule.PacketFilterList) == 0 {
			return nil
		}
	case OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters:
		// No packet filter changes needed
	}

	return &qRule
}

// BuildDeleteQosRuleFromPccRule constructs a QoSRule deletion request for a given PCC rule.
// This is used when the PCC rule is removed and the corresponding QoS rule
// needs to be deleted.
func BuildDeleteQosRuleFromPccRule(pccRuleId string) *QosRule {
	if pccRuleId == "" {
		logger.QosLog.Warnf("BuildDeleteQosRuleFromPccRule: empty PCC rule ID, skipping")
		return nil
	}

	qosRuleID := GetQosRuleIdFromPccRuleId(pccRuleId)
	if qosRuleID == 0 {
		logger.QosLog.Warnf("BuildDeleteQosRuleFromPccRule: invalid PCC rule ID %q (cannot derive QoS Rule Identifier), skipping", pccRuleId)
		return nil
	}
	qRule := QosRule{
		Identifier:    qosRuleID,
		OperationCode: OperationCodeDeleteExistingQoSRule,
		DQR:           DefaultDQR,
		QFI:           DefaultQFI,
	}

	return &qRule
}

func btou(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func GetQosRuleIdFromPccRuleId(pccRuleId string) uint8 {
	if id, err := strconv.Atoi(pccRuleId); err != nil {
		// TODO: Error Log
		return 0
	} else {
		return uint8(id)
	}
}

// BuildPacketFilterListFromPccRule builds a packet filter for each flow of the rule. A flow whose
// description cannot be encoded is left out, and said so: the rule then matches less traffic than
// the PCC rule, where a filter without its address would have matched more.
func (q *QosRule) BuildPacketFilterListFromPccRule(pccRule *models.PccRule) {
	pfList := []PacketFilter{}

	// Iterate through
	for _, flow := range pccRule.FlowInfos {
		pf, err := GetPacketFilterFromFlowInfo(&flow)
		if err != nil {
			logger.QosLog.Errorf("PCC rule [%s]: packet filter [%s] left out of the QoS rule: %v",
				pccRule.GetPccRuleId(), flow.GetPackFiltId(), err)
			continue
		}
		pfList = append(pfList, pf)
	}
	q.PacketFilterList = pfList
}

// GetPacketFilterFromFlowInfo builds the packet filter of one flow, or fails as SetPfContent does.
func GetPacketFilterFromFlowInfo(flowInfo *models.FlowInformation) (PacketFilter, error) {
	pf := &PacketFilter{
		Identifier: GetPfId(flowInfo.GetPackFiltId()),
		Direction:  GetPfDirectionFromPccFlowInfo(flowInfo.GetFlowDirection()),
	}

	// Fill PF component contents
	if err := pf.SetPfContent(flowInfo.GetFlowDescription()); err != nil {
		return PacketFilter{}, err
	}

	return *pf, nil
}

func GetPfId(pfID string) uint8 {
	if pfID == "" {
		logger.QosLog.Warn("PackFiltId is empty, defaulting to 0")
		return 0
	}

	id, err := strconv.Atoi(pfID)
	if err != nil {
		logger.QosLog.Errorf("Error converting PackFiltId [%s] to int: %v. Defaulting to 0", pfID, err)
		return 0
	}

	return uint8(id) & PacketFilterIdBitmask
}

// Get Packet Filter Directions
func GetPfDirectionFromPccFlowInfo(flowDir models.FlowDirectionRm) uint8 {
	switch flowDir {
	case models.FLOWDIRECTIONRM_UPLINK:
		return PacketFilterDirectionUplink
	case models.FLOWDIRECTIONRM_DOWNLINK:
		return PacketFilterDirectionDownlink
	case models.FLOWDIRECTIONRM_BIDIRECTIONAL:
		return PacketFilterDirectionBidirectional
	default:
		// TODO: Error Log
		return PacketFilterDirectionBidirectional
	}
}

// e.x. permit out ip-proto from x.x.x.x/maskbits port/port-range to assigned(x.x.x.x/maskbits) port/port-range
//
//	0		1 	2		3	  4   				5   		   6 	7						8
//
// An address may be IPv6 as well, as in "permit out 17 from 2001:db8::1/64 53 to assigned". The
// tokens are split on white space and an address from its length on the "/" only, so the colons of
// an IPv6 literal are never read as a port separator: ports are tokens of their own.
//
// See spec 29212-5.4.2 / 29512-5.6.3.2
func DecodeFlowDescToIPFilters(flowDesc string) *IPFilterRule {
	// Tokenize flow desc and make PF components
	pfcTags := strings.Fields(flowDesc)

	// get PF tags into IP filter components
	ipfRule := &IPFilterRule{}

	// Protocol Id/Next Header
	ipfRule.protoId = pfcTags[2]

	// decode source IP/mask
	ipfRule.decodeIpFilterAddr(true, pfcTags[4])

	// decode source port/port-range (optional)
	if pfcTags[6] == "to" {
		// decode source port/port-range
		ipfRule.decodeIpFilterPortInfo(true, pfcTags[5])

		// decode destination IP/mask
		ipfRule.decodeIpFilterAddr(false, pfcTags[7])

		// decode destination port/port-range(optional), if any
		if len(pfcTags) == 9 {
			ipfRule.decodeIpFilterPortInfo(false, pfcTags[8])
		}
	} else {
		// decode destination IP/mask
		ipfRule.decodeIpFilterAddr(false, pfcTags[6])

		// decode destination port/port-range(optional), if any
		if len(pfcTags) == 8 {
			ipfRule.decodeIpFilterPortInfo(false, pfcTags[7])
		}
	}

	return ipfRule
}

func (ipf *IPFilterRule) IsMatchAllIPFilter() bool {
	if ipf.sAddr.addr == ipFilterAddrAny && ipf.dAddr.addr == ipFilterAddrAssigned {
		return true
	}
	return false
}

func (ipfRule *IPFilterRule) decodeIpFilterPortInfo(source bool, tag string) {
	// check if it is single port or range
	ports := strings.Split(tag, "-")

	if len(ports) > 1 { // port range
		if source {
			ipfRule.sPortRange.lowLimit = ports[0]
			ipfRule.sPortRange.highLimit = ports[1]
		} else {
			ipfRule.dPortRange.lowLimit = ports[0]
			ipfRule.dPortRange.highLimit = ports[1]
		}
	} else {
		if source {
			ipfRule.sPort = ports[0]
		} else {
			ipfRule.dPort = ports[0]
		}
	}
}

func (ipfRule *IPFilterRule) decodeIpFilterAddr(source bool, tag string) {
	ipAndMask := strings.Split(tag, "/")
	if source {
		ipfRule.sAddr.addr = ipAndMask[0] // can be x.x.x.x, an IPv6 address or "any"
	} else {
		ipfRule.dAddr.addr = ipAndMask[0] // can be x.x.x.x, an IPv6 address or "assigned"
	}

	// mask can be nil
	if len(ipAndMask) > 1 {
		if source {
			ipfRule.sAddr.mask = ipAndMask[1]
		} else {
			ipfRule.dAddr.mask = ipAndMask[1]
		}
	}
}

// The keywords an IPFilterRule may give instead of an address (RFC 6733 section 4.3): "any"
// matches every address and "assigned" the address assigned to the UE. Neither is an address a
// packet filter component can carry.
const (
	ipFilterAddrAny      = "any"
	ipFilterAddrAssigned = "assigned"
)

// isKeyword reports whether the side names "any" or "assigned" rather than an address.
func (a IPFilterRuleIpAddr) isKeyword() bool {
	return a.addr == ipFilterAddrAny || a.addr == ipFilterAddrAssigned
}

// prefix reads the side as an address of either family with its prefix length. Without a length
// the address stands for itself alone: /32 for IPv4, /128 for IPv6. The address is kept as written,
// host bits and all, as the IPv4 encoding always kept it.
//
// An IPv4-mapped IPv6 address reads as the IPv4 address it maps, because net.IP.To4 read it so and
// the IPv4 packet filter encoding is not to change; its length is then an IPv4 one. An address with
// a zone, a negated one ("!") and a length beyond the family's are refused, as is anything else
// that is not an address: a packet filter that left them out would match more than the rule.
func (a IPFilterRuleIpAddr) prefix() (netip.Prefix, error) {
	addr, err := netip.ParseAddr(a.addr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("address %q: %w", a.addr, err)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("address %q: an address with a zone is not a packet filter address", a.addr)
	}
	addr = addr.Unmap()

	bits := addr.BitLen()
	if a.mask != "" {
		// strconv.Atoi, as the IPv4 encoding read the length before, so a length it took is
		// still taken.
		if bits, err = strconv.Atoi(a.mask); err != nil {
			return netip.Prefix{}, fmt.Errorf("address %q: prefix length %q: %w", a.addr, a.mask, err)
		}
	}

	prefix := netip.PrefixFrom(addr, bits)
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("address %q: prefix length %q is out of range for the family", a.addr, a.mask)
	}
	return prefix, nil
}

// GetPfContent fills the packet filter from a flow description, as SetPfContent does. A
// description SetPfContent refuses is logged and leaves the filter as it was.
func (pf *PacketFilter) GetPfContent(flowDesc string) {
	if err := pf.SetPfContent(flowDesc); err != nil {
		logger.QosLog.Errorf("flow description [%s] not encoded: %v", flowDesc, err)
	}
}

// SetPfContent fills the packet filter components from a flow description (TS 24.501 subclause
// 9.11.4.13). It fails, and leaves the filter as it was, when an address of the description cannot
// be encoded: leaving the address out instead would give the UE a filter matching more than the
// PCC rule does, all traffic in the worst case.
func (pf *PacketFilter) SetPfContent(flowDesc string) error {
	pfcList := []PacketFilterComponent{}

	ipf := DecodeFlowDescToIPFilters(flowDesc)

	// Make Packet Filter Component from decoded IPFilters

	// MatchAll Packet Filter
	if ipf.IsMatchAllIPFilter() {
		pfc := &PacketFilterComponent{
			ComponentType: PFComponentTypeMatchAll,
		}

		pfcList = append(pfcList, *pfc)
		pf.ContentLength += 1
		pf.Content = pfcList
		return nil
	}

	// Both addresses first, so that a refused one leaves the filter untouched.
	remoteAddr, remoteAddrLen, err := buildPFCompAddr(false, ipf.sAddr)
	if err != nil {
		return fmt.Errorf("remote address: %w", err)
	}
	localAddr, localAddrLen, err := buildPFCompAddr(true, ipf.dAddr)
	if err != nil {
		return fmt.Errorf("local address: %w", err)
	}

	// Protocol identifier/Next header type
	if pfc, plen := BuildPFCompProtocolId(ipf.protoId); pfc != nil {
		pfcList = append(pfcList, *pfc)
		pf.ContentLength += plen
	}

	// Remote Addr
	if remoteAddr != nil {
		pfcList = append(pfcList, *remoteAddr)
		pf.ContentLength += remoteAddrLen
	}

	// Remote Port
	if pfc, plen := buildPFCompPort(false, ipf.sPort); pfc != nil {
		pfcList = append(pfcList, *pfc)
		pf.ContentLength += plen
	}

	// Remote Port range
	if pfc, plen := buildPFCompPortRange(false, ipf.sPortRange); pfc != nil {
		pfcList = append(pfcList, *pfc)
		pf.ContentLength += plen
	}

	// Local Addr
	if localAddr != nil {
		pfcList = append(pfcList, *localAddr)
		pf.ContentLength += localAddrLen
	}

	// Local Port
	if pfc, plen := buildPFCompPort(true, ipf.dPort); pfc != nil {
		pfcList = append(pfcList, *pfc)
		pf.ContentLength += plen
	}

	// Local Port range
	if pfc, plen := buildPFCompPortRange(true, ipf.dPortRange); pfc != nil {
		pfcList = append(pfcList, *pfc)
		pf.ContentLength += plen
	}

	pf.Content = pfcList
	return nil
}

// buildPFCompAddr builds the address component of one side of a flow description, with the
// length it adds to the packet filter's contents (the type octet and the value).
//
//   - IPv4: IPv4 remote (0x10) or local (0x11) address, 4 octets of address and 4 of mask.
//   - IPv6: IPv6 remote (0x21) or local (0x23) address/prefix length, 16 octets of address and 1 of
//     prefix length (TS 24.501 Table 9.11.4.13.1). The 0x22 form, which it deprecates, is not used.
//
// The keywords "any" and "assigned" build no component: "any" matches every address, and the
// address assigned to the UE is the one the filter is applied to anyway. Anything else that is not
// an address of either family is an error, not a missing component.
func buildPFCompAddr(local bool, val IPFilterRuleIpAddr) (*PacketFilterComponent, uint8, error) {
	if val.isKeyword() {
		return nil, 0, nil
	}

	prefix, err := val.prefix()
	if err != nil {
		return nil, 0, err
	}

	if prefix.Addr().Is4() {
		component := PFComponentTypeIPv4RemoteAddress
		if local {
			component = PFComponentTypeIPv4LocalAddress
		}
		addr := prefix.Addr().As4()
		value := make([]byte, 0, 8)
		value = append(value, addr[:]...)
		value = append(value, net.CIDRMask(prefix.Bits(), 32)...)
		return &PacketFilterComponent{ComponentType: component, ComponentValue: value}, 9, nil
	}

	component := PFComponentTypeIPv6RemoteAddress
	if local {
		component = PFComponentTypeIPv6LocalAddress
	}
	addr := prefix.Addr().As16()
	value := make([]byte, 0, 17)
	value = append(value, addr[:]...)
	value = append(value, uint8(prefix.Bits()))
	return &PacketFilterComponent{ComponentType: component, ComponentValue: value}, 18, nil
}

func buildPFCompPort(local bool, val string) (*PacketFilterComponent, uint8) {
	if val == "" {
		return nil, 0
	}

	component := PFComponentTypeSingleRemotePort
	if local {
		component = PFComponentTypeSingleLocalPort
	}

	pfc := &PacketFilterComponent{
		ComponentType:  component,
		ComponentValue: make([]byte, 2),
	}

	if port, err := strconv.Atoi(val); err == nil {
		port16 := uint16(port)
		pfc.ComponentValue = []byte{byte(port16 >> 8), byte(port16 & 0xff)}
	}
	return pfc, 3
}

func buildPFCompPortRange(local bool, val IPFilterRulePortRange) (*PacketFilterComponent, uint8) {
	if val.lowLimit == "" || val.highLimit == "" {
		return nil, 0
	}

	component := PFComponentTypeRemotePortRange
	if local {
		component = PFComponentTypeLocalPortRange
	}

	pfc := &PacketFilterComponent{
		ComponentType:  component,
		ComponentValue: make([]byte, 4),
	}

	// low port value
	if port, err := strconv.Atoi(val.lowLimit); err == nil {
		port16 := uint16(port)
		pfc.ComponentValue = []byte{byte(port16 >> 8), byte(port16 & 0xff)}
	}

	// high port value
	if port, err := strconv.Atoi(val.highLimit); err == nil {
		port16 := uint16(port)
		pfc.ComponentValue = append(pfc.ComponentValue, byte(port16>>8), byte(port16&0xff))
	}
	return pfc, 5
}

func BuildPFCompProtocolId(val string) (*PacketFilterComponent, uint8) {
	if val == "ip" {
		return nil, 0
	}

	pfc := &PacketFilterComponent{
		ComponentType:  PFComponentTypeProtocolIdentifierOrNextHeader,
		ComponentValue: make([]byte, 1),
	}

	if pfcVal, err := strconv.Atoi(val); err == nil {
		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, uint32(pfcVal))
		pfc.ComponentValue = []byte{bs[3]}
	} else {
		return nil, 0
	}

	return pfc, 2
}

func (pf *PacketFilter) MarshalBinary() (data []byte, err error) {
	packetFilterBuffer := bytes.NewBuffer(nil)
	header := 0 | pf.Direction<<4 | pf.Identifier
	// write header
	err = packetFilterBuffer.WriteByte(header)
	if err != nil {
		return nil, err
	}
	// write length of packet filter
	err = packetFilterBuffer.WriteByte(pf.ContentLength) // uint8(len(pf.Content)))
	if err != nil {
		return nil, err
	}

	for _, content := range pf.Content {
		err = packetFilterBuffer.WriteByte(content.ComponentType)
		if err != nil {
			return nil, err
		}
		_, err = packetFilterBuffer.Write(content.ComponentValue)
		if err != nil {
			return nil, err
		}
	}
	/*
		err = packetFilterBuffer.WriteByte(pf.Content)
		if err != nil {
			return nil, err
		}

		if pf.ComponentType == PacketFilterComponentTypeMatchAll || pf.Component == nil {
			_, err = packetFilterBuffer.Write(pf.Component)
			if err != nil {
				return nil, err
			}
		}
	*/
	return packetFilterBuffer.Bytes(), nil
}

func (r *QosRule) MarshalBinary() ([]byte, error) {
	ruleContentBuffer := bytes.NewBuffer(nil)

	// write rule content Header
	ruleContentHeader := r.OperationCode<<5 | r.DQR<<4 | uint8(len(r.PacketFilterList))
	ruleContentBuffer.WriteByte(ruleContentHeader)

	packetFilterListBuffer := &bytes.Buffer{}
	for _, pf := range r.PacketFilterList {
		var packetFilterBytes []byte
		if retPacketFilterByte, err := pf.MarshalBinary(); err != nil {
			return nil, err
		} else {
			packetFilterBytes = retPacketFilterByte
		}

		if _, err := packetFilterListBuffer.Write(packetFilterBytes); err != nil {
			return nil, err
		}
	}

	// write QoS
	if _, err := ruleContentBuffer.ReadFrom(packetFilterListBuffer); err != nil {
		return nil, err
	}
	if r.OperationCode != OperationCodeDeleteExistingQoSRule {
		// Only for Create/Modify
		if err := ruleContentBuffer.WriteByte(r.Precedence); err != nil {
			return nil, err
		}
		segregationAndQFIByte := r.Segregation<<6 | r.QFI
		if err := ruleContentBuffer.WriteByte(segregationAndQFIByte); err != nil {
			return nil, err
		}
	}

	ruleBuffer := bytes.NewBuffer(nil)
	// write QoS rule identifier
	if err := ruleBuffer.WriteByte(r.Identifier); err != nil {
		return nil, err
	}

	// write QoS rule length
	if err := binary.Write(ruleBuffer, binary.BigEndian, uint16(ruleContentBuffer.Len())); err != nil {
		return nil, err
	}

	// write QoS rule Content
	if _, err := ruleBuffer.ReadFrom(ruleContentBuffer); err != nil {
		return nil, err
	}

	return ruleBuffer.Bytes(), nil
}

type QoSRules []QosRule

func (rs QoSRules) MarshalBinary() (data []byte, err error) {
	qosRulesBuffer := bytes.NewBuffer(nil)

	for _, rule := range rs {
		var ruleBytes []byte
		if retRuleBytes, err := rule.MarshalBinary(); err != nil {
			return nil, err
		} else {
			ruleBytes = retRuleBytes
		}

		if _, err := qosRulesBuffer.Write(ruleBytes); err != nil {
			return nil, err
		}
	}
	return qosRulesBuffer.Bytes(), nil
}
