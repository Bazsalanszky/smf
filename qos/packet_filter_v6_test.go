// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

// The packet filter contents (TS 24.501 subclause 9.11.4.13) of a flow description: the length
// octet, then the components, as MarshalBinary writes them after the identifier octet.
func TestAFlowDescriptionEncodesItsAddressesInTheirOwnFamily(t *testing.T) {
	tests := []struct {
		name     string
		flowDesc string
		want     []byte
	}{
		{
			name:     "IPv6 remote prefix with a port, local port range",
			flowDesc: "permit out 17 from 2001:db8::/32 53 to assigned 1000-2000",
			want: []byte{
				28,
				0x30, 17,
				0x21, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
				0x50, 0x00, 0x35,
				0x41, 0x03, 0xe8, 0x07, 0xd0,
			},
		},
		{
			name:     "IPv6 on both sides, host bits kept as written",
			flowDesc: "permit out 6 from 2001:db8:1::10/64 80-443 to 2001:db8:500::1/64 50000",
			want: []byte{
				46,
				0x30, 6,
				0x21, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x10, 64,
				0x51, 0x00, 0x50, 0x01, 0xbb,
				0x23, 0x20, 0x01, 0x0d, 0xb8, 0x05, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 64,
				0x40, 0xc3, 0x50,
			},
		},
		{
			name:     "IPv6 local address without a length is a /128",
			flowDesc: "permit out ip from any to 2001:db8::5",
			want: []byte{
				18,
				0x23, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05, 128,
			},
		},
		{
			name:     "an IPv4-mapped address is encoded as IPv4",
			flowDesc: "permit out ip from ::ffff:1.2.3.4 to assigned",
			want: []byte{
				9,
				0x10, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff,
			},
		},
		{
			name:     "IPv4 as before",
			flowDesc: "permit out 17 from 1.1.1.1/24 1000-1200 to 2.2.2.2/24 2000-2500",
			want: []byte{
				30,
				0x30, 17,
				0x10, 1, 1, 1, 1, 0xff, 0xff, 0xff, 0x00,
				0x51, 0x03, 0xe8, 0x04, 0xb0,
				0x11, 2, 2, 2, 2, 0xff, 0xff, 0xff, 0x00,
				0x41, 0x07, 0xd0, 0x09, 0xc4,
			},
		},
		{
			name:     "any to assigned matches all",
			flowDesc: "permit out ip from any to assigned",
			want:     []byte{1, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &qos.PacketFilter{}
			if err := pf.SetPfContent(tt.flowDesc); err != nil {
				t.Fatalf("SetPfContent: %v", err)
			}
			data, err := pf.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := data[1:]; !bytes.Equal(got, tt.want) {
				t.Fatalf("got  % x\nwant % x", got, tt.want)
			}
		})
	}
}

// A description with an address that cannot be encoded is refused, and leaves the filter as it
// was: a filter without that address would match more than the PCC rule does.
func TestAFlowDescriptionWithAnAddressItCannotEncodeIsRefused(t *testing.T) {
	for _, flowDesc := range []string{
		"permit out ip from 2001:db8::1%eth0 to assigned",
		"permit out ip from 2001:db8::/129 to assigned",
		"permit out ip from any to 1.2.3.4/33",
		"permit out ip from !10.0.0.1 to assigned",
		"permit out ip from somewhere to assigned",
		"permit out 17 from any to 2001:db8::1/x 53",
	} {
		t.Run(flowDesc, func(t *testing.T) {
			before := qos.PacketFilter{
				Identifier:    3,
				ContentLength: 1,
				Content:       []qos.PacketFilterComponent{{ComponentType: qos.PFComponentTypeMatchAll}},
			}
			pf := before
			if err := pf.SetPfContent(flowDesc); err == nil {
				t.Fatalf("accepted; content %+v", pf.Content)
			}
			if !reflect.DeepEqual(pf, before) {
				t.Fatalf("filter changed: %+v, was %+v", pf, before)
			}

			flow := models.FlowInformation{}
			flow.SetFlowDescription(flowDesc)
			if _, err := qos.GetPacketFilterFromFlowInfo(&flow); err == nil {
				t.Fatal("GetPacketFilterFromFlowInfo accepted it")
			}
		})
	}
}

func pccRuleWithFlows(descs ...string) *models.PccRule {
	rule := models.NewPccRule("7")
	rule.SetPrecedence(100)
	flows := make([]models.FlowInformation, 0, len(descs))
	for i, desc := range descs {
		var flow models.FlowInformation
		flow.SetFlowDescription(desc)
		flow.SetPackFiltId(string(rune('1' + i)))
		flow.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
		flows = append(flows, flow)
	}
	rule.SetFlowInfos(flows)
	return rule
}

// A refused flow is left out of the QoS rule; a rule all of whose flows are refused is not built,
// as one without flows is not.
func TestAQoSRuleLeavesOutTheFlowsItCannotEncode(t *testing.T) {
	qosData := models.NewQosData("5")
	const good, bad = "permit out 17 from 2001:db8::/32 to assigned", "permit out ip from 2001:db8::1%eth0 to assigned"

	rule := qos.BuildAddQoSRuleFromPccRule(pccRuleWithFlows(bad, good), qosData, qos.OperationCodeCreateNewQoSRule)
	if rule == nil {
		t.Fatal("no rule from one good and one refused flow")
	}
	if len(rule.PacketFilterList) != 1 || rule.PacketFilterList[0].Identifier != 2 {
		t.Fatalf("packet filters %+v, want only the second flow's", rule.PacketFilterList)
	}

	if rule := qos.BuildAddQoSRuleFromPccRule(pccRuleWithFlows(bad), qosData, qos.OperationCodeCreateNewQoSRule); rule != nil {
		t.Fatalf("a rule from refused flows only: %+v", rule)
	}
	if rule := qos.BuildModifyQosRuleFromPccRule(pccRuleWithFlows(bad), qosData,
		qos.OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters); rule != nil {
		t.Fatalf("a modification from refused flows only: %+v", rule)
	}
	if rule := qos.BuildModifyQosRuleFromPccRule(pccRuleWithFlows(bad), qosData,
		qos.OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters); rule == nil {
		t.Fatal("a modification that leaves the packet filters alone needs none of them encodable")
	}
}
