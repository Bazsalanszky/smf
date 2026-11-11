// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"testing"

	gojson "github.com/goccy/go-json"
	"github.com/omec-project/openapi/v2/models"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var testIid = InterfaceIdentifier{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

// storableContext is the smallest SMContext whose stored document decodes again: AccessType,
// NfStatus and SscModes.DefaultSscMode reject "" in their own UnmarshalJSON.
func storableContext(ref string, addr *UeIpAddr, dnnInfo *SnssaiSmfDnnInfo) *SMContext {
	return &SMContext{
		Ref:        ref,
		Supi:       testSupi,
		Identifier: testSupi,
		Dnn:        "ipv6-store-dnn",
		AnType:     models.ACCESSTYPE__3_GPP_ACCESS,
		PDUAddress: addr,
		DNNInfo:    dnnInfo,
		AMFProfile: models.NFProfileDiscovery{
			NfInstanceId: "amf-instance-v6", NfType: models.NFTYPE_AMF, NfStatus: models.NFSTATUS_REGISTERED,
		},
		SelectedPCFProfile: models.NFProfileDiscovery{
			NfInstanceId: "pcf-instance-v6", NfType: models.NFTYPE_PCF, NfStatus: models.NFSTATUS_REGISTERED,
		},
		DnnConfiguration: models.DnnConfiguration{
			SscModes: models.SscModes{DefaultSscMode: models.SSCMODE_SSC_MODE_1},
		},
		ProtocolConfigurationOptions: &ProtocolConfigurationOptions{DNSIPv4Request: true},
	}
}

// throughTheDatastore takes a context the way a restart does: ToBsonM, the BSON codec both ways
// (nested documents read back as maps, as the mongoapi client is configured), and the decoding
// GetSMContextByRefInDB applies.
func throughTheDatastore(t *testing.T, smContext *SMContext) (stored map[string]any, decoded *SMContext) {
	t.Helper()
	raw, err := bson.Marshal(ToBsonM(smContext))
	if err != nil {
		t.Fatalf("encoding as BSON: %v", err)
	}
	dec := bson.NewDecoder(bson.NewDocumentReader(bytes.NewReader(raw)))
	dec.DefaultDocumentMap()
	if err = dec.Decode(&stored); err != nil {
		t.Fatalf("decoding the BSON document: %v", err)
	}
	decoded = &SMContext{}
	if err = gojson.Unmarshal(mapToByte(stored), decoded); err != nil {
		t.Fatalf("decoding the session: %v", err)
	}
	return stored, decoded
}

func keysOf(t *testing.T, doc map[string]any, field string) []string {
	t.Helper()
	sub, ok := doc[field].(map[string]any)
	if !ok {
		t.Fatalf("stored %s is %T, want a document", field, doc[field])
	}
	keys := make([]string, 0, len(sub))
	for k := range sub {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// An IPv4 session is stored with exactly the keys it had before the IPv6 fields existed, in the
// three documents that gained one: the address, the DNN information and the PCO flags.
func TestAnIPv4SessionIsStoredAsBefore(t *testing.T) {
	allocator, err := NewIPAllocator("172.250.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	smContext := storableContext("v4-stored-as-before",
		&UeIpAddr{Ip: net.ParseIP("172.250.0.7").To4()},
		&SnssaiSmfDnnInfo{UeIPAllocator: allocator, DNS: DNS{IPv4Addr: net.ParseIP("8.8.8.8")}, MTU: 1400})

	stored := ToBsonM(smContext)
	pduAddress, err := gojson.Marshal(stored["pduAddress"])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"Ip":"172.250.0.7","Static":false,"UpfProvided":false}`; string(pduAddress) != want {
		t.Errorf("stored pduAddress = %s, want %s", pduAddress, want)
	}
	for field, want := range map[string][]string{
		"pduAddress":                   {"Ip", "Static", "UpfProvided"},
		"dnnInfo":                      {"DNS", "MTU", "UeIPAllocator"},
		"protocolConfigurationOptions": {"DNSIPv4Request", "DNSIPv6Request", "IPv4LinkMTURequest", "PCSCFIPv4Request"},
	} {
		if got := keysOf(t, stored, field); !reflect.DeepEqual(got, want) {
			t.Errorf("stored %s keys = %v, want %v", field, got, want)
		}
	}
}

// A document written before the IPv6 fields existed reads back as an IPv4 session.
func TestAStoredIPv4DocumentRestores(t *testing.T) {
	// The address and DNN parts of a document an SMF without IPv6 support writes.
	old := []byte(`{"ref":"old-doc","supi":"imsi-208930000000001","identifier":"imsi-208930000000001",
		"dnn":"internet","anType":"3GPP_ACCESS",
		"pduAddress":{"Ip":"172.250.0.7","UpfProvided":false,"Static":true},
		"dnnInfo":{"UeIPAllocator":{},"DNS":{"IPv4Addr":"8.8.8.8","IPv6Addr":""},"MTU":1400},
		"protocolConfigurationOptions":{"DNSIPv4Request":true,"DNSIPv6Request":true,"IPv4LinkMTURequest":true,"PCSCFIPv4Request":false},
		"selectedPDUSessionType":1,"pfcpContext":{},"tunnel":{}}`)
	var smContext SMContext
	if err := gojson.Unmarshal(old, &smContext); err != nil {
		t.Fatalf("decoding an old document: %v", err)
	}
	addr := smContext.PDUAddress
	if !addr.Ip.Equal(net.ParseIP("172.250.0.7")) || !addr.Static || addr.UpfProvided {
		t.Errorf("restored address = %+v", addr)
	}
	if !addr.HasIpv4() || addr.HasIpv6() || addr.Ipv6Prefix != nil || addr.Ipv6Iid != nil {
		t.Errorf("an old document restored with IPv6 state: %+v", addr)
	}
	if smContext.DNNInfo.UeIpv6Allocator != nil || smContext.DNNInfo.PCSCFIPv6 != nil {
		t.Errorf("an old document restored IPv6 DNN state: %+v", smContext.DNNInfo)
	}
	if smContext.ProtocolConfigurationOptions.PCSCFIPv6Request {
		t.Errorf("an old document restored a P-CSCF IPv6 request")
	}
}

func TestIPv6SessionsSurviveTheDatastore(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:500:7::/64")
	for _, tc := range []struct {
		name string
		addr *UeIpAddr
	}{
		{name: nameIPv6, addr: &UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &testIid}},
		{name: nameIPv4v6, addr: &UeIpAddr{Ip: net.ParseIP("172.250.0.7").To4(), Ipv6Prefix: &prefix, Ipv6Iid: &testIid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v6Allocator, err := NewIpv6PrefixAllocator("2001:db8:500::/56", 64)
			if err != nil {
				t.Fatal(err)
			}
			smContext := storableContext("v6-"+tc.name, tc.addr, &SnssaiSmfDnnInfo{
				UeIpv6Allocator: v6Allocator,
				DNS:             DNS{IPv6Addr: net.ParseIP("2001:4860:4860::8888")},
				PCSCFIPv6:       net.ParseIP("2001:db8:ffff::5"),
				MTU:             1400,
			})
			smContext.ProtocolConfigurationOptions.PCSCFIPv6Request = true

			stored, decoded := throughTheDatastore(t, smContext)
			sub := stored["pduAddress"].(map[string]any)
			if sub["Ipv6Prefix"] != "2001:db8:500:7::/64" || sub["Ipv6Iid"] != "0123:4567:89ab:cdef" {
				t.Errorf("stored pduAddress = %v, want the prefix and identifier in text", sub)
			}

			got := decoded.PDUAddress
			if got.Ipv6Prefix == nil || *got.Ipv6Prefix != prefix || got.Ipv6Iid == nil || *got.Ipv6Iid != testIid {
				t.Fatalf("restored address = %+v, want prefix %s and identifier %s", got, prefix, testIid)
			}
			if got.HasIpv4() != tc.addr.HasIpv4() || !got.Ip.Equal(tc.addr.Ip) {
				t.Errorf("restored IPv4 %v, want %v", got.Ip, tc.addr.Ip)
			}
			if got.Ipv6Addr().String() != "2001:db8:500:7:123:4567:89ab:cdef" {
				t.Errorf("restored IPv6 address = %s", got.Ipv6Addr())
			}
			if !decoded.DNNInfo.PCSCFIPv6.Equal(net.ParseIP("2001:db8:ffff::5")) ||
				!decoded.DNNInfo.DNS.IPv6Addr.Equal(net.ParseIP("2001:4860:4860::8888")) {
				t.Errorf("restored DNN information = %+v", decoded.DNNInfo)
			}
			if !decoded.ProtocolConfigurationOptions.PCSCFIPv6Request {
				t.Errorf("the P-CSCF IPv6 request was not restored")
			}
			// The restored allocator has no pool, as the IPv4 one has none: releasing on it is
			// skipped, not a panic, and the session's own addresses are cleared.
			if decoded.DNNInfo.UeIpv6Allocator == nil || decoded.DNNInfo.HasIpv6Pool() {
				t.Errorf("restored IPv6 allocator = %+v, want one with no pool", decoded.DNNInfo.UeIpv6Allocator)
			}
			decoded.initLogTags()
			if err := decoded.ReleaseUeIpAddr(); err != nil {
				t.Errorf("ReleaseUeIpAddr: %v", err)
			}
			if decoded.PDUAddress.HasIpv6() || decoded.PDUAddress.HasIpv4() {
				t.Errorf("after release the session holds %+v", decoded.PDUAddress)
			}
		})
	}
}
