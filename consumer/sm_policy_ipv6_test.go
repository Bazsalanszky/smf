// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
)

// policyCreateBody sends the session's policy association create to a stub PCF and returns the
// request body as sent.
func policyCreateBody(t *testing.T, typ uint8, addr *smf_context.UeIpAddr) []byte {
	t.Helper()
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			t.Errorf("reading the create body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	defer server.Close()

	smContext := smContextWithPCF(t, server)
	smContext.Ref = "urn:uuid:5e1f0c2a-0000-4000-8000-000000000001"
	smContext.Dnn = testPolicyDnn
	smContext.PDUAddress = addr
	smContext.SelectedPDUSessionType = typ
	snssai := models.NewSnssai(1)
	snssai.SetSd("010203")
	smContext.Snssai = snssai
	smContext.DnnConfiguration = models.DnnConfiguration{}
	if _, _, err := SendSMPolicyAssociationCreate(smContext); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	return body
}

const testPolicyDnn = "internet"

// withoutNotificationURI decodes a create body and drops its notificationUri, which is built
// from the SBI configuration this test does not set, and which another change formats anew.
func withoutNotificationURI(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	delete(fields, "notificationUri")
	return fields
}

// The create of an IPv4 session, field for field as the SMF sent it before IPv6 sessions,
// notificationUri aside, for an address in either form.
func TestIPv4PolicyCreateIsAsBefore(t *testing.T) {
	const before = `{"accessType":"","dnn":"internet","ipv4Address":"192.168.139.17","notificationUri":"://:0/nsmf-callback/sm-policies/urn:uuid:5e1f0c2a-0000-4000-8000-000000000001","pduSessionId":10,"pduSessionType":"IPV4","ratType":"","servingNetwork":{"mcc":"","mnc":""},"sliceInfo":{"sd":"010203","sst":1},"supi":"imsi-001010123456789","suppFeat":"F"}`
	want, err := json.Marshal(withoutNotificationURI(t, []byte(before)))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []net.IP{net.ParseIP(testSmfAllocatedIpv4).To4(), net.ParseIP(testSmfAllocatedIpv4)} {
		body := policyCreateBody(t, nasMessage.PDUSessionTypeIPv4, &smf_context.UeIpAddr{Ip: ip})
		got, err := json.Marshal(withoutNotificationURI(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("create body\n got %s\nwant %s", got, want)
		}
	}
}

// A session with IPv6 gives the PCF its prefix as ipv6AddressPrefix; ipv4Address is sent only for
// a session with an IPv4 address, and not as "<nil>" for one without.
func TestPolicyCreateCarriesTheSessionsAddresses(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:500:3::/64")
	iid := smf_context.InterfaceIdentifier{0, 0, 0, 0, 0, 0, 0, 1}
	for _, tc := range []struct {
		name               string
		typ                uint8
		addr               *smf_context.UeIpAddr
		wantType, wantIpv4 string
		wantPrefix         string
	}{
		{
			name: "IPv6", typ: nasMessage.PDUSessionTypeIPv6,
			addr:     &smf_context.UeIpAddr{Ipv6Prefix: &prefix, Ipv6Iid: &iid},
			wantType: "IPV6", wantPrefix: "2001:db8:500:3::/64",
		},
		{
			name: "IPv4v6", typ: nasMessage.PDUSessionTypeIPv4IPv6,
			addr:     &smf_context.UeIpAddr{Ip: net.ParseIP(testSmfAllocatedIpv4).To4(), Ipv6Prefix: &prefix, Ipv6Iid: &iid},
			wantType: "IPV4V6", wantIpv4: testSmfAllocatedIpv4, wantPrefix: "2001:db8:500:3::/64",
		},
		{
			name: "IPv4", typ: nasMessage.PDUSessionTypeIPv4,
			addr:     &smf_context.UeIpAddr{Ip: net.ParseIP(testSmfAllocatedIpv4).To4()},
			wantType: "IPV4", wantIpv4: testSmfAllocatedIpv4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := withoutNotificationURI(t, policyCreateBody(t, tc.typ, tc.addr))
			str := func(key string) string {
				v, _ := fields[key].(string)
				return v
			}
			if got := str("pduSessionType"); got != tc.wantType {
				t.Errorf("pduSessionType %q, want %q", got, tc.wantType)
			}
			if _, present := fields["ipv4Address"]; present != (tc.wantIpv4 != "") || str("ipv4Address") != tc.wantIpv4 {
				t.Errorf("ipv4Address %v (present %t), want %q", fields["ipv4Address"], present, tc.wantIpv4)
			}
			if _, present := fields["ipv6AddressPrefix"]; present != (tc.wantPrefix != "") || str("ipv6AddressPrefix") != tc.wantPrefix {
				t.Errorf("ipv6AddressPrefix %v (present %t), want %q", fields["ipv6AddressPrefix"], present, tc.wantPrefix)
			}
		})
	}
}
