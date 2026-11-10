// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/sbiaddr"
)

const (
	sbiTestV4   = "10.0.0.5"
	sbiTestV6   = "fd00::5"
	sbiTestPort = 29502
	sbiTestFQDN = "smf"
	smfNameCfg  = "SMF"
	v4Prefix    = "http://10.0.0.5:29502"
	v6Prefix    = "http://[fd00::5]:29502"
	fqdnPrefix  = "http://smf:29502"

	svcPduSession    = "nsmf-pdusession"
	svcEventExposure = "nsmf-event-exposure"
)

type wantEndPoint struct {
	ipv4, ipv6 string
}

func sbiTestContext(registerIPv4, registerIPv6 string, pref sbiaddr.Preference) *smfContext.SMFContext {
	return &smfContext.SMFContext{
		NfInstanceID:  "sbi-test-nf-id",
		URIScheme:     models.URISCHEME_HTTP,
		RegisterIPv4:  registerIPv4,
		RegisterIPv6:  registerIPv6,
		SbiPreference: pref,
		SBIPort:       sbiTestPort,
	}
}

// saveSmfSelfSbi returns SMF_Self and restores its SBI fields when the test ends.
func saveSmfSelfSbi(t *testing.T) *smfContext.SMFContext {
	t.Helper()
	self := smfContext.SMF_Self()
	savedV4, savedV6, savedPref := self.RegisterIPv4, self.RegisterIPv6, self.SbiPreference
	savedScheme, savedPort := self.URIScheme, self.SBIPort
	t.Cleanup(func() {
		self.RegisterIPv4, self.RegisterIPv6, self.SbiPreference = savedV4, savedV6, savedPref
		self.URIScheme, self.SBIPort = savedScheme, savedPort
	})
	return self
}

func useSmfConfig(t *testing.T, cfg *factory.Configuration) {
	t.Helper()
	saved := factory.SmfConfig.Configuration
	factory.SmfConfig.Configuration = cfg
	t.Cleanup(func() { factory.SmfConfig.Configuration = saved })
}

func TestGetNfProfileAddresses(t *testing.T) {
	tests := []struct {
		name          string
		ctx           *smfContext.SMFContext
		sbi           *factory.Sbi
		smfName       string
		wantFQDN      string
		wantIPv4      []string
		wantIPv6      []string
		wantEndPoints []wantEndPoint
		wantApiPrefix string
	}{
		{
			name: "IPv4", ctx: sbiTestContext(sbiTestV4, "", sbiaddr.PreferIPv4),
			wantIPv4: []string{sbiTestV4}, wantEndPoints: []wantEndPoint{{ipv4: sbiTestV4}},
			wantApiPrefix: v4Prefix,
		},
		{
			name: "host name", ctx: sbiTestContext(sbiTestFQDN, "", sbiaddr.PreferIPv4),
			wantFQDN: sbiTestFQDN, wantEndPoints: []wantEndPoint{{}}, wantApiPrefix: fqdnPrefix,
		},
		{
			name: "IPv6 only", ctx: sbiTestContext("", sbiTestV6, sbiaddr.PreferIPv4),
			wantIPv6: []string{sbiTestV6}, wantEndPoints: []wantEndPoint{{ipv6: sbiTestV6}},
			wantApiPrefix: v6Prefix,
		},
		{
			name: "IPv6 in the legacy field", ctx: sbiTestContext(sbiTestV6, "", sbiaddr.PreferIPv4),
			wantIPv6: []string{sbiTestV6}, wantEndPoints: []wantEndPoint{{ipv6: sbiTestV6}},
			wantApiPrefix: v6Prefix,
		},
		{
			name: "dual stack, IPv4 preferred", ctx: sbiTestContext(sbiTestV4, sbiTestV6, sbiaddr.PreferIPv4),
			wantIPv4: []string{sbiTestV4}, wantIPv6: []string{sbiTestV6},
			wantEndPoints: []wantEndPoint{{ipv4: sbiTestV4}, {ipv6: sbiTestV6}},
			wantApiPrefix: v4Prefix,
		},
		{
			name: "dual stack, IPv6 preferred", ctx: sbiTestContext(sbiTestV4, sbiTestV6, sbiaddr.PreferIPv6),
			wantIPv4: []string{sbiTestV4}, wantIPv6: []string{sbiTestV6},
			wantEndPoints: []wantEndPoint{{ipv4: sbiTestV4}, {ipv6: sbiTestV6}},
			wantApiPrefix: v6Prefix,
		},
		{
			name: "host name and IPv6", ctx: sbiTestContext(sbiTestFQDN, sbiTestV6, sbiaddr.PreferIPv6),
			wantFQDN: sbiTestFQDN, wantIPv6: []string{sbiTestV6}, wantEndPoints: []wantEndPoint{{ipv6: sbiTestV6}},
			wantApiPrefix: fqdnPrefix,
		},
		{
			name: "registerIPv4 POD_IP with smfName advertises the name", ctx: sbiTestContext(sbiTestV4, "", sbiaddr.PreferIPv4),
			sbi: &factory.Sbi{RegisterIPv4: sbiaddr.EnvPodIP}, smfName: smfNameCfg,
			wantFQDN: sbiTestFQDN, wantEndPoints: []wantEndPoint{{}}, wantApiPrefix: fqdnPrefix,
		},
		{
			name: "registerIPv4 POD_IP with smfName keeps the IPv6 pod address", ctx: sbiTestContext("", sbiTestV6, sbiaddr.PreferIPv4),
			sbi: &factory.Sbi{RegisterIPv4: sbiaddr.EnvPodIP}, smfName: smfNameCfg,
			wantFQDN: sbiTestFQDN, wantIPv6: []string{sbiTestV6}, wantEndPoints: []wantEndPoint{{ipv6: sbiTestV6}},
			wantApiPrefix: fqdnPrefix,
		},
		{
			name: "smfName without POD_IP is ignored", ctx: sbiTestContext(sbiTestV4, "", sbiaddr.PreferIPv4),
			sbi: &factory.Sbi{RegisterIPv4: sbiTestV4}, smfName: smfNameCfg,
			wantIPv4: []string{sbiTestV4}, wantEndPoints: []wantEndPoint{{ipv4: sbiTestV4}},
			wantApiPrefix: v4Prefix,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			useSmfConfig(t, &factory.Configuration{ServiceNameList: []string{svcPduSession}, Sbi: tc.sbi, SmfName: tc.smfName})
			profile, err := getNfProfile(tc.ctx, []nfConfigApi.SessionManagement{makeSessionCfg()})
			if err != nil {
				t.Fatalf("getNfProfile: %v", err)
			}
			if profile.GetFqdn() != tc.wantFQDN {
				t.Errorf("fqdn = %q, want %q", profile.GetFqdn(), tc.wantFQDN)
			}
			if !reflect.DeepEqual(profile.GetIpv4Addresses(), tc.wantIPv4) {
				t.Errorf("ipv4Addresses = %v, want %v", profile.GetIpv4Addresses(), tc.wantIPv4)
			}
			if !reflect.DeepEqual(profile.GetIpv6Addresses(), tc.wantIPv6) {
				t.Errorf("ipv6Addresses = %v, want %v", profile.GetIpv6Addresses(), tc.wantIPv6)
			}
			for _, svc := range profile.GetNfServiceList() {
				checkService(t, svc, tc.wantFQDN, tc.wantApiPrefix, tc.wantEndPoints)
			}
			for _, svc := range profile.GetNfServices() {
				checkService(t, svc, tc.wantFQDN, tc.wantApiPrefix, tc.wantEndPoints)
			}
			// TS 29.510: an IpEndPoint carries at most one of ipv4Address and ipv6Address.
			body, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			var decoded models.NFProfile
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("profile does not round-trip: %v", err)
			}
		})
	}
}

func checkService(t *testing.T, svc models.NFService, wantFQDN, wantApiPrefix string, want []wantEndPoint) {
	t.Helper()
	if svc.GetFqdn() != wantFQDN {
		t.Errorf("service fqdn = %q, want %q", svc.GetFqdn(), wantFQDN)
	}
	if svc.GetApiPrefix() != wantApiPrefix {
		t.Errorf("apiPrefix = %q, want %q", svc.GetApiPrefix(), wantApiPrefix)
	}
	if u, err := url.Parse(svc.GetApiPrefix()); err != nil || u.Port() != "29502" {
		t.Errorf("apiPrefix %q does not parse with port 29502: %v", svc.GetApiPrefix(), err)
	}
	if v := svc.GetVersions(); len(v) != 1 || v[0].GetApiFullVersion() != wantApiPrefix+"/"+svcPduSession+"/v1" {
		t.Errorf("versions = %+v, want apiFullVersion %s/nsmf-pdusession/v1", v, wantApiPrefix)
	}
	got := svc.GetIpEndPoints()
	if len(got) != len(want) {
		t.Fatalf("ipEndPoints = %+v, want %d", got, len(want))
	}
	for i, e := range got {
		if e.GetIpv4Address() != want[i].ipv4 || e.GetIpv6Address() != want[i].ipv6 || e.GetPort() != sbiTestPort {
			t.Errorf("ipEndPoints[%d] = %q %q :%d, want %q %q :%d", i,
				e.GetIpv4Address(), e.GetIpv6Address(), e.GetPort(), want[i].ipv4, want[i].ipv6, sbiTestPort)
		}
	}
}

// For an IPv4 register address the profile carries the same ipv4Addresses, apiPrefix and
// apiFullVersion as the old fmt.Sprintf code; the only addition is the ipEndPoint.
func TestGetNfProfileKeepsLegacyIPv4Shape(t *testing.T) {
	useSmfConfig(t, &factory.Configuration{ServiceNameList: []string{svcPduSession, svcEventExposure}})
	for _, ip := range []string{"127.0.0.2", sbiTestV4, "192.168.1.10"} {
		for _, scheme := range []models.UriScheme{models.URISCHEME_HTTP, models.URISCHEME_HTTPS} {
			ctx := sbiTestContext(ip, "", sbiaddr.PreferIPv4)
			ctx.URIScheme = scheme
			profile, err := getNfProfile(ctx, []nfConfigApi.SessionManagement{makeSessionCfg()})
			if err != nil {
				t.Fatal(err)
			}
			normalizeAdvertisedSmfHost(&profile)
			legacyPrefix := fmt.Sprintf("%s://%s:%d", scheme, ip, sbiTestPort)
			if !reflect.DeepEqual(profile.GetIpv4Addresses(), []string{ip}) || profile.HasFqdn() || profile.HasIpv6Addresses() {
				t.Errorf("%s: addresses %v fqdn %q ipv6 %v", ip, profile.GetIpv4Addresses(), profile.GetFqdn(), profile.GetIpv6Addresses())
			}
			for _, svc := range profile.GetNfServiceList() {
				if svc.GetApiPrefix() != legacyPrefix || svc.GetVersions()[0].GetApiFullVersion() != legacyPrefix+"/"+svcPduSession+"/v1" {
					t.Errorf("%s: apiPrefix %q apiFullVersion %q, legacy %q", ip, svc.GetApiPrefix(),
						svc.GetVersions()[0].GetApiFullVersion(), legacyPrefix)
				}
			}
		}
	}
}

// normalizeAdvertisedSmfHost rewrites the apiFullVersion of every service to its own name
// when the SMF registers a host name, as before, and leaves an IP registration alone.
func TestNormalizeAdvertisedSmfHost(t *testing.T) {
	self := saveSmfSelfSbi(t)
	useSmfConfig(t, &factory.Configuration{ServiceNameList: []string{svcPduSession, svcEventExposure}})

	tests := []struct {
		name, registerIPv4, registerIPv6 string
		wantPrefix                       string
		perServiceName                   bool
	}{
		{name: "IPv4", registerIPv4: sbiTestV4, wantPrefix: v4Prefix},
		{name: "IPv6", registerIPv6: sbiTestV6, wantPrefix: v6Prefix},
		{name: "host name", registerIPv4: sbiTestFQDN, registerIPv6: sbiTestV6, wantPrefix: fqdnPrefix, perServiceName: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			self.RegisterIPv4, self.RegisterIPv6, self.SbiPreference = tc.registerIPv4, tc.registerIPv6, sbiaddr.PreferIPv4
			self.URIScheme, self.SBIPort = models.URISCHEME_HTTP, sbiTestPort
			profile, err := getNfProfile(self, []nfConfigApi.SessionManagement{makeSessionCfg()})
			if err != nil {
				t.Fatal(err)
			}
			normalizeAdvertisedSmfHost(&profile)
			for _, svc := range profile.GetNfServiceList() {
				wantFull := tc.wantPrefix + "/" + svcPduSession + "/v1"
				if tc.perServiceName {
					wantFull = tc.wantPrefix + "/" + string(svc.GetServiceName()) + "/v1"
				}
				if svc.GetApiPrefix() != tc.wantPrefix || svc.GetVersions()[0].GetApiFullVersion() != wantFull {
					t.Errorf("%s: apiPrefix %q apiFullVersion %q, want %q %q", svc.GetServiceName(),
						svc.GetApiPrefix(), svc.GetVersions()[0].GetApiFullVersion(), tc.wantPrefix, wantFull)
				}
			}
		})
	}
}

// The SM policy notification URI is the SMF's own URI, bracketed for IPv6, and a UE
// address that is not IPv4 is left out instead of being sent as "<nil>".
func TestSMPolicyCreateCallbackAndUeAddress(t *testing.T) {
	self := saveSmfSelfSbi(t)

	tests := []struct {
		name, registerIPv4, registerIPv6 string
		ueIP                             net.IP
		wantNotify                       string
		wantUeIpv4                       any
	}{
		{
			name: "IPv4 SMF, IPv4 UE", registerIPv4: sbiTestV4, ueIP: net.ParseIP(testSmfAllocatedIpv4),
			wantNotify: "http://10.0.0.5:29502/nsmf-callback/sm-policies/ref-1", wantUeIpv4: testSmfAllocatedIpv4,
		},
		{
			name: "IPv6 SMF, IPv4 UE", registerIPv6: sbiTestV6, ueIP: net.ParseIP(testSmfAllocatedIpv4),
			wantNotify: "http://[fd00::5]:29502/nsmf-callback/sm-policies/ref-1", wantUeIpv4: testSmfAllocatedIpv4,
		},
		{
			name: "no UE IPv4 address", registerIPv4: sbiTestV4, ueIP: net.ParseIP("2001:db8::1"),
			wantNotify: "http://10.0.0.5:29502/nsmf-callback/sm-policies/ref-1", wantUeIpv4: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			self.RegisterIPv4, self.RegisterIPv6, self.SbiPreference = tc.registerIPv4, tc.registerIPv6, sbiaddr.PreferIPv4
			self.URIScheme, self.SBIPort = models.URISCHEME_HTTP, sbiTestPort

			var sent map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
					t.Errorf("decode create body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
					t.Errorf("encode decision: %v", err)
				}
			}))
			defer server.Close()

			smContext := smContextWithPCF(t, server)
			smContext.Ref = "ref-1"
			smContext.PolicyReportedIpv4 = ""
			smContext.PDUAddress = &smfContext.UeIpAddr{Ip: tc.ueIP}
			smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
			smContext.Snssai = models.NewSnssai(1)
			if _, _, err := SendSMPolicyAssociationCreate(smContext); err != nil {
				t.Fatalf("create failed: %v", err)
			}
			if sent["notificationUri"] != tc.wantNotify {
				t.Errorf("notificationUri = %v, want %q", sent["notificationUri"], tc.wantNotify)
			}
			if sent["ipv4Address"] != tc.wantUeIpv4 {
				t.Errorf("ipv4Address = %v, want %v", sent["ipv4Address"], tc.wantUeIpv4)
			}
		})
	}
}
