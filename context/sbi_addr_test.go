// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/sbiaddr"
)

const (
	sbiPodIPEnv  = "POD_IP"
	sbiPodIPsEnv = "POD_IPS"
	sbiTestPort  = 29502
	sbiV4        = "10.0.0.5"
	sbiV6        = "fd00::5"
	sbiLocalV4   = "192.168.1.10"
	sbiLocalV6   = "2001:db8::10"
	sbiAnyV4     = "0.0.0.0"
	sbiSvcName   = "smf"
	sbiWantV6URI = "http://[fd00::5]:29502"
	sbiPeerV6URI = "http://[fd00::42]:29518"
)

func sbiIfAddr(s string) net.Addr {
	return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(64, 128)}
}

// A pod's interface addresses: loopback and link-local first, then one global per family.
func sbiLocalAddrs() ([]net.Addr, error) {
	return []net.Addr{sbiIfAddr("127.0.0.1"), sbiIfAddr("::1"), sbiIfAddr("fe80::1"), sbiIfAddr(sbiLocalV4), sbiIfAddr(sbiLocalV6)}, nil
}

func sbiNoLocalAddrs() ([]net.Addr, error) { return nil, errors.New("no interfaces") }

func TestResolveSbiAddrs(t *testing.T) {
	tests := []struct {
		name     string
		sbi      factory.Sbi
		env      map[string]string // set with t.Setenv; "" unsets the variable
		local    func() ([]net.Addr, error)
		wantV4   string
		wantV6   string
		wantPref sbiaddr.Preference
		wantBind string
	}{
		{name: "nothing configured", wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiAnyV4},
		{
			name: "chart default: a service name", sbi: factory.Sbi{RegisterIPv4: sbiSvcName, BindingIPv4: sbiAnyV4},
			wantV4: sbiSvcName, wantBind: sbiAnyV4,
		},
		{name: "IPv4 literal", sbi: factory.Sbi{RegisterIPv4: sbiV4}, wantV4: sbiV4, wantBind: sbiAnyV4},
		{name: "IPv6 literal under registerIPv4", sbi: factory.Sbi{RegisterIPv4: "FD00:0::5"}, wantV6: sbiV6, wantBind: sbiAnyV4},
		{
			name: "registerIPv6 next to IPv4 gives dual", sbi: factory.Sbi{RegisterIPv4: sbiV4, RegisterIPv6: sbiV6},
			wantV4: sbiV4, wantV6: sbiV6, wantBind: sbiAnyV4,
		},
		{
			name: "host name and IPv6", sbi: factory.Sbi{RegisterIPv4: sbiSvcName, RegisterIPv6: sbiV6},
			wantV4: sbiSvcName, wantV6: sbiV6, wantBind: sbiAnyV4,
		},
		{
			name: "a host name wins the legacy field over IPv4", sbi: factory.Sbi{RegisterIPv4: sbiSvcName + "," + sbiV4},
			wantV4: sbiSvcName, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP holding IPv4", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: sbiV4}, wantV4: sbiV4, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP holding IPv6 under registerIPv4", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv, BindingIPv4: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: sbiV6}, wantV6: sbiV6, wantBind: sbiV6,
		},
		{
			name: "POD_IPS dual stack", sbi: factory.Sbi{RegisterIPv4: sbiPodIPsEnv},
			env: map[string]string{sbiPodIPsEnv: sbiV6 + "," + sbiV4}, wantV4: sbiV4, wantV6: sbiV6, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP and POD_IPS", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv, RegisterIPv6: sbiPodIPsEnv},
			env: map[string]string{sbiPodIPEnv: sbiV4, sbiPodIPsEnv: sbiV4 + "," + sbiV6}, wantV4: sbiV4, wantV6: sbiV6, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP unset falls back to the local IPv4", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: ""}, local: sbiLocalAddrs, wantV4: sbiLocalV4, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP unset under registerIPv6 falls back to the local IPv6", sbi: factory.Sbi{RegisterIPv6: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: ""}, local: sbiLocalAddrs, wantV6: sbiLocalV6, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP unset under both keys falls back per family", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv, RegisterIPv6: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: ""}, local: sbiLocalAddrs, wantV4: sbiLocalV4, wantV6: sbiLocalV6, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IP unset without local addresses gives the default", sbi: factory.Sbi{RegisterIPv4: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: ""}, local: sbiNoLocalAddrs, wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiAnyV4,
		},
		{
			name: "POD_IPS unset is not a fallback trigger", sbi: factory.Sbi{RegisterIPv4: sbiPodIPsEnv},
			env: map[string]string{sbiPodIPsEnv: ""}, local: sbiLocalAddrs, wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiAnyV4,
		},
		{
			name: "an invalid value gives the default", sbi: factory.Sbi{RegisterIPv4: "10.0.0.256"},
			wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiAnyV4,
		},
		{
			name: "preferredFamily IPv6", sbi: factory.Sbi{RegisterIPv4: sbiV4, RegisterIPv6: sbiV6, PreferredFamily: "IPv6"},
			wantV4: sbiV4, wantV6: sbiV6, wantPref: sbiaddr.PreferIPv6, wantBind: sbiAnyV4,
		},
		{
			name: "an unknown preferredFamily means IPv4", sbi: factory.Sbi{RegisterIPv4: sbiV4, PreferredFamily: "IPv5"},
			wantV4: sbiV4, wantBind: sbiAnyV4,
		},
		{
			name: "bindingAddr wins over bindingIPv4", sbi: factory.Sbi{BindingAddr: "::", BindingIPv4: sbiAnyV4},
			wantV4: factory.SMF_DEFAULT_IPV4, wantBind: "::",
		},
		{
			name: "bindingAddr from POD_IP", sbi: factory.Sbi{BindingAddr: sbiPodIPEnv},
			env: map[string]string{sbiPodIPEnv: sbiV6}, wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiV6,
		},
		{
			name: "bracketed bindingIPv4 is unwrapped", sbi: factory.Sbi{BindingIPv4: "[::]"},
			wantV4: factory.SMF_DEFAULT_IPV4, wantBind: "::",
		},
		{
			name: "a bindingAddr list binds the dual-stack wildcard", sbi: factory.Sbi{BindingAddr: sbiPodIPsEnv},
			env: map[string]string{sbiPodIPsEnv: sbiV4 + "," + sbiV6}, wantV4: factory.SMF_DEFAULT_IPV4, wantBind: sbiAnyV4,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				sbiSetEnv(t, k, v)
			}
			local := tc.local
			if local == nil {
				local = func() ([]net.Addr, error) {
					t.Error("interface addresses read although POD_IP is not the trigger")
					return nil, nil
				}
			}
			var c SMFContext
			sbi := tc.sbi
			c.resolveSbiAddrs(&sbi, local)
			if c.RegisterIPv4 != tc.wantV4 || c.RegisterIPv6 != tc.wantV6 {
				t.Errorf("RegisterIPv4, RegisterIPv6 = %q, %q, want %q, %q", c.RegisterIPv4, c.RegisterIPv6, tc.wantV4, tc.wantV6)
			}
			if c.SbiPreference != tc.wantPref {
				t.Errorf("SbiPreference = %v, want %v", c.SbiPreference, tc.wantPref)
			}
			if c.BindingIPv4 != tc.wantBind {
				t.Errorf("BindingIPv4 = %q, want %q", c.BindingIPv4, tc.wantBind)
			}
		})
	}
}

// sbiSetEnv sets an environment variable for the test, or unsets it for an empty value.
func sbiSetEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value) // registers the restore
	if value == "" {
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

// sbiLegacyRegisterAndBind is the register and binding logic of InitSmfContext before
// resolveSbiAddrs, with GetLocalIP over the given interface addresses.
func sbiLegacyRegisterAndBind(sbi *factory.Sbi, ifAddrs []net.Addr) (register, bind string) {
	localIp := ""
	for _, address := range ifAddrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			localIp = ipnet.IP.String()
			break
		}
	}
	register = factory.SMF_DEFAULT_IPV4
	if sbi.RegisterIPv4 != "" {
		register = sbi.RegisterIPv4
		if sbi.RegisterIPv4 == "POD_IP" {
			if podIP := os.Getenv("POD_IP"); podIP != "" {
				register = podIP
			} else if localIp != "" {
				register = localIp
			} else {
				register = factory.SMF_DEFAULT_IPV4
			}
		}
	}
	bind = os.Getenv(sbi.BindingIPv4)
	if bind == "" {
		bind = sbi.BindingIPv4
		if bind == "" {
			bind = sbiAnyV4
		}
	}
	return register, bind
}

// For every IPv4-only configuration (registerIPv4 an IPv4 address, a host name, POD_IP
// or unset; bindingIPv4 alone), the context fields are what they were before.
func TestResolveSbiAddrsKeepsLegacyBehaviour(t *testing.T) {
	registers := []string{"", "127.0.0.1", sbiV4, sbiSvcName, "smf.omec.svc.cluster.local", sbiPodIPEnv}
	bindings := []string{"", "0.0.0.0", sbiV4, sbiSvcName, sbiPodIPEnv}
	envs := []string{"", "10.1.2.3"}
	locals := map[string][]net.Addr{
		"no local IPv4": {sbiIfAddr("127.0.0.1"), sbiIfAddr("fe80::1")},
		"local IPv4":    {sbiIfAddr("127.0.0.1"), sbiIfAddr(sbiLocalV4), sbiIfAddr(sbiLocalV6)},
	}
	for _, register := range registers {
		for _, binding := range bindings {
			for _, env := range envs {
				for localName, local := range locals {
					name := fmt.Sprintf("register=%q/binding=%q/POD_IP=%q/%s", register, binding, env, localName)
					t.Run(name, func(t *testing.T) {
						sbiSetEnv(t, sbiPodIPEnv, env)
						sbi := factory.Sbi{RegisterIPv4: register, BindingIPv4: binding}
						wantRegister, wantBind := sbiLegacyRegisterAndBind(&sbi, local)
						var c SMFContext
						c.resolveSbiAddrs(&sbi, func() ([]net.Addr, error) { return local, nil })
						if c.RegisterIPv4 != wantRegister || c.RegisterIPv6 != "" || c.BindingIPv4 != wantBind {
							t.Errorf("got register %q, %q, bind %q; legacy register %q, bind %q",
								c.RegisterIPv4, c.RegisterIPv6, c.BindingIPv4, wantRegister, wantBind)
						}
						if got, want := c.GetSbiUri(), fmt.Sprintf("%s://%s:%d", c.URIScheme, wantRegister, c.SBIPort); got != want {
							t.Errorf("GetSbiUri() = %q, legacy %q", got, want)
						}
					})
				}
			}
		}
	}
}

func TestGetSbiUri(t *testing.T) {
	tests := []struct {
		name   string
		ctx    *SMFContext
		want   string
		wantV6 bool
	}{
		{name: "IPv4", ctx: &SMFContext{URIScheme: models.URISCHEME_HTTP, RegisterIPv4: sbiV4, SBIPort: sbiTestPort}, want: "http://10.0.0.5:29502"},
		{name: "host name", ctx: &SMFContext{URIScheme: models.URISCHEME_HTTPS, RegisterIPv4: sbiSvcName, SBIPort: sbiTestPort}, want: "https://smf:29502"},
		{name: "IPv6 only", ctx: &SMFContext{URIScheme: models.URISCHEME_HTTP, RegisterIPv6: sbiV6, SBIPort: sbiTestPort}, want: sbiWantV6URI, wantV6: true},
		{name: "IPv6 in the legacy field", ctx: &SMFContext{URIScheme: models.URISCHEME_HTTP, RegisterIPv4: sbiV6, SBIPort: sbiTestPort}, want: sbiWantV6URI, wantV6: true},
		{
			name: "dual, IPv4 preferred", ctx: &SMFContext{URIScheme: models.URISCHEME_HTTP, RegisterIPv4: sbiV4, RegisterIPv6: sbiV6, SBIPort: sbiTestPort},
			want: "http://10.0.0.5:29502",
		},
		{
			name: "dual, IPv6 preferred",
			ctx: &SMFContext{
				URIScheme: models.URISCHEME_HTTP, RegisterIPv4: sbiV4, RegisterIPv6: sbiV6, SBIPort: sbiTestPort,
				SbiPreference: sbiaddr.PreferIPv6,
			},
			want: sbiWantV6URI, wantV6: true,
		},
		{
			name: "a host name wins over IPv6 with either preference",
			ctx: &SMFContext{
				URIScheme: models.URISCHEME_HTTP, RegisterIPv4: sbiSvcName, RegisterIPv6: sbiV6, SBIPort: sbiTestPort,
				SbiPreference: sbiaddr.PreferIPv6,
			},
			want: "http://smf:29502",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ctx.GetSbiUri()
			if got != tc.want {
				t.Fatalf("GetSbiUri() = %q, want %q", got, tc.want)
			}
			u, err := url.Parse(got + "/nsmf-callback/nf-status-notify")
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			if u.Port() != "29502" || (net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).To4() == nil) != tc.wantV6 {
				t.Errorf("parsed host %q port %q", u.Hostname(), u.Port())
			}
		})
	}
}

func sbiAMFProfile(apiPrefix string, endPoints ...models.IpEndPoint) models.NFProfileDiscovery {
	var svc models.NFService
	svc.SetServiceInstanceId("namf-comm")
	svc.SetServiceName(models.SERVICENAME_NAMF_COMM)
	svc.SetScheme(models.URISCHEME_HTTP)
	if apiPrefix != "" {
		svc.SetApiPrefix(apiPrefix)
	}
	svc.SetIpEndPoints(endPoints)
	var prof models.NFProfileDiscovery
	prof.SetNfInstanceId("amf-1")
	prof.SetNfType(models.NFTYPE_AMF)
	prof.SetNfServiceList(map[string]models.NFService{svc.GetServiceInstanceId(): svc})
	return prof
}

func sbiEndPoint(ipv4, ipv6 string) models.IpEndPoint {
	e := models.NewIpEndPoint()
	if ipv4 != "" {
		e.SetIpv4Address(ipv4)
	}
	if ipv6 != "" {
		e.SetIpv6Address(ipv6)
	}
	e.SetPort(29518)
	return *e
}

// The peer clients are built from PeerServiceURI: the apiPrefix as before, and otherwise
// the peer's IPv4 or IPv6 endpoint, which used to give an empty apiRoot.
func TestRebuildCommunicationClientResolvesPeerAddresses(t *testing.T) {
	self := SMF_Self()
	savedPref := self.SbiPreference
	t.Cleanup(func() { self.SbiPreference = savedPref })

	tests := []struct {
		name    string
		profile models.NFProfileDiscovery
		pref    sbiaddr.Preference
		want    string
	}{
		{
			name:    "apiPrefix is used as it is",
			profile: sbiAMFProfile("http://10.42.0.42:29518", sbiEndPoint("10.42.0.1", "")),
			want:    "http://10.42.0.42:29518",
		},
		{
			name:    "an IPv6 apiPrefix is used as it is",
			profile: sbiAMFProfile("http://[fd00::42]:29518"),
			want:    sbiPeerV6URI,
		},
		{name: "IPv4 endpoint", profile: sbiAMFProfile("", sbiEndPoint("10.42.0.1", "")), want: "http://10.42.0.1:29518"},
		{name: "IPv6-only endpoint", profile: sbiAMFProfile("", sbiEndPoint("", "fd00::42")), want: "http://[fd00::42]:29518"},
		{
			name:    "dual endpoints, IPv4 preferred",
			profile: sbiAMFProfile("", sbiEndPoint("10.42.0.1", ""), sbiEndPoint("", "fd00::42")),
			want:    "http://10.42.0.1:29518",
		},
		{
			name:    "dual endpoints, IPv6 preferred",
			profile: sbiAMFProfile("", sbiEndPoint("10.42.0.1", ""), sbiEndPoint("", "fd00::42")),
			pref:    sbiaddr.PreferIPv6,
			want:    sbiPeerV6URI,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			self.SbiPreference = tc.pref
			smCtx := &SMContext{AMFProfile: tc.profile}
			smCtx.RebuildCommunicationClient()
			if smCtx.CommunicationClient == nil {
				t.Fatal("CommunicationClient is nil")
			}
			if got := smCtx.CommunicationClient.GetConfig().Servers[0].Variables["apiRoot"].DefaultValue; got != tc.want {
				t.Errorf("apiRoot = %q, want %q", got, tc.want)
			}
		})
	}
}
