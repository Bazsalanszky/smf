// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/smf/factory"
)

func TestResolvePfcpLocal(t *testing.T) {
	const (
		podIPEnv  = "POD_IP"
		podIPsEnv = "POD_IPS"
		v4        = "10.42.0.17"
		v6        = "2001:db8:600::17"
	)
	tests := []struct {
		name       string
		pfcp       factory.PFCP
		env        map[string]string
		wantNodeID NodeID
		wantV4     string
		wantV6     string
		wantListen string // "" = wildcard
		wantFamily AddressFamily
	}{
		{
			name:       "IPv4 POD_IP (the default chart on an IPv4 cluster)",
			pfcp:       factory.PFCP{Addr: podIPEnv},
			env:        map[string]string{podIPEnv: v4},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP(v4).To4()},
			wantV4:     v4, wantListen: v4, wantFamily: AddressFamilyAuto,
		},
		{
			name:       "IPv6 POD_IP (the default chart on an IPv6 cluster)",
			pfcp:       factory.PFCP{Addr: podIPEnv},
			env:        map[string]string{podIPEnv: v6},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: net.ParseIP(v6)},
			wantV6:     v6, wantListen: v6, wantFamily: AddressFamilyIPv6,
		},
		{
			name:       "POD_IPS, IPv4 primary",
			pfcp:       factory.PFCP{Addr: podIPsEnv},
			env:        map[string]string{podIPsEnv: v4 + "," + v6},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP(v4).To4()},
			wantV4:     v4, wantV6: v6, wantFamily: AddressFamilyAuto,
		},
		{
			name:       "POD_IPS, IPv6 primary",
			pfcp:       factory.PFCP{Addr: podIPsEnv},
			env:        map[string]string{podIPsEnv: v6 + ", " + v4},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: net.ParseIP(v6)},
			wantV4:     v4, wantV6: v6, wantFamily: AddressFamilyAuto,
		},
		{
			name:       "address list, IPv6 preferred for the Node ID",
			pfcp:       factory.PFCP{Addr: v4 + ",[" + v6 + "]", PreferredFamily: AddressFamilyIPv6.String()},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: net.ParseIP(v6)},
			wantV4:     v4, wantV6: v6, wantFamily: AddressFamilyIPv6,
		},
		{
			name:       "explicit FQDN Node ID",
			pfcp:       factory.PFCP{Addr: v6, NodeID: "smf.example.org"},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeFqdn, NodeIdValue: []byte("smf.example.org")},
			wantV6:     v6, wantListen: v6, wantFamily: AddressFamilyIPv6,
		},
		{
			name:       "explicit Node ID from an environment variable",
			pfcp:       factory.PFCP{Addr: podIPsEnv, NodeID: "SMF_NODE_ID"},
			env:        map[string]string{podIPsEnv: v4 + "," + v6, "SMF_NODE_ID": v6},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: net.ParseIP(v6)},
			wantV4:     v4, wantV6: v6, wantFamily: AddressFamilyAuto,
		},
		{
			name:       "IPv4 SMF asked to prefer IPv6 for UPF names",
			pfcp:       factory.PFCP{Addr: v4, PreferredFamily: "IPv6"},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP(v4).To4()},
			wantV4:     v4, wantListen: v4, wantFamily: AddressFamilyIPv6,
		},
		{
			name:       "no address: the 0.0.0.0 default, as before",
			pfcp:       factory.PFCP{},
			wantNodeID: NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: net.IPv4zero.To4()},
			wantV4:     net.IPv4zero.String(), wantListen: net.IPv4zero.String(), wantFamily: AddressFamilyAuto,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			pfcp := tc.pfcp
			local, err := resolvePfcpLocal(&pfcp)
			if err != nil {
				t.Fatalf("resolvePfcpLocal(%+v): %v", tc.pfcp, err)
			}
			if local.nodeID.NodeIdType != tc.wantNodeID.NodeIdType ||
				string(local.nodeID.NodeIdValue) != string(tc.wantNodeID.NodeIdValue) {
				t.Errorf("Node ID = %+v (%s), want %+v (%s)", local.nodeID, local.nodeID.ValueString(),
					tc.wantNodeID, tc.wantNodeID.ValueString())
			}
			checkIP(t, "IPv4 N4 address", local.addrs.IPv4, tc.wantV4)
			checkIP(t, "IPv6 N4 address", local.addrs.IPv6, tc.wantV6)
			if local.resolveFamily != tc.wantFamily {
				t.Errorf("resolve family = %v, want %v", local.resolveFamily, tc.wantFamily)
			}
			if int(pfcp.Port) != int(DefaultPfcpPort) {
				t.Errorf("port = %d, want the default %d", pfcp.Port, DefaultPfcpPort)
			}

			c := &SMFContext{CPNodeID: local.nodeID, N4Addrs: local.addrs, PFCPPort: int(pfcp.Port)}
			listen := c.PFCPListenAddr()
			checkIP(t, "listen address", listen.IP, tc.wantListen)
			if listen.Port != int(DefaultPfcpPort) {
				t.Errorf("listen port = %d, want %d", listen.Port, DefaultPfcpPort)
			}
			fv4, fv6 := c.FSEIDAddrs()
			checkIP(t, "F-SEID IPv4", fv4, tc.wantV4)
			checkIP(t, "F-SEID IPv6", fv6, tc.wantV6)
		})
	}
}

func TestResolvePfcpLocalRejects(t *testing.T) {
	for name, pfcp := range map[string]factory.PFCP{
		"a list entry that is not an IP": {Addr: "10.0.0.1,smf.example.org"},
		"an empty list":                  {Addr: " , "},
		"an unknown family":              {Addr: "10.0.0.2", PreferredFamily: "inet6"},
	} {
		t.Run(name, func(t *testing.T) {
			if local, err := resolvePfcpLocal(&pfcp); err == nil {
				t.Errorf("resolvePfcpLocal(%+v) = %+v, want an error", pfcp, local)
			}
		})
	}
}

// The IPv4 Node ID is the one InitSmfContext set before: type 0 and the To4() value.
func TestResolvePfcpLocalKeepsIPv4NodeID(t *testing.T) {
	const addr = "192.0.2.21"
	pfcp := factory.PFCP{Addr: addr, Port: 8806}
	local, err := resolvePfcpLocal(&pfcp)
	if err != nil {
		t.Fatal(err)
	}
	legacy := NodeID{NodeIdType: 0, NodeIdValue: net.ParseIP(addr).To4()}
	if local.nodeID.NodeIdType != legacy.NodeIdType || string(local.nodeID.NodeIdValue) != string(legacy.NodeIdValue) {
		t.Errorf("Node ID = %+v, want %+v", local.nodeID, legacy)
	}
	c := &SMFContext{CPNodeID: local.nodeID, N4Addrs: local.addrs, PFCPPort: int(pfcp.Port)}
	if got := c.PFCPListenAddr().String(); got != addr+":8806" {
		t.Errorf("listen address = %s, want %s:8806", got, addr)
	}
}

// A context set up without InitSmfContext, as many tests do by setting CPNodeID only, still
// binds and builds its F-SEID from CPNodeID.
func TestN4AddrsFallBackToCPNodeID(t *testing.T) {
	c := &SMFContext{CPNodeID: *NewNodeID("127.0.0.1"), PFCPPort: 8805}
	if got := c.PFCPListenAddr().String(); got != "127.0.0.1:8805" {
		t.Errorf("listen address = %s, want 127.0.0.1:8805", got)
	}
	v4, v6 := c.FSEIDAddrs()
	checkIP(t, "F-SEID IPv4", v4, "127.0.0.1")
	checkIP(t, "F-SEID IPv6", v6, "")

	c = &SMFContext{CPNodeID: *NewNodeID("::1"), PFCPPort: 8805}
	v4, v6 = c.FSEIDAddrs()
	checkIP(t, "F-SEID IPv4", v4, "")
	checkIP(t, "F-SEID IPv6", v6, "::1")

	c = &SMFContext{CPNodeID: *NewNodeID("smf.example.org"), PFCPPort: 8805}
	if got := c.PFCPListenAddr(); got.IP != nil {
		t.Errorf("an FQDN Node ID with no N4 address binds %v, want the wildcard", got)
	}
}

func TestAdapterRelayIP(t *testing.T) {
	tests := []struct {
		addrs N4Addrs
		want  string
	}{
		{N4Addrs{IPv4: net.ParseIP("10.0.0.5")}, "10.0.0.5"},
		{N4Addrs{IPv6: net.ParseIP("fd00::5")}, "fd00::5"},
		{N4Addrs{IPv4: net.ParseIP("10.0.0.5"), IPv6: net.ParseIP("fd00::5")}, ""},
		{N4Addrs{IPv4: net.IPv4zero}, ""},
		{N4Addrs{IPv4: net.ParseIP("127.0.0.1")}, ""},
	}
	for _, tc := range tests {
		c := &SMFContext{N4Addrs: tc.addrs}
		checkIP(t, "relay address for "+tc.addrs.IPv4.String()+"/"+tc.addrs.IPv6.String(), c.AdapterRelayIP(), tc.want)
	}
}

func TestParseUpfTransportFamily(t *testing.T) {
	const upfV6, upfV4, upfAuto = "upf-v6.example", "upf-v4.example", "upf-auto.example"
	got, err := parseUpfTransportFamily(map[string]string{upfV6: "ipv6", upfV4: "IPv4", upfAuto: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]AddressFamily{upfV6: AddressFamilyIPv6, upfV4: AddressFamilyIPv4}
	if len(got) != len(want) || got[upfV6] != want[upfV6] || got[upfV4] != want[upfV4] {
		t.Errorf("parseUpfTransportFamily = %v, want %v", got, want)
	}
	if _, err := parseUpfTransportFamily(map[string]string{upfV6: "both"}); err == nil {
		t.Error("an unknown family was accepted")
	}
}

func checkIP(t *testing.T, what string, got net.IP, want string) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Errorf("%s = %v, want none", what, got)
		}
		return
	}
	if !got.Equal(net.ParseIP(want)) {
		t.Errorf("%s = %v, want %s", what, got, want)
	}
}
