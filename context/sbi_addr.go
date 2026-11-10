// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"cmp"
	"net"

	"github.com/omec-project/openapi/v2/models"
	openapiutils "github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/sbiaddr"
)

// SbiAddrs classifies the SMF's register hosts: RegisterIPv4 (an IPv4 address or a host
// name, as before) and RegisterIPv6. The fields stay the source of truth, so code and
// tests that set them directly keep working.
func (s *SMFContext) SbiAddrs() sbiaddr.RegisterAddrs {
	addrs, err := sbiaddr.ParseRegister(s.RegisterIPv4, s.RegisterIPv6)
	if err != nil {
		logger.CtxLog.Warnf("SBI register address: %v; using the valid part", err)
	}
	return addrs
}

// GetSbiUri is the SMF's own base URI, scheme://host:port with an IPv6 host in brackets.
// Callback URIs given to peers are built from it.
func (s *SMFContext) GetSbiUri() string {
	return s.SbiAddrs().URI(string(s.URIScheme), s.SBIPort, s.SbiPreference)
}

// PeerServiceURI returns the base URI of service, a service of the discovered peer
// profile. It is the service's apiPrefix, or, when the peer registered none, a URI built
// from its FQDN or its IPv4 or IPv6 endpoint (see openapiutils.NFServiceURI), with the
// SMF's preferred family.
func PeerServiceURI(profile *models.NFProfileDiscovery, service *models.NFService) string {
	return openapiutils.NFServiceURI(profile, service, SMF_Self().SbiPreference == sbiaddr.PreferIPv6)
}

// resolveSbiAddrs sets the SBI register addresses, the family preference and the binding
// host from the sbi configuration. Problems are logged; the result is always usable.
//
// registerIPv4 and registerIPv6 may hold an address, a host name or the name of an
// environment variable, and each address goes to the field of its own family. As before,
// a POD_IP that is not set falls back to the host's own address (now per family), and an
// empty result to SMF_DEFAULT_IPV4. interfaceAddrs is net.InterfaceAddrs outside tests.
func (s *SMFContext) resolveSbiAddrs(sbi *factory.Sbi, interfaceAddrs func() ([]net.Addr, error)) {
	addrs, err := sbiaddr.ResolveRegister(sbi.RegisterIPv4, sbi.RegisterIPv6)
	if err != nil {
		logger.CtxLog.Warnf("SBI register address: %v", err)
	}
	v4PodIP, v6PodIP := sbi.RegisterIPv4 == sbiaddr.EnvPodIP, sbi.RegisterIPv6 == sbiaddr.EnvPodIP
	if addrs.Empty() && (v4PodIP || v6PodIP) {
		if ifAddrs, ierr := interfaceAddrs(); ierr == nil {
			local := sbiaddr.FromInterfaceAddrs(ifAddrs)
			if v4PodIP {
				addrs.IPv4 = local.IPv4
			}
			if v6PodIP {
				addrs.IPv6 = local.IPv6
			}
			if !addrs.Empty() {
				logger.CtxLog.Warnf("POD_IP is not set; falling back to local IP [%s] [%s] for the SBI register address",
					addrs.IPv4, addrs.IPv6)
			}
		}
	}
	if addrs.Empty() {
		if sbi.RegisterIPv4 != "" || sbi.RegisterIPv6 != "" {
			logger.CtxLog.Warnln("no usable SBI register address; falling back to default RegisterIPv4", factory.SMF_DEFAULT_IPV4)
		}
		addrs.IPv4 = factory.SMF_DEFAULT_IPV4
	}
	if addrs.FQDN != "" && addrs.IPv4 != "" {
		logger.CtxLog.Warnf("SBI register address: registering FQDN %s, not IPv4 %s", addrs.FQDN, addrs.IPv4)
	}
	s.RegisterIPv4 = cmp.Or(addrs.FQDN, addrs.IPv4)
	s.RegisterIPv6 = addrs.IPv6

	if s.SbiPreference, err = sbiaddr.ParsePreference(sbi.PreferredFamily); err != nil {
		logger.CtxLog.Warnf("SBI preferredFamily: %v; using IPv4", err)
	}
	logger.CtxLog.Infof("sbi lb - smf RegisterIPv4 [%s] RegisterIPv6 [%s], preferred family %s",
		s.RegisterIPv4, s.RegisterIPv6, s.SbiPreference)

	if sbi.BindingAddr == "" && sbi.BindingIPv4 == "" {
		logger.CtxLog.Warnln("error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default")
	}
	if s.BindingIPv4, err = sbiaddr.BindHost(sbi.BindingAddr, sbi.BindingIPv4); err != nil {
		logger.CtxLog.Warnf("SBI binding address: %v", err)
	}
	logger.CtxLog.Infof("SBI binding address [%s]", s.BindingIPv4)
}
