// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

// Package ra answers the router solicitations of IPv6 PDU sessions and sends their router
// advertisements, over the SMF's own GTP-U endpoint (TS 23.501 clause 5.8.2.2.2, TS 29.061 clause
// 11.2.1.3.1, TS 29.244 clause 5.3).
//
// The UPF forwards a session's router solicitations to the SMF with the UP2CP PDR and FAR, as
// G-PDUs whose TEID is the session's local SEID on that UPF (context.RouterAdvertisementTEID). The
// SMF answers each with a router advertisement carrying the session's /64, sent as a G-PDU to the
// CP2UP PDR's F-TEID, which forwards it to the UE with the session's downlink FAR. One unsolicited
// advertisement also goes out once the access tunnel is up, for a UE that does not solicit.
package ra

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/gtpu"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/ndp"
)

// The advertisement's fields (docs/lab/open5gs-ra-path.md section 8). The router lifetime is the
// Open5GS SMF's; RFC 8319 allows it. The prefix is valid and preferred for as long as the session
// holds it, which is the session's lifetime: it is released with the session, not aged.
const (
	curHopLimit    = 64
	routerLifetime = 64800
)

// maxInFlight bounds the solicitations being answered at once. Answering one waits for the
// session's lock, which a PFCP exchange can hold for seconds; a solicitation beyond the bound is
// dropped, and the UE solicits again.
const maxInFlight = 64

// Service is a running router advertisement service.
type Service struct {
	endpoint *gtpu.Endpoint
	inFlight chan struct{}
	wg       sync.WaitGroup
	// lookup finds the session of a solicitation's TEID; context.GetSMContextBySEID outside
	// tests.
	lookup func(seid uint64) *context.SMContext
	// upfPort is the port advertisements are sent to: gtpu.Port outside tests.
	upfPort uint16
	// ready is closed once endpoint is set. The endpoint serves from inside gtpu.Listen, so a
	// solicitation can arrive before Listen has returned it.
	ready chan struct{}
}

// Start runs the service on the endpoint cfg configures, and makes sessions established from now
// on get the router advertisement rules. Stop undoes both.
func Start(cfg *factory.CPGtpu) (*Service, error) {
	addrs, err := ParseAddrs(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("cpGtpu.addr: %w", err)
	}
	family, err := context.ParseAddressFamily(cfg.PreferredFamily)
	if err != nil {
		return nil, fmt.Errorf("cpGtpu.preferredFamily: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = gtpu.Port
	}

	s, err := listen(addrs, port, gtpu.Port, context.GetSMContextBySEID)
	if err != nil {
		return nil, err
	}
	endpoint := s.endpoint

	advertised := &context.CPGtpuAddrs{PreferIPv6: family == context.AddressFamilyIPv6}
	for _, addr := range addrs {
		if addr.Is4() {
			advertised.IPv4 = net.IP(addr.AsSlice())
		} else {
			advertised.IPv6 = net.IP(addr.AsSlice())
		}
	}
	context.SetCPGtpuEndpoint(advertised)
	context.RouterAdvertisementSender = s.sendUnsolicited
	logger.GtpuLog.Infof("router advertisement service on %v (IPv4 %v, IPv6 %v, preferring %s)",
		endpoint.LocalAddrs(), advertised.IPv4, advertised.IPv6, family)
	return s, nil
}

// listen opens the endpoint of a service that finds sessions with lookup and sends to UPFs on
// upfPort.
func listen(addrs []netip.Addr, port, upfPort uint16, lookup func(uint64) *context.SMContext) (*Service, error) {
	s := &Service{
		inFlight: make(chan struct{}, maxInFlight),
		lookup:   lookup,
		upfPort:  upfPort,
		ready:    make(chan struct{}),
	}
	endpoint, err := gtpu.Listen(addrs, port, s.handleGPDU)
	if err != nil {
		close(s.ready)
		s.wg.Wait()
		return nil, err
	}
	s.endpoint = endpoint
	close(s.ready)
	return s, nil
}

// Stop stops the service; sessions established afterwards get no router advertisement rules.
func (s *Service) Stop() {
	context.RouterAdvertisementSender = nil
	context.SetCPGtpuEndpoint(nil)
	s.endpoint.Close()
	s.wg.Wait()
}

// ParseAddrs reads the endpoint's addresses: one IP address, or one per family separated by a
// comma, or the name of an environment variable holding either. Brackets around an IPv6 address
// are allowed. An IPv4-mapped address is IPv4. The unspecified address is refused: the UPFs are
// told the address to send to, so it must be one.
func ParseAddrs(value string) ([]netip.Addr, error) {
	if env := os.Getenv(value); env != "" {
		value = env
	}
	var v4, v6 netip.Addr
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(entry), "["), "]")
		if entry == "" {
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", entry)
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("%q: an address with a zone cannot be advertised", entry)
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			return nil, fmt.Errorf("%q: the unspecified address cannot be advertised", entry)
		}
		switch {
		case addr.Is4() && !v4.IsValid():
			v4 = addr
		case addr.Is6() && !v6.IsValid():
			v6 = addr
		default:
			return nil, fmt.Errorf("%q: more than one address of its family", entry)
		}
	}
	var out []netip.Addr
	for _, addr := range []netip.Addr{v4, v6} {
		if addr.IsValid() {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no address in %q", value)
	}
	return out, nil
}

// handleGPDU runs on the endpoint's read loop. It checks the packet is a router solicitation
// there, where the payload is valid, and answers it on a goroutine of its own, which waits for the
// session's lock.
func (s *Service) handleGPDU(teid uint32, payload []byte, from netip.AddrPort) {
	rs, err := ndp.ParseRouterSolicitation(payload)
	if err != nil {
		logger.GtpuLog.Debugf("G-PDU from %s with TEID %#x dropped: not a router solicitation: %v", from, teid, err)
		return
	}
	select {
	case s.inFlight <- struct{}{}:
	default:
		logger.GtpuLog.Warnf("router solicitation from %s (TEID %#x) dropped: %d being answered", from, teid, maxInFlight)
		return
	}
	s.wg.Add(1)
	go func() {
		defer func() {
			<-s.inFlight
			s.wg.Done()
		}()
		s.answer(teid, rs, from)
	}()
}

// answer sends the router advertisement that answers rs, which arrived with teid from a UPF.
func (s *Service) answer(teid uint32, rs *ndp.RouterSolicitation, from netip.AddrPort) {
	<-s.ready
	if s.endpoint == nil {
		return
	}
	smContext := s.lookup(uint64(teid))
	if smContext == nil {
		logger.GtpuLog.Warnf("router solicitation from %s with TEID %#x: no session has that local SEID", from, teid)
		return
	}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	path, err := smContext.RouterAdvertisementPath(s.endpoint.HasFamily)
	if err != nil {
		smContext.SubPduSessLog.Warnf("router solicitation from %s not answered: %v", rs.Source, err)
		return
	}
	if !path.Rules.ForwardsToAccess() {
		// The access tunnel is not up yet: the unsolicited advertisement goes to all nodes, the
		// soliciting UE included, once it is (context.SMContext.AdvertiseIpv6Prefix).
		smContext.SubPduSessLog.Infof("router solicitation from %s not answered yet: the access tunnel is not up; "+
			"the unsolicited advertisement follows when it is", rs.Source)
		return
	}
	if path.SMFTEID != teid {
		// The session's rules on this UPF name another TEID: the solicitation was forwarded by
		// rules the session no longer has.
		smContext.SubPduSessLog.Warnf("router solicitation with TEID %#x not answered: the session's rules name TEID %#x",
			teid, path.SMFTEID)
		return
	}
	// To the solicitation's source, or to all nodes when it has none yet (RFC 4861 clause 6.2.6).
	dst := rs.Source
	if dst.IsUnspecified() {
		dst = ndp.AllNodes
	}
	if err := s.send(path, dst); err != nil {
		smContext.SubPduSessLog.Errorf("router advertisement to %s via UPF %s: %v", dst, path.UPF, err)
		return
	}
	smContext.SubPduSessLog.Infof("router advertisement of %s to %s via UPF %s TEID %#x, answering a solicitation",
		path.Prefix, dst, path.UPF, path.UPFTEID)
}

// sendUnsolicited is context.RouterAdvertisementSender: the one unsolicited advertisement, once the
// access tunnel is up. Its caller holds the session's lock.
func (s *Service) sendUnsolicited(smContext *context.SMContext, prefix netip.Prefix, _ context.InterfaceIdentifier) {
	path, err := smContext.RouterAdvertisementPath(s.endpoint.HasFamily)
	if err != nil {
		smContext.SubPduSessLog.Warnf("no unsolicited router advertisement of %s: %v", prefix, err)
		return
	}
	if err := s.send(path, ndp.AllNodes); err != nil {
		smContext.SubPduSessLog.Errorf("unsolicited router advertisement via UPF %s: %v", path.UPF, err)
		return
	}
	smContext.SubPduSessLog.Infof("unsolicited router advertisement of %s via UPF %s TEID %#x",
		path.Prefix, path.UPF, path.UPFTEID)
}

func (s *Service) send(path *context.RouterAdvertisementPath, dst netip.Addr) error {
	pkt, err := Advertisement(path).Marshal(RouterLinkLocal(path.Iid), dst)
	if err != nil {
		return err
	}
	return s.endpoint.SendGPDU(netip.AddrPortFrom(path.UPF, s.upfPort), path.UPFTEID, pkt)
}

// Advertisement is the router advertisement of the session path names: its /64, on-link flag clear
// (TS 29.061 clause 11.2.1.3.1: the UE sends everything to the network), autonomous flag set, and
// the DNN's MTU when one is configured.
func Advertisement(path *context.RouterAdvertisementPath) *ndp.RouterAdvertisement {
	ra := &ndp.RouterAdvertisement{
		Prefix:            path.Prefix,
		CurHopLimit:       curHopLimit,
		RouterLifetime:    routerLifetime,
		ValidLifetime:     ndp.InfiniteLifetime,
		PreferredLifetime: ndp.InfiniteLifetime,
		Autonomous:        true,
	}
	if path.LinkMTU >= ndp.MinIPv6MTU {
		ra.MTU = uint32(path.LinkMTU)
	}
	return ra
}

// RouterLinkLocal is the address the SMF sends router advertisements from: fe80::1, as the Open5GS
// SMF does, or fe80::2 for the UE whose interface identifier would make fe80::1 its own address.
func RouterLinkLocal(ueIid context.InterfaceIdentifier) netip.Addr {
	router := context.InterfaceIdentifier{7: 1}
	if ueIid == router {
		router[7] = 2
	}
	return ndp.LinkLocal(router)
}
