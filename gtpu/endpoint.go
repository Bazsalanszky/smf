// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package gtpu

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/omec-project/smf/logger"
)

// maxDatagram bounds one read. A router solicitation is under 100 octets; anything larger than an
// Ethernet frame is not something the endpoint acts on.
const maxDatagram = 2048

// GPDUHandler is called for every G-PDU the endpoint receives, with its TEID, the T-PDU after any
// extension headers, and the sender. It runs on the endpoint's read loop: it must not block, and the
// payload is valid only until it returns.
type GPDUHandler func(teid uint32, payload []byte, from netip.AddrPort)

// Endpoint is a GTP-U endpoint on one UDP socket per local address. It answers Echo Requests itself
// and hands G-PDUs to its handler; every other message is dropped.
type Endpoint struct {
	handler GPDUHandler
	done    chan struct{}
	conns   []*net.UDPConn
	wg      sync.WaitGroup
	once    sync.Once
}

// Listen opens one socket per address, on port (Port in production; 0 picks a free one). At least
// one address is required, and at most one per family is useful: a reply goes out on the socket of
// the destination's family.
func Listen(addrs []netip.Addr, port uint16, handler GPDUHandler) (*Endpoint, error) {
	if len(addrs) == 0 {
		return nil, errors.New("GTP-U endpoint: no local address")
	}
	e := &Endpoint{handler: handler, done: make(chan struct{})}
	for _, addr := range addrs {
		network := "udp4"
		if addr.Is6() && !addr.Is4In6() {
			network = "udp6"
		}
		conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr.Unmap(), port)))
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("GTP-U endpoint on %s: %w", netip.AddrPortFrom(addr, port), err)
		}
		e.conns = append(e.conns, conn)
	}
	for _, conn := range e.conns {
		e.wg.Add(1)
		go e.serve(conn)
	}
	return e, nil
}

// LocalAddrs returns the address and port each socket is bound to, in the order Listen was given.
func (e *Endpoint) LocalAddrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(e.conns))
	for _, conn := range e.conns {
		out = append(out, conn.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	return out
}

// Close closes the sockets and waits for the read loops to end. It is safe to call more than once.
func (e *Endpoint) Close() {
	e.once.Do(func() {
		close(e.done)
		for _, conn := range e.conns {
			if err := conn.Close(); err != nil {
				logger.GtpuLog.Debugf("GTP-U endpoint close: %v", err)
			}
		}
	})
	e.wg.Wait()
}

// SendGPDU sends payload as a G-PDU to teid at dst, from the socket of dst's family.
func (e *Endpoint) SendGPDU(dst netip.AddrPort, teid uint32, payload []byte) error {
	conn := e.connFor(dst.Addr())
	if conn == nil {
		return fmt.Errorf("GTP-U endpoint has no socket of the family of %s", dst.Addr())
	}
	_, err := conn.WriteToUDPAddrPort(NewGPDU(teid, payload), dst)
	return err
}

// HasFamily reports whether the endpoint has a socket that can send to addr.
func (e *Endpoint) HasFamily(addr netip.Addr) bool {
	return e.connFor(addr) != nil
}

func (e *Endpoint) connFor(addr netip.Addr) *net.UDPConn {
	want6 := addr.Is6() && !addr.Is4In6()
	for _, conn := range e.conns {
		local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		if (local.Is6() && !local.Is4In6()) == want6 {
			return conn
		}
	}
	return nil
}

func (e *Endpoint) serve(conn *net.UDPConn) {
	defer e.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.GtpuLog.Warnf("GTP-U endpoint %s: read: %v", conn.LocalAddr(), err)
			continue
		}
		e.receive(conn, buf[:n], from)
	}
}

func (e *Endpoint) receive(conn *net.UDPConn, b []byte, from netip.AddrPort) {
	msg, err := Parse(b)
	if err != nil {
		logger.GtpuLog.Debugf("GTP-U from %s dropped: %v", from, err)
		return
	}
	switch msg.Type {
	case MsgTypeEchoRequest:
		if _, err := conn.WriteToUDPAddrPort(NewEchoResponse(msg.Seq), from); err != nil {
			logger.GtpuLog.Warnf("GTP-U Echo Response to %s: %v", from, err)
		}
	case MsgTypeGPDU:
		if e.handler != nil {
			e.handler(msg.TEID, msg.Payload, from)
		}
	default:
		logger.GtpuLog.Debugf("GTP-U message type %d from %s (TEID %#x) ignored", msg.Type, from, msg.TEID)
	}
}
