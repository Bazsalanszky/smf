// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"net"
	"strconv"
)

// HostPort returns the "host:port" string to listen on or dial. It uses
// net.JoinHostPort, which brackets an IPv6 literal ("[2001:db8::1]:8805");
// fmt.Sprintf("%s:%d") did not, and net.Listen / net.ResolveUDPAddr then
// rejected the result with "too many colons in address". IPv4 addresses,
// hostnames and an empty host give the same string as before. A host that is
// already bracketed is unwrapped first so it is not bracketed twice.
func HostPort(host string, port int) string {
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
