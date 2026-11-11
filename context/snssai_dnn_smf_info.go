// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"

	"github.com/omec-project/openapi/v2/models"
)

// SnssaiSmfInfo records the SMF S-NSSAI related information
type SnssaiSmfInfo struct {
	DnnInfos map[string]*SnssaiSmfDnnInfo
	PlmnId   models.PlmnId
	Snssai   SNssai
}

// SnssaiSmfDnnInfo records the SMF per S-NSSAI DNN information
type SnssaiSmfDnnInfo struct {
	UeIPAllocator *IPAllocator
	DNS           DNS
	MTU           uint16

	// UeIpv6Allocator hands out the DNN's IPv6 prefixes (ueSubnetIpv6), nil when the DNN has no IPv6
	// pool. PCSCFIPv6 is the DNN's P-CSCF IPv6 address (pcscfIpv6), nil when it has none. Both are
	// omitted from the stored session when unset, so that an IPv4 DNN's session is stored as before.
	UeIpv6Allocator *Ipv6PrefixAllocator `json:"UeIpv6Allocator,omitempty" yaml:"ueIpv6Allocator,omitempty" bson:"UeIpv6Allocator,omitempty"`
	PCSCFIPv6       net.IP               `json:"PCSCFIPv6,omitempty" yaml:"pcscfIPv6,omitempty" bson:"PCSCFIPv6,omitempty"`
}

// HasIpv4Pool reports whether the DNN has a usable IPv4 pool.
func (d *SnssaiSmfDnnInfo) HasIpv4Pool() bool {
	return d != nil && d.UeIPAllocator != nil && d.UeIPAllocator.g != nil && d.UeIPAllocator.ipNetwork != nil
}

// HasIpv6Pool reports whether the DNN has a usable IPv6 pool.
func (d *SnssaiSmfDnnInfo) HasIpv6Pool() bool {
	return d != nil && d.UeIpv6Allocator.hasPool()
}

type DNS struct {
	IPv4Addr net.IP
	IPv6Addr net.IP
}
