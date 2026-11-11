// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

// ProtocolConfigurationOptions
package context

type ProtocolConfigurationOptions struct {
	DNSIPv4Request     bool
	DNSIPv6Request     bool
	IPv4LinkMTURequest bool
	PCSCFIPv4Request   bool
	// Omitted when false, so that a session that did not ask is stored as before this field existed.
	PCSCFIPv6Request bool `json:"PCSCFIPv6Request,omitempty" yaml:"pcscfIPv6Request,omitempty" bson:"PCSCFIPv6Request,omitempty"`
}
