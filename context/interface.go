// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package context

const (
	SourceInterfaceAccess uint8 = iota
	SourceInterfaceCore
)

const (
	DestinationInterfaceAccess uint8 = iota
	DestinationInterfaceCore
	DestinationInterfaceSgiLanN6Lan
)

// 3GPP Interface Type values (TS 29.244 clause 8.2.118). A PDI or a set of forwarding parameters
// may carry one next to its Source or Destination Interface, which only says Access or Core.
const (
	InterfaceTypeN33GPPAccess uint8 = 11
	InterfaceTypeN6           uint8 = 17
)

type SourceInterface struct {
	InterfaceValue uint8 // 0x00001111
}

type DestinationInterface struct {
	InterfaceValue uint8 // 0x00001111
}
