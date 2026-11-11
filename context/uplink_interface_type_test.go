// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import "testing"

// On a path of two UPFs, N3 3GPP Access is the first one's source and N6 the anchor's destination.
// The hop between them is N9, for which the SMF sends no interface type: the IE is optional, and
// one of the N3 or N6 values there would be wrong.
func TestUplinkInterfaceTypesFollowThePath(t *testing.T) {
	first, anchor := NewDataPathNode(), NewDataPathNode()
	first.AddNext(anchor)
	anchor.AddPrev(first)

	for _, tc := range []struct {
		name             string
		node             *DataPathNode
		wantSrc, wantDst *uint8
	}{
		{"first UPF", first, ifaceType(InterfaceTypeN33GPPAccess), nil},
		{"anchor", anchor, nil, ifaceType(InterfaceTypeN6)},
		{"single UPF", NewDataPathNode(), ifaceType(InterfaceTypeN33GPPAccess), ifaceType(InterfaceTypeN6)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.node.UplinkSourceInterfaceType(); !sameIfaceType(got, tc.wantSrc) {
				t.Errorf("UplinkSourceInterfaceType() = %v, want %v", ifaceTypeValue(got), ifaceTypeValue(tc.wantSrc))
			}
			if got := tc.node.UplinkDestinationInterfaceType(); !sameIfaceType(got, tc.wantDst) {
				t.Errorf("UplinkDestinationInterfaceType() = %v, want %v", ifaceTypeValue(got), ifaceTypeValue(tc.wantDst))
			}
		})
	}

	// Each call hands out its own value: a rule that changed its copy would change every rule's.
	if a, b := first.UplinkSourceInterfaceType(), first.UplinkSourceInterfaceType(); a == b {
		t.Error("UplinkSourceInterfaceType returns a shared pointer")
	}
}

func ifaceType(v uint8) *uint8 { return &v }

func sameIfaceType(a, b *uint8) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func ifaceTypeValue(p *uint8) any {
	if p == nil {
		return nil
	}
	return *p
}
