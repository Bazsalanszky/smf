// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/openapi/v2/models"
)

const (
	tV4   = nasMessage.PDUSessionTypeIPv4
	tV6   = nasMessage.PDUSessionTypeIPv6
	tV4V6 = nasMessage.PDUSessionTypeIPv4IPv6
	tEth  = nasMessage.PDUSessionTypeEthernet
	tUns  = nasMessage.PDUSessionTypeUnstructured
	c50   = nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed
	c51   = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed

	noType = "no type"
)

func subscription(def models.PduSessionType, allowed ...models.PduSessionType) models.PduSessionTypes {
	return models.PduSessionTypes{DefaultSessionType: &def, AllowedSessionTypes: allowed}
}

var (
	subV4   = subscription(models.PDUSESSIONTYPE_IPV4, models.PDUSESSIONTYPE_IPV4) // webconsole's default
	subV6   = subscription(models.PDUSESSIONTYPE_IPV6)
	subV4V6 = subscription(models.PDUSESSIONTYPE_IPV4_V6)
	// Both families, each on its own, defaulting to IPv4.
	subV4AndV6 = subscription(models.PDUSESSIONTYPE_IPV4, models.PDUSESSIONTYPE_IPV6)
	subEth     = subscription(models.PDUSESSIONTYPE_ETHERNET)
)

type pools struct{ v4, v6 bool }

var (
	poolV4   = pools{v4: true}
	poolV6   = pools{v6: true}
	poolBoth = pools{v4: true, v6: true}
	poolNone = pools{}
)

// want is the expected selection: a type and accept cause, or a rejection key.
type want struct {
	typ    uint8
	cause  uint8
	reject PDUSessionTypeRefusal
}

func accept(typ uint8) want               { return want{typ: typ} }
func acceptWith(typ, cause uint8) want    { return want{typ: typ, cause: cause} }
func refuse(r PDUSessionTypeRefusal) want { return want{reject: r} }
func (w want) String() string {
	return fmt.Sprintf("type %d cause %d (%s)", w.typ, w.cause, w.reject)
}

func got(s PDUSessionTypeSelection) want {
	return want{typ: s.Type, cause: s.AcceptCause, reject: s.Refusal}
}

// Every requested type against every subscription and pool combination.
func TestSelectPDUSessionType(t *testing.T) {
	r50, r51, r28, r26 := refuse(RefuseIPv4OnlyAllowed), refuse(RefuseIPv6OnlyAllowed),
		refuse(RefuseUnknownPDUSessionType), refuse(RefuseNoPool)

	subs := []struct {
		name string
		sub  models.PduSessionTypes
	}{{"sub v4", subV4}, {"sub v6", subV6}, {"sub v4v6", subV4V6}, {"sub v4+v6", subV4AndV6}, {"sub eth", subEth}}
	poolSets := []struct {
		name string
		p    pools
	}{{"pool v4", poolV4}, {"pool v6", poolV6}, {"pools v4+v6", poolBoth}, {"no pool", poolNone}}

	// expected[request][subscription][pools], in the order of subs and poolSets.
	expected := map[string][5][4]want{
		nameIPv4: {
			{accept(tV4), r26, accept(tV4), r26}, // sub v4
			{r51, r51, r51, r51},                 // sub v6: IPv6 only allowed, pool or not
			{accept(tV4), r51, accept(tV4), r26}, // sub v4v6
			{accept(tV4), r51, accept(tV4), r26}, // sub v4+v6
			{r28, r28, r28, r28},                 // sub eth
		},
		nameIPv6: {
			{r50, r50, r50, r50},
			{r26, accept(tV6), accept(tV6), r26},
			{r50, accept(tV6), accept(tV6), r26},
			{r50, accept(tV6), accept(tV6), r26},
			{r28, r28, r28, r28},
		},
		nameIPv4v6: {
			{acceptWith(tV4, c50), r26, acceptWith(tV4, c50), r26},
			{r26, acceptWith(tV6, c51), acceptWith(tV6, c51), r26},
			{acceptWith(tV4, c50), acceptWith(tV6, c51), accept(tV4V6), r26},
			{acceptWith(tV4, c50), acceptWith(tV6, c51), accept(tV4V6), r26},
			{r28, r28, r28, r28},
		},
		"Ethernet": {
			{r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28},
		},
		"Unstructured": {
			{r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28}, {r28, r28, r28, r28},
		},
		noType: {
			// No type requested: the default type, reduced to what is offered, never with a cause.
			{accept(tV4), r26, accept(tV4), r26},
			{r26, accept(tV6), accept(tV6), r26},
			{accept(tV4), accept(tV6), accept(tV4V6), r26},
			{accept(tV4), accept(tV6), accept(tV4), r26},
			{r28, r28, r28, r28},
		},
	}
	requests := map[string]struct {
		typ     uint8
		present bool
	}{
		nameIPv4: {tV4, true}, nameIPv6: {tV6, true}, nameIPv4v6: {tV4V6, true},
		"Ethernet": {tEth, true}, "Unstructured": {tUns, true}, noType: {0, false},
	}

	for reqName, rows := range expected {
		req := requests[reqName]
		for i, s := range subs {
			for j, p := range poolSets {
				name := reqName + "/" + s.name + "/" + p.name
				sel := SelectPDUSessionType(req.typ, req.present, s.sub, p.p.v4, p.p.v6)
				if g, w := got(sel), rows[i][j]; g != w {
					t.Errorf("%s: got %s, want %s (%s)", name, g, w, sel.Reason)
				}
				if sel.Refusal != NotRefused && sel.Type != 0 {
					t.Errorf("%s: a refusal selected type %d", name, sel.Type)
				}
			}
		}
	}
}

func TestSelectPDUSessionTypeEdgeCases(t *testing.T) {
	// A reserved type value.
	if sel := SelectPDUSessionType(7, true, subV4V6, true, true); sel.Refusal != RefuseUnknownPDUSessionType {
		t.Errorf("type 7: %+v, want #28", sel)
	}
	// A request naming a type for a subscription without a default type is refused with #50, as
	// before the selection existed.
	noDefault := models.PduSessionTypes{AllowedSessionTypes: []models.PduSessionType{models.PDUSESSIONTYPE_IPV4}}
	if sel := SelectPDUSessionType(tV4, true, noDefault, true, false); sel.Refusal != RefuseIPv4OnlyAllowed {
		t.Errorf("no default type: %+v, want #50", sel)
	}
	// Without a type and without a default type the session is IPv4, as before; IPv6 only on a
	// DNN that has no IPv4 pool.
	for _, tc := range []struct {
		p    pools
		want uint8
	}{{poolV4, tV4}, {poolBoth, tV4}, {poolNone, tV4}, {poolV6, tV6}} {
		if sel := SelectPDUSessionType(0, false, models.PduSessionTypes{}, tc.p.v4, tc.p.v6); sel.Type != tc.want {
			t.Errorf("no type, no subscription types, pools %+v: %+v, want type %d", tc.p, sel, tc.want)
		}
	}
	// The default type counts as allowed even when allowedSessionTypes omits it (TS 29.503).
	if sel := SelectPDUSessionType(tV6, true, subscription(models.PDUSESSIONTYPE_IPV6, models.PDUSESSIONTYPE_IPV4),
		true, true); sel.Type != tV6 {
		t.Errorf("IPv6 requested, IPv6 the default only: %+v", sel)
	}
}

// The IPv4 case the SMF handled before the selection existed, byte for byte: webconsole's default
// subscription, an IPv4 pool, and a UE asking for IPv4, for IPv4v6 or for nothing.
func TestSelectPDUSessionTypeKeepsIPv4(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     uint8
		present bool
		want    want
	}{
		{nameIPv4, tV4, true, accept(tV4)},
		{nameIPv4v6, tV4V6, true, acceptWith(tV4, c50)},
		{noType, 0, false, accept(tV4)},
	} {
		// An IPv6 pool on the DNN changes nothing for a subscriber allowed IPv4 only.
		for _, v6Pool := range []bool{false, true} {
			if g := got(SelectPDUSessionType(tc.req, tc.present, subV4, true, v6Pool)); g != tc.want {
				t.Errorf("%s (IPv6 pool %t): got %s, want %s", tc.name, v6Pool, g, tc.want)
			}
		}
	}
}

// HandlePDUSessionEstablishmentRequest applies the selection: the type and the accept's cause on a
// downgrade, or a PDUSessionTypeError carrying the refusal.
func TestHandlePDUSessionEstablishmentRequestSelectsTheType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     uint8 // 0 for no PDU session type IE
		sub     models.PduSessionTypes
		dnn     *SnssaiSmfDnnInfo
		want    want
		wantErr bool
	}{
		{"IPv4v6 on a dual-stack DNN", tV4V6, subV4V6, dualStackDnn(t, "172.250.0.0/24", testUeIpv6Pool), accept(tV4V6), false},
		{"IPv4v6 on an IPv6 DNN", tV4V6, subV4V6, dualStackDnn(t, "", testUeIpv6Pool), acceptWith(tV6, c51), false},
		{"IPv6 for an IPv4 subscriber", tV6, subV4, dualStackDnn(t, "172.250.0.0/24", testUeIpv6Pool), refuse(RefuseIPv4OnlyAllowed), true},
		{"no type", 0, subV6, dualStackDnn(t, "172.250.0.0/24", testUeIpv6Pool), accept(tV6), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := &SMContext{
				DNNInfo:                      tc.dnn,
				DnnConfiguration:             models.DnnConfiguration{PduSessionTypes: tc.sub},
				ProtocolConfigurationOptions: &ProtocolConfigurationOptions{},
			}
			smContext.initLogTags()
			req := nasMessage.NewPDUSessionEstablishmentRequest(0)
			req.SetPDUSessionID(5)
			if tc.req != 0 {
				req.PDUSessionType = nasType.NewPDUSessionType(nasMessage.PDUSessionEstablishmentRequestPDUSessionTypeType)
				req.SetPDUSessionTypeValue(tc.req)
			}
			err := smContext.HandlePDUSessionEstablishmentRequest(req)
			var typeErr *PDUSessionTypeError
			if tc.wantErr {
				if !errors.As(err, &typeErr) || typeErr.Refusal != tc.want.reject {
					t.Fatalf("error = %v, want a refusal %s", err, tc.want.reject)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if g := (want{typ: smContext.SelectedPDUSessionType, cause: smContext.EstAcceptCause5gSMValue}); g != tc.want {
				t.Errorf("got %s, want %s", g, tc.want)
			}
		})
	}
}

// The subscriptions webconsole writes, per the DNN's pools: IPv4 pool only, IPV4 / [IPV4]; both
// pools, IPV4 / [IPV4, IPV6, IPV4V6]; IPv6 pool only, IPV6 / [IPV6]. An allowed IPV4V6 allows
// IPv4 as well, and IPv4 is refused on a DNN that has no IPv4 pool.
func TestSelectPDUSessionTypeForWebconsoleSubscriptions(t *testing.T) {
	dual := subscription(models.PDUSESSIONTYPE_IPV4,
		models.PDUSESSIONTYPE_IPV4, models.PDUSESSIONTYPE_IPV6, models.PDUSESSIONTYPE_IPV4_V6)
	v6Only := subscription(models.PDUSESSIONTYPE_IPV6, models.PDUSESSIONTYPE_IPV6)
	for _, tc := range []struct {
		name    string
		sub     models.PduSessionTypes
		p       pools
		req     uint8
		present bool
		want    want
	}{
		{"dual: IPv4", dual, poolBoth, tV4, true, accept(tV4)},
		{"dual: IPv6", dual, poolBoth, tV6, true, accept(tV6)},
		{"dual: IPv4v6", dual, poolBoth, tV4V6, true, accept(tV4V6)},
		{"dual: no type", dual, poolBoth, 0, false, accept(tV4)},
		{"IPv6 DNN: IPv6", v6Only, poolV6, tV6, true, accept(tV6)},
		{"IPv6 DNN: IPv4v6", v6Only, poolV6, tV4V6, true, acceptWith(tV6, c51)},
		{"IPv6 DNN: IPv4", v6Only, poolV6, tV4, true, refuse(RefuseIPv6OnlyAllowed)},
		{"IPv6 DNN: no type", v6Only, poolV6, 0, false, accept(tV6)},
		// An IPV4V6 subscription on a DNN that has only an IPv6 pool: IPv4 is refused all the same.
		{"IPv4v6 allowed, IPv6 pool: IPv4", subV4V6, poolV6, tV4, true, refuse(RefuseIPv6OnlyAllowed)},
		{"IPv4 DNN: IPv6", subV4, poolV4, tV6, true, refuse(RefuseIPv4OnlyAllowed)},
	} {
		if g := got(SelectPDUSessionType(tc.req, tc.present, tc.sub, tc.p.v4, tc.p.v6)); g != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, g, tc.want)
		}
	}
}
