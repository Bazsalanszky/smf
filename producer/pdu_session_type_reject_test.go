// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
)

// Each refusal of the PDU session type reaches the UE with its own 5GSM cause; every other
// refusal of the request keeps the #50 it had.
func TestPDUSessionTypeRejectCauses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cause  uint8
		status int
	}{
		{
			"IPv4 only", &smf_context.PDUSessionTypeError{Refusal: smf_context.RefuseIPv4OnlyAllowed},
			nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed, http.StatusForbidden,
		},
		{
			"IPv6 only", &smf_context.PDUSessionTypeError{Refusal: smf_context.RefuseIPv6OnlyAllowed},
			nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed, http.StatusForbidden,
		},
		{
			"unknown type", &smf_context.PDUSessionTypeError{Refusal: smf_context.RefuseUnknownPDUSessionType},
			nasMessage.Cause5GSMUnknownPDUSessionType, http.StatusForbidden,
		},
		{
			"no pool", &smf_context.PDUSessionTypeError{Refusal: smf_context.RefuseNoPool},
			nasMessage.Cause5GSMInsufficientResources, http.StatusInternalServerError,
		},
		{
			"other error", errors.New("selected PDU session type is not set"),
			nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed, http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := smf_context.NewSMContext("imsi-208930100007489", 10)
			t.Cleanup(func() { smf_context.RemoveSMContext(smContext.Ref) })
			smContext.Pti = requestPti

			rsp := pduSessionTypeReject(smContext, tc.err)
			if rsp.Status != tc.status {
				t.Errorf("HTTP status = %d, want %d", rsp.Status, tc.status)
			}
			body, ok := rsp.Body.(*models.PostSmContexts400Response)
			if !ok {
				t.Fatalf("body is %T", rsp.Body)
			}
			if got := gsmCauseOf(t, body.GetBinaryDataN1SmMessage()); got != tc.cause {
				t.Errorf("5GSM cause = %d, want %d", got, tc.cause)
			}
		})
	}
}

func gsmCauseOf(t *testing.T, file *os.File) uint8 {
	t.Helper()
	if file == nil {
		t.Fatal("no N1 SM message was attached to the rejection")
	}
	t.Cleanup(func() {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
	})
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	m := nas.NewMessage()
	if err := m.GsmMessageDecode(&payload); err != nil {
		t.Fatalf("decoding the rejection: %v", err)
	}
	if m.PDUSessionEstablishmentReject == nil {
		t.Fatalf("the rejection is message type %#x", m.GsmHeader.GetMessageType())
	}
	return m.PDUSessionEstablishmentReject.GetCauseValue()
}
