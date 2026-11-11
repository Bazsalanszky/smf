// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/transaction"
)

// The router advertisement seam fires for the update that carries the setup response only.
func TestIsSetupResponse(t *testing.T) {
	for infoType, want := range map[models.N2SmInfoType]bool{
		models.N2SMINFOTYPE_PDU_RES_SETUP_RSP: true,
		models.N2SMINFOTYPE_PDU_RES_MOD_RSP:   false,
		models.N2SMINFOTYPE_PATH_SWITCH_REQ:   false,
	} {
		update := models.NewSmContextUpdateDataWithDefaults()
		update.SetN2SmInfoType(infoType)
		req := models.UpdateSmContextRequest{}
		req.SetJsonData(*update)
		if got := isSetupResponse(&transaction.Transaction{Req: req}); got != want {
			t.Errorf("%s: %t, want %t", infoType, got, want)
		}
	}
	if isSetupResponse(&transaction.Transaction{Req: "not an update"}) {
		t.Error("a request of another type is a setup response")
	}
	if isSetupResponse(&transaction.Transaction{Req: models.UpdateSmContextRequest{}}) {
		t.Error("an update without N2 SM information is a setup response")
	}
}
