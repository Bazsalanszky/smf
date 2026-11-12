// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The adapter's Association Setup Response is handled synchronously inside the send, under the
// UpfLock the sender holds (HandleAdapterPfcpRsp). Recording the UPF's N3 families there must not
// take the lock again: the first lab run with it deadlocked every UPF lookup, and every PDU
// session stalled before its Establishment.
func TestTheAdapterRecordsTheN3FamiliesUnderTheCallersLock(t *testing.T) {
	off := false
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &off}},
		}
	}
	const ip = "1.1.1.12"
	nodeID := context.NewNodeID(ip)
	upf := context.NewUPF(nodeID, nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })

	// V4 and V6, ASSOSI with source interface Access (0): 10.10.3.1 and 2001:db8::1.
	res := ie.NewUserPlaneIPResourceInformation(0x43, 0, "10.10.3.1", "2001:db8::1", "", ie.SrcInterfaceAccess)
	rsp := message.NewAssociationSetupResponse(1, ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID(ip, "", ""), ie.NewRecoveryTimeStamp(time.Unix(1_790_000_000, 0)), res)

	done := make(chan error, 1)
	upf.UpfLock.Lock()
	go func() { done <- adapter.HandleAdapterPfcpRsp(rsp, nil) }()
	select {
	case err := <-done:
		upf.UpfLock.Unlock()
		if err != nil {
			t.Fatalf("handling the association response: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler blocked on the UpfLock its caller holds")
	}

	if got := upf.GetN3Transport(); !got.Dual {
		t.Errorf("N3 transport after a dual advertisement is %+v, want dual", got)
	}
}
