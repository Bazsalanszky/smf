// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A transaction goroutine started by SendPfcp is not tied to any test's lifecycle. At the
// production retry timings it can easily outlive the sub-second test that spawned it and later
// touch memory the runtime has since reused for an unrelated test's stack -- a real race the
// detector reports between two logically unrelated tests. Shortening the timings here bounds how
// long such a leaked goroutine can stay alive.
func init() {
	udp.SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)
}

// The whole mechanism rests on one thing: a restored session must be sent as a session
// ESTABLISHMENT, not a modification. A restarted UPF holds no session, so a modification addressed
// to a session identifier it never issued is either rejected or, worse, applied to unrelated state.
//
// Nothing else in the suite looks at what actually goes on the wire, so this stands up a PFCP
// socket for the SMF and a listener standing in for the UPF, and reads the message type off it.
func TestARestoredSessionIsSentAsAnEstablishmentNotAModification(t *testing.T) {
	nativeDatapath(t)
	upfConn, upfPort := listenLoopback(t)
	startSmfPfcpSocket(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.Port = upfPort
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
	// The N3 interface the RAN was told to send to. Without it the tunnel cannot be pinned.
	upf.N3Interfaces = []context.UPFInterfaceInfo{{
		NetworkInstance:       "internet",
		IPv4EndPointAddresses: []net.IP{net.ParseIP("192.168.252.3")},
	}}

	smContext, wantPDRID, wantTEID := sessionWithDataPath(t, "imsi-208930000000901", 1, upf)

	// A session that is currently established: the UPF has issued an identifier for it. Left as it
	// is, the activation path would send a modification.
	pfcpCtx := smContext.PFCPContext["127.0.0.1"]
	pfcpCtx.RemoteSEID = 0xBEEF

	if !reissue(smContext, "127.0.0.1") {
		t.Fatalf("the session was not re-issued")
	}

	msg := readPfcp(t, upfConn)
	if got, want := msg.MessageType(), message.MsgTypeSessionEstablishmentRequest; got != want {
		t.Fatalf("the restarted UPF received message type %d, want %d (session establishment). "+
			"A modification names a session the restarted UPF never created.", got, want)
	}

	// The rules go back with the identifiers the SMF already holds. They mean something to a UPF
	// only while it holds the rules they name, and a restarted one holds none, so carrying them
	// over is both safe and what keeps every existing reference to a rule valid.
	establishment, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		t.Fatalf("unexpected message shape %T", msg)
	}
	if len(establishment.CreatePDR) == 0 {
		t.Fatalf("the establishment carried no Create PDR, so nothing was re-installed")
	}
	pdrID, err := establishment.CreatePDR[0].PDRID()
	if err != nil {
		t.Fatalf("reading the PDR ID back: %v", err)
	}
	if pdrID != wantPDRID {
		t.Errorf("the re-installed PDR is %d, want %d; restoration renumbered a rule it should have "+
			"carried over, leaving every reference the SMF holds pointing at the old value", pdrID, wantPDRID)
	}

	// The uplink tunnel must be named, not re-chosen. If the CHOOSE flag is still set the UPF
	// allocates a second TEID, the RAN is never told, and every uplink packet keeps arriving on the
	// old one and misses the rule table -- which is what the cluster showed.
	pdi, err := establishment.CreatePDR[0].PDI()
	if err != nil {
		t.Fatalf("reading the PDI back: %v", err)
	}
	var fteid *ie.IE
	for _, child := range pdi {
		if child.Type == ie.FTEID {
			fteid = child
		}
	}
	if fteid == nil {
		t.Fatalf("the re-installed PDR carries no F-TEID, so the UPF has nothing to match uplink on")
	}
	f, err := fteid.FTEID()
	if err != nil {
		t.Fatalf("parsing the F-TEID: %v", err)
	}
	if f.HasCh() {
		t.Errorf("the F-TEID still has the CHOOSE flag set, so the restarted UPF will allocate a new " +
			"tunnel the RAN knows nothing about")
	}
	if f.TEID != wantTEID {
		t.Errorf("the re-installed tunnel is TEID %#x, want %#x — the one the RAN is sending on", f.TEID, wantTEID)
	}
}

// nativeDatapath selects the PFCP datapath rather than the adapter, which would post the message to
// an HTTP endpoint instead of putting it on the wire.
func nativeDatapath(t *testing.T) {
	t.Helper()
	enabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: &enabled},
			EnableUpfAdapter: false,
		},
	}
}

func listenLoopback(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("standing in for the UPF: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// startSmfPfcpSocket gives the SMF a real socket to send from, which the send path takes from the
// package-level server rather than opening per message.
func startSmfPfcpSocket(t *testing.T) {
	t.Helper()
	self := context.SMF_Self()
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserving a port for the SMF: %v", err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	self.CPNodeID = *context.NewNodeID("127.0.0.1")
	self.PFCPPort = port
	udp.Run(func(*udp.Message) {})
	time.Sleep(50 * time.Millisecond) // let the listener bind before anything is sent

	t.Cleanup(func() {
		// A transaction goroutine started by a send in this test is not tied to the test's
		// lifecycle, and its error handler reads factory.SmfConfig, which a later test rewrites --
		// a race the detector reports between the two. Drain them before returning, then take the
		// server down so it does not linger into a later test and make that one send real packets
		// (and leak its own such goroutines) too.
		udp.WaitForAllTransactions()
		if server := udp.GetServer(); server != nil {
			if server.Conn != nil {
				server.Conn.Close()
				<-server.Done // the read loop has observed the close and returned
			}
			udp.SetServer(nil)
		}
	})
}

func readPfcp(t *testing.T, conn *net.UDPConn) message.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the restarted UPF received nothing: %v", err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parsing what the UPF received: %v", err)
	}
	return msg
}

// sessionWithDataPath builds a session with one activated data path anchored on the given UPF, so
// the activation path has rules to send.
func sessionWithDataPath(t *testing.T, supi string, psi int32, upf *context.UPF) (*context.SMContext, uint16, uint32) {
	t.Helper()
	pdr, err := upf.AddPDR()
	if err != nil {
		t.Fatalf("allocating a PDR: %v", err)
	}
	// What ActivateUpLinkTunnel builds: the CHOOSE flag set, asking the UPF to allocate the tunnel.
	// Restoration has to turn this into a named tunnel, and a bare PDR would not exercise that.
	pdr.PDI.SourceInterface = context.SourceInterface{InterfaceValue: context.SourceInterfaceAccess}
	pdr.PDI.LocalFTeid = &context.FTEID{Ch: true}

	smContext := context.NewSMContext(supi, psi)
	// The N3 address is resolved per session type, the same way the N2 setup resolves it.
	smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			1: &context.DataPath{
				Activated:     true,
				IsDefaultPath: true,
				FirstDPNode: &context.DataPathNode{
					UPF:          upf,
					UpLinkTunnel: &context.GTPTunnel{TEID: 0x1234, PDR: map[string]*context.PDR{"default": pdr}},
				},
			},
		},
	}
	smContext.SMLock.Lock()
	smContext.PFCPContext[upf.NodeID.ResolveNodeIdToIp().String()] = &context.PFCPSessionContext{
		NodeID:    upf.NodeID,
		LocalSEID: 4321,
	}
	smContext.SMLock.Unlock()
	return smContext, pdr.PDRID, 0x1234
}

// A restored IPv6 session gets its router advertisement rules back with the rest: the UP2CP PDR on
// the uplink tunnel the RAN is using, named rather than chosen as the uplink PDRs are, with its FAR
// to the SMF, and the CP2UP PDR on the downlink FAR asking the restarted UPF for a new F-TEID.
func TestARestoredSessionReinstallsItsRouterAdvertisementRules(t *testing.T) {
	nativeDatapath(t)
	upfConn, upfPort := listenLoopback(t)
	startSmfPfcpSocket(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.Port = upfPort
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
	upf.N3Interfaces = []context.UPFInterfaceInfo{{
		NetworkInstance:       "internet",
		IPv4EndPointAddresses: []net.IP{net.ParseIP("192.168.252.3")},
	}}
	smContext, _, wantTEID := sessionWithDataPath(t, "imsi-208930000000902", 1, upf)
	smContext.PFCPContext["127.0.0.1"].RemoteSEID = 0xBEEF
	node := smContext.Tunnel.DataPathPool[1].FirstDPNode
	node.UpLinkTunnel.PDR[defaultPdrKey].PDI.LocalFTeid = &context.FTEID{V4: true, Ch: true, Chid: true, ChooseId: 1}

	dl, err := upf.AddPDR()
	if err != nil {
		t.Fatal(err)
	}
	dl.PDI.SourceInterface = context.SourceInterface{InterfaceValue: context.SourceInterfaceCore}
	dl.FAR.ApplyAction.Forw = true
	node.DownLinkTunnel = &context.GTPTunnel{PDR: map[string]*context.PDR{defaultPdrKey: dl}}

	// The rules as context builds them for an IPv6 session, with the F-TEIDs an earlier
	// incarnation of the UPF gave.
	smf := net.ParseIP("10.0.0.9").To4()
	rs, err := upf.AddPDR()
	if err != nil {
		t.Fatal(err)
	}
	rs.PDI = context.PDI{
		SourceInterface: context.SourceInterface{InterfaceValue: context.SourceInterfaceAccess},
		LocalFTeid:      &context.FTEID{V4: true, Ch: true, Chid: true, ChooseId: 1},
		SDFFilter: &context.SDFFilter{
			Fd:                      true,
			FlowDescription:         []byte(context.RouterSolicitationFlowDescription),
			LengthOfFlowDescription: uint16(len(context.RouterSolicitationFlowDescription)),
		},
	}
	rs.OuterHeaderRemoval = &context.OuterHeaderRemoval{OuterHeaderRemovalDescription: context.OuterHeaderRemovalGtpUUdpIp}
	rs.FAR.ApplyAction.Forw = true
	rs.FAR.ForwardingParameters = &context.ForwardingParameters{
		DestinationInterface: context.DestinationInterface{InterfaceValue: context.DestinationInterfaceCPFunction},
		OuterHeaderCreation: &context.OuterHeaderCreation{
			OuterHeaderCreationDescription: context.OuterHeaderCreationGtpUUdpIpv4,
			Teid:                           4321,
			Ipv4Address:                    smf,
		},
	}
	ra := &context.PDR{
		PDRID: rs.PDRID + 1,
		FAR:   dl.FAR,
		PDI: context.PDI{
			SourceInterface: context.SourceInterface{InterfaceValue: context.SourceInterfaceCPFunction},
			LocalFTeid:      &context.FTEID{V4: true, Ch: true, Teid: 0x55, Ipv4Address: net.ParseIP("192.168.252.3").To4()},
		},
		OuterHeaderRemoval: &context.OuterHeaderRemoval{OuterHeaderRemovalDescription: context.OuterHeaderRemovalGtpUUdpIp},
	}
	node.RouterAdvertisement = &context.RouterAdvertisementRules{Solicitation: rs, Advertisement: ra}

	if !reissue(smContext, "127.0.0.1") {
		t.Fatal("the session was not re-issued")
	}
	if ra.PDI.LocalFTeid.Teid != 0 || ra.PDI.LocalFTeid.Ipv4Address != nil {
		t.Errorf("the CP2UP F-TEID of the UPF's earlier incarnation was kept: %+v", ra.PDI.LocalFTeid)
	}

	establishment, ok := readPfcp(t, upfConn).(*message.SessionEstablishmentRequest)
	if !ok {
		t.Fatal("no establishment request")
	}
	createPDRs := map[uint16]*ie.IE{}
	for _, createPDR := range establishment.CreatePDR {
		createPDRs[must(t, createPDR.PDRID)] = createPDR
	}
	pdiOf := func(id uint16) (source uint8, fteid *ie.FTEIDFields, sdf string) {
		t.Helper()
		createPDR := createPDRs[id]
		if createPDR == nil {
			t.Fatalf("PDR %d was not re-installed; the request has %d Create PDRs", id, len(createPDRs))
		}
		for _, child := range must(t, createPDR.PDI) {
			switch child.Type {
			case ie.SourceInterface:
				source = must(t, child.SourceInterface)
			case ie.FTEID:
				fteid = must(t, child.FTEID)
			case ie.SDFFilter:
				sdf = must(t, child.SDFFilter).FlowDescription
			}
		}
		return source, fteid, sdf
	}

	source, fteid, sdf := pdiOf(rs.PDRID)
	if source != ie.SrcInterfaceAccess || sdf != context.RouterSolicitationFlowDescription {
		t.Errorf("UP2CP source interface %d, SDF %q", source, sdf)
	}
	if fteid == nil || fteid.HasCh() || fteid.TEID != wantTEID || !fteid.IPv4Address.Equal(net.ParseIP("192.168.252.3")) {
		t.Errorf("UP2CP F-TEID %+v, want the uplink tunnel's %#x, named", fteid, wantTEID)
	}
	if precedence := must(t, createPDRs[rs.PDRID].Precedence); precedence != 0 {
		t.Errorf("UP2CP precedence %d", precedence)
	}

	source, fteid, _ = pdiOf(ra.PDRID)
	if source != ie.SrcInterfaceCPFunction {
		t.Errorf("CP2UP source interface %d", source)
	}
	if fteid == nil || !fteid.HasCh() || fteid.HasChID() || fteid.TEID != 0 {
		t.Errorf("CP2UP F-TEID %+v, want CHOOSE without a CHOOSE ID", fteid)
	}
	if farID := must(t, createPDRs[ra.PDRID].FARID); farID != dl.FAR.FARID {
		t.Errorf("CP2UP FAR %d, want the downlink FAR %d", farID, dl.FAR.FARID)
	}

	var up2cpFAR *ie.IE
	for _, createFAR := range establishment.CreateFAR {
		if must(t, createFAR.FARID) == rs.FAR.FARID {
			up2cpFAR = createFAR
		}
	}
	if up2cpFAR == nil {
		t.Fatal("the UP2CP FAR was not re-installed")
	}
	for _, child := range must(t, up2cpFAR.ForwardingParameters) {
		switch child.Type {
		case ie.DestinationInterface:
			if di := must(t, child.DestinationInterface); di != ie.DstInterfaceCPFunction {
				t.Errorf("UP2CP destination interface %d", di)
			}
		case ie.OuterHeaderCreation:
			ohc := must(t, child.OuterHeaderCreation)
			if ohc.OuterHeaderCreationDescription != 0x0100 || ohc.TEID != 4321 || !ohc.IPv4Address.Equal(smf) {
				t.Errorf("UP2CP outer header creation %+v", ohc)
			}
		}
	}
}

// must returns what get returns, failing the test on its error.
func must[T any](t *testing.T, get func() (T, error)) T {
	t.Helper()
	v, err := get()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
