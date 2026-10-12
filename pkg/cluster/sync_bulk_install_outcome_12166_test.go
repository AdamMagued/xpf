package cluster

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #12166: a transient helper transport failure is not a semantic import
// refusal. A bulk containing such a failure must keep the receive window and
// HA hold open, withhold BulkAck, and let the sender's bounded bulk-prime retry
// re-request the authoritative table. A later successful bulk completes; a
// semantic refusal remains the intentional-ACK path.
func TestBulkAckWaitsForTransientSessionInstall12166(t *testing.T) {
	transientA := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1001, DstPort: 80}
	transientB := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 4}, SrcPort: 1002, DstPort: 80}
	refused := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 6}, SrcPort: 1003, DstPort: 80}
	healthy := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 7}, DstIP: [4]byte{10, 0, 0, 8}, SrcPort: 1004, DstPort: 80}
	transientV6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1005, DstPort: 80}
	transientV6.SrcIP[15], transientV6.DstIP[15] = 1, 2
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		failSetV4: map[dataplane.SessionKey]error{
			transientA: errors.New("session table write failed"),
			transientB: errors.New("session table write failed"),
			refused:    dataplane.ErrSyncedImportRefused,
		},
		failSetV6: map[dataplane.SessionKeyV6]error{
			transientV6: errors.New("session table write failed"),
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
	released := make(chan struct{}, 2)
	ss.OnBulkSyncReceived = func() { released <- struct{}{} }

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &frameCaptureConn{Conn: local}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	writeBulk := func(epoch uint64) {
		ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(epoch, nil))
		for _, key := range []dataplane.SessionKey{transientA, transientB, refused, healthy} {
			ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key, val))
		}
		ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(transientV6, val6))
		ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(epoch, nil))
	}

	writeBulk(1)
	// Give an erroneous asynchronous hold-release callback a bounded chance to
	// run; all other completion observables are synchronous in handleMessage.
	select {
	case <-released:
		t.Fatal("transient install failures released the HA sync hold")
	case <-time.After(50 * time.Millisecond):
	}
	if got := len(conn.frames); got != 0 {
		t.Fatalf("transient install failures produced %d ack frames; want BulkAck withheld", got)
	}
	if ss.BulkEverCompleted() || ss.stats.BulkSyncEndTime.Load() != 0 {
		t.Fatalf("incomplete bulk marked completed (ever=%v end=%d)", ss.BulkEverCompleted(), ss.stats.BulkSyncEndTime.Load())
	}
	if got := ss.TransferReadiness(); !got.BulkReceiveInProgress || got.ReadyForManualFailover() {
		t.Fatalf("incomplete bulk must remain a manual-failover readiness blocker, readiness=%+v", got)
	}
	if _, ok := dp.v4sessions[transientA]; ok {
		t.Fatal("fixture expected transient A's failed helper install to remain absent")
	}
	if _, ok := dp.v4sessions[transientB]; ok {
		t.Fatal("fixture expected transient B's failed helper install to remain absent")
	}
	if _, ok := dp.v6sessions[transientV6]; ok {
		t.Fatal("fixture expected transient IPv6 install to remain absent")
	}
	if _, ok := dp.v4sessions[healthy]; !ok {
		t.Fatal("fixture's later successful helper install did not land")
	}
	if ss.sessionMirrorWarnedV4.Load() {
		t.Fatal("fixture requires the later success to clear the mirror warning, isolating bulk outcome tracking")
	}
	if got := ss.stats.ImportsRefusedByHelper.Load(); got != 1 {
		t.Fatalf("semantic refusal count = %d, want 1", got)
	}

	// The bounded resend arrives as a fresh authoritative bulk. Its transient
	// installs now succeed, and the receiver can reconcile, ack, and release.
	delete(dp.failSetV4, transientA)
	delete(dp.failSetV4, transientB)
	delete(dp.failSetV6, transientV6)
	writeBulk(2)
	if len(conn.frames) != 1 {
		t.Fatalf("recovered bulk emitted %d frames, want one BulkAck", len(conn.frames))
	}
	ack := conn.frames[0]
	if len(ack) != syncHeaderSize+8 || ack[4] != syncMsgBulkAck || binary.LittleEndian.Uint64(ack[syncHeaderSize:]) != 2 {
		t.Fatalf("recovered bulk ack = %v, want BulkAck for epoch 2", ack)
	}
	if !ss.BulkEverCompleted() || ss.stats.BulkSyncEndTime.Load() == 0 {
		t.Fatal("recovered authoritative bulk did not complete")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("recovered authoritative bulk did not release the HA sync hold")
	}
	for _, key := range []dataplane.SessionKey{transientA, transientB, healthy} {
		if _, ok := dp.v4sessions[key]; !ok {
			t.Errorf("recovered bulk did not install %v", key)
		}
	}
	if _, ok := dp.v6sessions[transientV6]; !ok {
		t.Error("recovered bulk did not install the transient IPv6 session")
	}
	if _, ok := dp.v4sessions[refused]; ok {
		t.Error("semantic refusal unexpectedly installed a row")
	}
}

func TestBulkAckClassifiesCommittedAndDeterministicOutcomes12166(t *testing.T) {
	cases := []struct {
		name    string
		family  int
		err     error
		wantAck bool
	}{
		{"repair-pending-v4", 4, dataplane.ErrSyncedImportRepairPending, true},
		{"repair-overflow-v4", 4, dataplane.ErrSyncedImportRepairOverflow, true},
		{"repair-pending-v6", 6, dataplane.ErrSyncedImportRepairPending, true},
		{"repair-overflow-v6", 6, dataplane.ErrSyncedImportRepairOverflow, true},
		{"semantic-refusal", 4, dataplane.ErrSyncedImportRefused, true},
		{"unresolved-extension-header", 4, errors.New(
			"refusing synced session with unresolved IPv6 extension-header protocol 0"), true},
		{"deterministic-parse", 4, errors.New("parse next_hop : invalid IP address syntax"), true},
		{"context-wrapped-unresolved-extension", 4, errors.New(
			"helper error while handling refusing synced session with unresolved IPv6 extension-header protocol 0"), false},
		{"helper-down", 4, errors.New(
			"mirror synced v4 session to userspace helper: session helper unreachable: read session response: i/o timeout"), false},
		{"mirror-write-failed", 4, errors.New("mirror-write-failed"), false},
		{"unknown-helper-error", 4, errors.New("unexpected helper failure"), false},
	}
	key4 := dataplane.SessionKey{
		Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 1001, DstPort: 80,
	}
	key6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1002, DstPort: 80}
	key6.SrcIP[15], key6.DstIP[15] = 1, 2
	val4 := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp := &mockSweepDP{
				v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
				v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
			}
			ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
			ss.IsPrimaryFn = func() bool { return false }
			ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
			ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			conn := &frameCaptureConn{Conn: local}
			ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
			if tc.family == 4 {
				dp.failSetV4 = map[dataplane.SessionKey]error{key4: tc.err}
				ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key4, val4))
			} else {
				dp.failSetV6 = map[dataplane.SessionKeyV6]error{key6: tc.err}
				ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(key6, val6))
			}
			ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))

			acks := bulkAckEpochs12166(conn)
			if tc.wantAck {
				if len(acks) != 1 || acks[0] != 1 {
					t.Fatalf("deterministic/committed outcome acks=%v, want [1]", acks)
				}
				if ss.TransferReadiness().BulkReceiveInProgress || !ss.BulkEverCompleted() {
					t.Fatal("definitive outcome did not complete the authoritative bulk")
				}
			} else {
				if len(acks) != 0 {
					t.Fatalf("retryable outcome acks=%v, want no ack", acks)
				}
				if !ss.TransferReadiness().BulkReceiveInProgress || ss.BulkEverCompleted() {
					t.Fatal("retryable outcome did not retain the incomplete receive window")
				}
			}
			if tc.name == "repair-pending-v4" || tc.name == "repair-overflow-v4" ||
				tc.name == "repair-pending-v6" || tc.name == "repair-overflow-v6" {
				if ss.stats.Errors.Load() != 0 {
					t.Fatalf("committed repair result counted as helper transport error: %d", ss.stats.Errors.Load())
				}
			}
		})
	}
}

func TestBulkTransientInstallTrackingIsPerFamily12166(t *testing.T) {
	key4 := dataplane.SessionKey{
		Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 1001, DstPort: 80,
	}
	key6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1002, DstPort: 80}
	key6.SrcIP[15], key6.DstIP[15] = 1, 2
	val4 := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	for _, tc := range []struct {
		name   string
		family int
	}{
		{name: "v4-only", family: 4},
		{name: "v6-only", family: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &mockSweepDP{
				v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
				v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
			}
			ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
			ss.IsPrimaryFn = func() bool { return false }
			ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
			ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			conn := &frameCaptureConn{Conn: local}
			ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
			if tc.family == 4 {
				dp.failSetV4 = map[dataplane.SessionKey]error{key4: errors.New("transient write failure")}
				ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key4, val4))
			} else {
				dp.failSetV6 = map[dataplane.SessionKeyV6]error{key6: errors.New("transient write failure")}
				ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(key6, val6))
			}
			ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
			if got := bulkAckEpochs12166(conn); len(got) != 0 {
				t.Fatalf("single-family transient install acks=%v, want no ack", got)
			}
			if !ss.TransferReadiness().BulkReceiveInProgress || ss.BulkEverCompleted() {
				t.Fatal("single-family transient install did not retain the receive gate")
			}
		})
	}
}

func TestBulkInstallFailureMarkerTransitions12166(t *testing.T) {
	key := dataplane.SessionKey{
		Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 1001, DstPort: 80,
	}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	for _, tc := range []struct {
		name    string
		action  string
		wantAck bool
	}{
		{name: "fail-then-success", action: "success", wantAck: true},
		{name: "fail-then-refused", action: "refused", wantAck: true},
		{name: "fail-then-applied-delete", action: "delete", wantAck: true},
		{name: "fail-then-failed-delete", action: "failed-delete", wantAck: false},
		{name: "new-bulk-resets-previous-marker", action: "reset", wantAck: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &mockSweepDP{
				v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
				failSetV4:  map[dataplane.SessionKey]error{key: errors.New("transient write failure")},
			}
			ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
			ss.IsPrimaryFn = func() bool { return false }
			ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
			ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			conn := &frameCaptureConn{Conn: local}
			ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
			ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key, val))
			switch tc.action {
			case "success":
				delete(dp.failSetV4, key)
				ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key, val))
			case "refused":
				dp.failSetV4[key] = dataplane.ErrSyncedImportRefused
				ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key, val))
			case "delete":
				ss.handleMessage(conn, syncMsgDeleteV4, encodeDeleteV4(key, 0, false)[syncHeaderSize:])
			case "failed-delete":
				dp.failDeleteV4 = map[dataplane.SessionKey]error{key: errors.New("delete failed")}
				ss.handleMessage(conn, syncMsgDeleteV4, encodeDeleteV4(key, 0, false)[syncHeaderSize:])
			case "reset":
				ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(2, nil))
				ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(2, nil))
			}
			if tc.action != "reset" {
				ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
			}
			acks := bulkAckEpochs12166(conn)
			if tc.wantAck {
				wantEpoch := uint64(1)
				if tc.action == "reset" {
					wantEpoch = 2
				}
				if len(acks) != 1 || acks[0] != wantEpoch {
					ss.bulkMu.Lock()
					failed := len(ss.bulkInstallFailedV4)
					ss.bulkMu.Unlock()
					t.Fatalf("transition acks=%v, want [%d] (deletes=%d stale=%d errors=%d failed=%d)",
						acks, wantEpoch, ss.stats.DeletesReceived.Load(),
						ss.stats.DeletesStaleIgnored.Load(), ss.stats.Errors.Load(), failed)
				}
				if ss.TransferReadiness().BulkReceiveInProgress || !ss.BulkEverCompleted() {
					t.Fatal("resolved marker transition did not complete the bulk")
				}
			} else {
				if len(acks) != 0 {
					t.Fatalf("failed delete incorrectly cleared the marker: acks=%v", acks)
				}
				ss.bulkMu.Lock()
				failed := len(ss.bulkInstallFailedV4)
				ss.bulkMu.Unlock()
				if failed != 1 || !ss.TransferReadiness().BulkReceiveInProgress {
					t.Fatalf("failed delete cleared retry debt: failed=%d readiness=%+v",
						failed, ss.TransferReadiness())
				}
			}
		})
	}
}
