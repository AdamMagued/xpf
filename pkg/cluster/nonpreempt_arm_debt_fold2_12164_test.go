package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Fold-2 permanent pins for #12164 (ported from the round-1/confirmation
// reviewer probes). Each cell is two-manager over the production heartbeat +
// election path, and each kills the mutant named in its header.

// Ordinary monitor debt must never move or flap a non-preempt RG — the
// fold-1 receiver rule did both (NEW_MAJOR_1). Kills a receiver-rule
// reintroduction: with the peer-primary takeover rule restored, debt-50
// flaps every frame and debt-10/254 move ownership.
func TestNonPreemptOrdinaryDebtNeverMovesTwoManager12164(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ownerPrio  int
		peerPrio   int
		debt       int
		debtWeight int
	}{
		{"higher-prio-debt50", 200, 100, 50, 205},
		{"higher-prio-debt10", 200, 100, 10, 245},
		{"weight1-ordinary-debt254", 200, 100, maxRedundancyGroupWeight - 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.ClusterConfig{
				ControlInterface: "em0",
				RedundancyGroups: []*config.RedundancyGroup{{
					ID: 1, NodePriorities: map[int]int{0: tc.ownerPrio, 1: tc.peerPrio},
				}},
			}
			owner, peer := NewManager(0, 1), NewManager(1, 1)
			owner.UpdateConfig(cfg)
			peer.UpdateConfig(cfg)
			owner.SetRGReady(1, true, nil)
			peer.SetRGReady(1, true, nil)
			owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
			peer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
			exchangeElection12164(owner, peer)
			if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
				t.Fatal("precondition: owner primary / peer secondary")
			}
			t.Cleanup(func() { owner.Stop(); peer.Stop() })

			owner.SetMonitorWeight(1, "ge-0/0/0", true, tc.debt)
			if got := owner.GroupState(1).Weight; got != tc.debtWeight {
				t.Fatalf("ordinary-debt weight = %d, want %d", got, tc.debtWeight)
			}
			ownerT, peerT, dual := 0, 0, 0
			lastO, lastP := owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)
			for range 6 {
				owner.handlePeerHeartbeat(peer.buildHeartbeat())
				peer.handlePeerHeartbeat(owner.buildHeartbeat())
				nowO, nowP := owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)
				if nowO != lastO {
					ownerT++
				}
				if nowP != lastP {
					peerT++
				}
				lastO, lastP = nowO, nowP
				if nowO && nowP {
					dual++
				}
			}
			if ownerT != 0 || peerT != 0 || dual != 0 {
				t.Errorf("ordinary debt moved a non-preempt RG: ownerT=%d peerT=%d dual=%d",
					ownerT, peerT, dual)
			}
			if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
				t.Error("ordinary debt changed non-preempt ownership")
			}
		})
	}
}

// The arm-debt yield requires a live echo lease: a stale incarnation, a
// missing echo, or an expired lease must not yield. Kills an
// echo-gate-removal mutant (all three sub-cases yield without the gate).
func TestNonPreemptArmDebtYieldRequiresLiveEcho12164(t *testing.T) {
	for _, tc := range []struct {
		name      string
		breakEcho func(owner, peer *Manager)
	}{
		{"stale-incarnation", func(owner, peer *Manager) {
			pkt := peer.buildHeartbeat()
			pkt.PeerHeartbeatSession = owner.LocalProcessToken() ^ 0x5eed
			owner.handlePeerHeartbeat(pkt)
		}},
		{"zero-echo", func(owner, peer *Manager) {
			pkt := peer.buildHeartbeat()
			pkt.PeerHeartbeatSession, pkt.PeerHeartbeatSequence = 0, 0
			owner.handlePeerHeartbeat(pkt)
		}},
		{"expired-lease", func(owner, peer *Manager) {
			owner.mu.Lock()
			pg := owner.peerGroups[1]
			pg.heartbeatEchoLeaseUntil = time.Now().Add(-time.Millisecond)
			owner.peerGroups[1] = pg
			owner.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, peer := armDebtPair12164(t)
			tc.breakEcho(owner, peer)
			owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			if !owner.IsLocalPrimary(1) {
				t.Fatalf("arm-debt incumbent yielded on a %s echo", tc.name)
			}
		})
	}
}

// Marker-only arm state (zero-cost entry, retained marker without debt)
// must never yield; only positive authoritative debt yields. Kills a
// marker-instead-of-debt mutant.
func TestNonPreemptArmDebtYieldRequiresPositiveDebt12164(t *testing.T) {
	for _, tc := range []struct {
		name    string
		debt    int
		present bool
		yield   bool
	}{
		{"fully-held", 254, true, true},
		{"partially-paid", 1, true, true},
		{"fully-paid-marker-retained", 0, true, false},
		{"zero-cost-marker", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(0, 1)
			m.groups[1] = &RedundancyGroupState{GroupID: 1, State: StatePrimary, LocalPriority: 200, Weight: 200, MonitorFails: []string{DataplaneArmMonitorIface, "ge-0/0/0"}}
			m.monitorWeights[monitorKey{rgID: 1, iface: "ge-0/0/0"}] = 55
			if tc.present {
				m.monitorWeights[monitorKey{rgID: 1, iface: DataplaneArmMonitorIface}] = tc.debt
			}
			m.groups[1].Weight = rgWeightFromDebt(55 + tc.debt)
			if m.groups[1].Weight == 0 {
				m.monitorWeights[monitorKey{rgID: 1, iface: "ge-0/0/0"}] = 0
				m.groups[1].Weight = rgWeightFromDebt(tc.debt)
			}
			// Priority 200 (not 100): the yield requires the peer to WIN
			// the receiver ordering (peerEff > localEff), and at debt 1
			// the local eff is 200*199/255 = 156 — a priority-100 peer
			// (eff 100) must NOT take the RG. This cell measures the
			// debt-vs-marker distinction, so the peer must win on
			// ordering in the yield rows.
			pg := &PeerGroupState{GroupID: 1, State: StateSecondary, Priority: 200, Weight: 255,
				heartbeatEchoSession: m.LocalProcessToken(), heartbeatEchoSequence: 7,
				heartbeatEchoLeaseUntil: time.Now().Add(time.Minute)}
			result, _ := m.electRG(m.groups[1], pg)
			if tc.yield && result != electLocalSecondary {
				t.Error("held arm debt did not yield")
			}
			if !tc.yield && result == electLocalSecondary {
				t.Error("marker-only state yielded without holding actual arm debt")
			}
		})
	}
}

// A committed owner that loses its dataplane hands back to the healthy old
// owner instead of blackholing behind the role pin (F3). Kills a pin-branch
// without the arm-debt exception: the new owner stays primary at weight 1.
func TestNonPreemptCommittedArmDebtOwnerHandsBack12164(t *testing.T) {
	oldOwner, newOwner := armDebtPair12164(t)
	newOwner.SetPeerFailoverFunc(func(id int) (uint64, error) {
		_, err := oldOwner.ManualFailover(id)
		return 12164, err
	})
	newOwner.SetPeerFailoverCommitFunc(func(id int, requestID uint64) error {
		return oldOwner.FinalizePeerTransferOut(id)
	})
	if err := newOwner.RequestPeerFailover(1); err != nil {
		t.Fatal(err)
	}
	newOwner.mu.Lock()
	newOwner.peerTransferCommitGraceUntil[1] = time.Now().Add(-time.Second)
	newOwner.mu.Unlock()
	oldOwner.mu.Lock()
	oldOwner.localTransferOutHoldUntil[1] = time.Now().Add(-time.Second)
	oldOwner.mu.Unlock()
	exchangeElection12164(oldOwner, newOwner)
	if oldOwner.IsLocalPrimary(1) || !newOwner.IsLocalPrimary(1) {
		t.Fatal("transfer did not settle")
	}
	newOwner.SetRGReady(1, false, []string{"last XDP link lost"})
	newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	if newOwner.IsLocalPrimary(1) || !oldOwner.IsLocalPrimary(1) {
		t.Errorf("committed primary still holds RG at arm-debt floor over ready peer: newOwner=%s/%d oldOwner=%s/%d",
			newOwner.GroupState(1).State, newOwner.GroupState(1).Weight,
			oldOwner.GroupState(1).State, oldOwner.GroupState(1).Weight)
	}
}

// An arm-debt yield to a peer that cannot promote must not strand the RG:
// the not-ready peer promotes DEGRADED via the arm-floor yield-ownership
// arm rather than leaving the RG ownerless (F1). Kills a yield-ownership
// without the weight-1 arm: the RG sits ownerless until the 2min fallback.
func TestNonPreemptArmDebtYieldNeverStrandsUnreadyPeer12164(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(owner, peer *Manager)
	}{
		{"peer-not-ready", func(owner, peer *Manager) {
			peer.SetRGReady(1, false, []string{"userspace helper not running"})
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
		}},
		{"peer-in-takeover-hold", func(owner, peer *Manager) {
			peer.SetRGReady(1, false, []string{"rejoining"})
			peer.takeoverHoldTime = time.Minute
			peer.SetRGReady(1, true, nil)
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
		}},
		{"peer-fails-after-announcing", func(owner, peer *Manager) {
			announced := peer.buildHeartbeat()
			peer.SetRGReady(1, false, []string{"helper died after sending heartbeat"})
			owner.handlePeerHeartbeat(announced)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, peer := armDebtPair12164(t)
			tc.setup(owner, peer)
			owner.SetRGReady(1, false, []string{"XDP attachment lost"})
			owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			exchangeElection12164(owner, peer)
			if !owner.IsLocalPrimary(1) && !peer.IsLocalPrimary(1) {
				t.Errorf("arm-debt yield stranded the RG with a %s peer: owner=%s/%d peer=%s/%d",
					tc.name, owner.GroupState(1).State, owner.GroupState(1).Weight,
					peer.GroupState(1).State, peer.GroupState(1).Weight)
			}
		})
	}
}

// armDebtPair12164 builds an owner-primary / peer-secondary non-preempt pair
// with both dataplanes proven, ready for a fault injection.
func armDebtPair12164(t *testing.T) (owner, peer *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}}},
	}
	owner, peer = NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	owner.SetRGReady(1, true, nil)
	peer.SetRGReady(1, true, nil)
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	peer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatal("precondition: owner primary / peer secondary")
	}
	t.Cleanup(func() { owner.Stop(); peer.Stop() })
	return owner, peer
}
