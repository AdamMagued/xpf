package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Fold-3/4 permanent pins for #12164: ordering-consistent yield (MAJOR-1),
// observed-primary-gated weight-1 arm (MAJOR-2), kernel-hold exclusion
// (MAJOR-3), in-grace handover (MINOR-1), and committed-pin protections.

// A tied effective priority the peer LOSES must not yield: the peer's
// neither-primary branch returns NoChange on the tie, so a raw-weight yield
// would flap (yield → peer NoChange → yielder re-promotes → yield).
// Kills the raw-weight-only yield mutant (peerWeight > localWeight without
// the effective-priority conjunct): the incumbent yields and flaps.
func TestNonPreemptArmDebtYieldRequiresReceiverWin12164(t *testing.T) {
	owner, peer := armDebtPair12164(t)
	// Peer weight 2 vs owner floor 1: raw weight says yield, but both
	// effective priorities truncate to 0 (200*1/255 = 100*2/255 = 0) and
	// the peer (node 1) loses the tie — so no yield.
	peer.SetMonitorWeight(1, "ge-1/0/0", true, 253)
	owner.handlePeerHeartbeat(peer.buildHeartbeat())
	owner.SetRGReady(1, false, []string{"XDP attachment lost"})
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if !owner.IsLocalPrimary(1) {
		t.Fatal("incumbent yielded to a peer that loses the receiver ordering (tie flap)")
	}
	ownerT, peerT := 0, 0
	lastO, lastP := true, false
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
	}
	if ownerT != 0 || peerT != 0 {
		t.Errorf("tied ordering flapped: ownerT=%d peerT=%d (want stable incumbent)", ownerT, peerT)
	}
}

// A cold-booting peer at SECONDARY/weight-1 must NOT read as yielded: both
// nodes unarmed hold the gate (no DEGRADED promote). Kills the ungated
// weight-1 arm mutant (without peerWasPrimaryThisSession): n0 promotes
// DEGRADED with a false "peer yielded" cause.
func TestNonPreemptColdBootUnarmedPeerStillHolds12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}}},
	}
	n0, n1 := NewManager(0, 1), NewManager(1, 1)
	n0.UpdateConfig(cfg)
	n1.UpdateConfig(cfg)
	t.Cleanup(func() { n0.Stop(); n1.Stop() })
	// Neither side proves its dataplane: both sit SECONDARY at weight 1.
	// n0 is additionally not ready (sync startup hold).
	n0.SetRGReady(1, false, []string{"session sync startup hold: bulk sync not yet complete"})
	exchangeElection12164(n0, n1)
	if n0.IsLocalPrimary(1) {
		t.Fatal("not-ready n0 promoted DEGRADED off a cold-booting peer (weight-1 arm fired without observed primary)")
	}
	if n1.IsLocalPrimary(1) {
		t.Fatal("n1 promoted while unarmed (cold-boot hold skipped)")
	}
}

// A kernel-upgrade-hold peer advertises weight 0 and cannot promote; the
// incumbent must keep the RG instead of yielding into an indefinite strand.
// Kills the unclamped-hold mutant (hold peer advertises 255): the RG goes
// ownerless for the life of the hold.
func TestNonPreemptArmDebtYieldSkipsKernelHoldPeer12164(t *testing.T) {
	owner, peer := armDebtPair12164(t)
	peer.SetKernelUpgradeHold("test hold")
	owner.handlePeerHeartbeat(peer.buildHeartbeat())
	if got := owner.peerGroups[1].Weight; got != 0 {
		t.Fatalf("held peer advertised weight %d, want 0 (weight-zero wire shape)", got)
	}
	owner.SetRGReady(1, false, []string{"XDP attachment lost"})
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) {
		t.Fatal("incumbent yielded to a kernel-hold peer that can never promote (indefinite strand)")
	}
}

// An arm failure INSIDE the old owner's transfer grace still hands back:
// the grace releases on a live floor-yield instead of sitting ownerless.
// Kills the ungated-grace mutant (no floor-yield release): ownerless 9/9.
func TestNonPreemptCommittedArmDebtHandsBackInsideGrace12164(t *testing.T) {
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
	// Expire only the NEW owner's grace; the OLD owner's transfer-out hold
	// stays live — the arm failure lands inside it.
	newOwner.mu.Lock()
	newOwner.peerTransferCommitGraceUntil[1] = time.Now().Add(-time.Second)
	newOwner.mu.Unlock()
	exchangeElection12164(oldOwner, newOwner)
	if oldOwner.IsLocalPrimary(1) || !newOwner.IsLocalPrimary(1) {
		t.Fatal("transfer did not settle")
	}
	newOwner.SetRGReady(1, false, []string{"last XDP link lost"})
	newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	if !oldOwner.IsLocalPrimary(1) && !newOwner.IsLocalPrimary(1) {
		t.Error("arm failure inside the old-owner grace left the RG ownerless")
	}
	if !oldOwner.IsLocalPrimary(1) {
		t.Errorf("old owner did not reclaim: old=%s new=%s",
			oldOwner.GroupState(1).State, newOwner.GroupState(1).State)
	}
}

// The committed-primary pin must use the same effective-priority ordering as
// the yield below it. A peer that loses an effective tie cannot release the
// operator's pin; otherwise the recovered old owner retakes the RG.
func TestCommittedArmDebtPinRequiresReceiverWin12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: true, NodePriorities: map[int]int{0: 100, 1: 120},
		}},
	}
	newOwner, oldOwner := NewManager(0, 1), NewManager(1, 1)
	newOwner.UpdateConfig(cfg)
	oldOwner.UpdateConfig(cfg)
	t.Cleanup(func() { newOwner.Stop(); oldOwner.Stop() })
	for _, m := range []*Manager{newOwner, oldOwner} {
		m.SetRGReady(1, true, nil)
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(oldOwner, newOwner)
	if !oldOwner.IsLocalPrimary(1) {
		t.Fatal("precondition: preferred old owner is not primary")
	}
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
	if !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
		t.Fatal("committed transfer to new owner did not settle")
	}

	// Both effective priorities truncate to zero: the pin owner is node 0
	// at weight 1, while node 1's ordinary debt leaves weight 2. Node 1
	// loses the tie, so the committed-primary pin must not be released.
	oldOwner.SetMonitorWeight(1, "ge-1/0/0", true, 253)
	exchangeElection12164(oldOwner, newOwner)
	newOwner.SetRGReady(1, false, []string{"last XDP link lost"})
	newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	newOwner.mu.RLock()
	pinned := newOwner.groups[1].transferCommitRolePinned
	newOwner.mu.RUnlock()
	if !pinned || !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
		t.Fatal("committed-primary pin released for a peer that loses the receiver ordering")
	}

	newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	newOwner.SetRGReady(1, true, nil)
	oldOwner.SetMonitorWeight(1, "ge-1/0/0", false, 253)
	exchangeElection12164(oldOwner, newOwner)
	if !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
		t.Fatal("recovered old owner retook the committed RG after a tie-lost pin release")
	}
}

// The committed-primary pin must also release for an effective tie the peer
// wins by node ID. Kills removal of the tie-winner half of the ordering gate.
// The preempt arm hands back through the preempt branch; the non-preempt arm
// must fall through to the tie-win yield, killing the Y-notw mutant
// (tie-win disjunct removal) that the preempt-only cell could never see.
func TestCommittedArmDebtPinYieldsToTiedLowerNode12164(t *testing.T) {
	for _, preempt := range []bool{true, false} {
		name := "preempt"
		if !preempt {
			name = "non-preempt"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.ClusterConfig{
				ControlInterface: "em0",
				RedundancyGroups: []*config.RedundancyGroup{{
					ID: 1, Preempt: preempt, NodePriorities: map[int]int{0: 100, 1: 100},
				}},
			}
			newOwner, oldOwner := NewManager(1, 1), NewManager(0, 1)
			newOwner.UpdateConfig(cfg)
			oldOwner.UpdateConfig(cfg)
			t.Cleanup(func() { newOwner.Stop(); oldOwner.Stop() })
			for _, m := range []*Manager{newOwner, oldOwner} {
				m.SetRGReady(1, true, nil)
				m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
			}
			exchangeElection12164(oldOwner, newOwner)
			if !oldOwner.IsLocalPrimary(1) {
				t.Fatal("precondition: lower-node-ID old owner is not primary")
			}
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
			if !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
				t.Fatal("committed transfer to new owner did not settle")
			}

			// Both priorities truncate to zero (old owner at w2, committed owner at
			// w1); node 0 wins the effective tie against node 1 and should reclaim.
			oldOwner.SetMonitorWeight(1, "ge-1/0/0", true, 253)
			exchangeElection12164(oldOwner, newOwner)
			newOwner.SetRGReady(1, false, []string{"last XDP link lost"})
			newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			exchangeElection12164(oldOwner, newOwner)
			newOwner.mu.RLock()
			pinned := newOwner.groups[1].transferCommitRolePinned
			newOwner.mu.RUnlock()
			if pinned {
				t.Fatal("committed-primary pin remained for a peer that wins the effective tie")
			}
			if !oldOwner.IsLocalPrimary(1) || newOwner.IsLocalPrimary(1) {
				t.Fatalf("pin released but tie-winning peer did not take over: new primary=%v, peer primary=%v",
					newOwner.IsLocalPrimary(1), oldOwner.IsLocalPrimary(1))
			}
		})
	}
}

// The weight-1 arm's observed-primary bit belongs to one peer session only.
// A restarted peer at the cold-boot floor must not inherit its prior session's
// history and trigger a DEGRADED promotion.
func TestNonPreemptArmDebtPinClearsHistoryOnSessionChange12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, NodePriorities: map[int]int{0: 100, 1: 200},
		}},
	}
	peer, local := NewManager(1, 1), NewManager(0, 1)
	peer.UpdateConfig(cfg)
	local.UpdateConfig(cfg)
	t.Cleanup(func() { peer.Stop(); local.Stop() })
	for _, m := range []*Manager{peer, local} {
		m.SetRGReady(1, true, nil)
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(local, peer)
	if !peer.IsLocalPrimary(1) || local.IsLocalPrimary(1) {
		t.Fatal("precondition: peer must be primary")
	}
	local.SetRGReady(1, false, []string{"session sync startup hold"})
	local.handlePeerHeartbeat(peer.buildHeartbeat())
	local.mu.RLock()
	observedPrimary := local.peerGroups[1].peerWasPrimaryThisSession
	local.mu.RUnlock()
	if !observedPrimary {
		t.Fatal("fixture: local manager did not observe peer as primary")
	}

	restartedPeer := NewManager(1, 1)
	restartedPeer.UpdateConfig(cfg)
	t.Cleanup(restartedPeer.Stop)
	if restartedPeer.LocalProcessToken() == peer.LocalProcessToken() {
		t.Fatal("fixture: restarted peer reused its process session")
	}
	local.handlePeerHeartbeat(restartedPeer.buildHeartbeat())
	local.mu.RLock()
	cleared := !local.peerGroups[1].peerWasPrimaryThisSession
	local.mu.RUnlock()
	if !cleared {
		t.Fatal("peer PRIMARY history survived a peer-session change")
	}
	exchangeElection12164(local, restartedPeer)
	if local.IsLocalPrimary(1) || local.GroupState(1).DegradedPromoted {
		t.Fatal("not-ready local promoted DEGRADED from a restarted cold-boot peer")
	}
}

// The old-owner secondary pin also requires observed-primary history before
// releasing its transfer grace. A restarted peer that never owned the RG must
// not be mistaken for a live floor-yield.
func TestCommittedSecondaryPinRequiresObservedPeer12164(t *testing.T) {
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
	exchangeElection12164(oldOwner, newOwner)
	if oldOwner.IsLocalPrimary(1) || !newOwner.IsLocalPrimary(1) {
		t.Fatal("committed transfer did not settle")
	}

	restartedPeer := NewManager(1, 1)
	restartedPeer.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	})
	t.Cleanup(restartedPeer.Stop)
	oldOwner.handlePeerHeartbeat(restartedPeer.buildHeartbeat())
	restartedPeer.handlePeerHeartbeat(oldOwner.buildHeartbeat())
	oldOwner.handlePeerHeartbeat(restartedPeer.buildHeartbeat())
	oldOwner.mu.RLock()
	peerWasPrimary := oldOwner.peerGroups[1].peerWasPrimaryThisSession
	pinned := oldOwner.groups[1].transferCommitRolePinned
	oldOwner.mu.RUnlock()
	if peerWasPrimary {
		t.Fatal("restarted peer unexpectedly had PRIMARY history")
	}
	if !pinned || oldOwner.IsLocalPrimary(1) {
		t.Fatal("secondary pin/grace released for a restarted peer never observed primary")
	}
}
