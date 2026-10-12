package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestArmDebtExcludesRG0WhileRG1Yields12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	}
	n0, n1 := NewManager(0, 1), NewManager(1, 1)
	n0.UpdateConfig(cfg)
	n1.UpdateConfig(cfg)
	t.Cleanup(func() { n0.Stop(); n1.Stop() })
	for _, m := range []*Manager{n0, n1} {
		for _, rg := range []int{0, 1} {
			m.SetRGReady(rg, true, nil)
			m.SetMonitorWeight(rg, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
		}
	}
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(0) || !n0.IsLocalPrimary(1) {
		t.Fatalf("precondition: node0 owns RG0+RG1 (rg0=%v rg1=%v)", n0.IsLocalPrimary(0), n0.IsLocalPrimary(1))
	}

	// The daemon arm-failure path applies arm debt to every RG. Election must
	// exclude config-authority RG0 while still yielding data RG1.
	for _, rg := range []int{0, 1} {
		n0.SetRGReady(rg, false, []string{"dataplane arm FAILED"})
		n0.SetMonitorWeight(rg, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	}
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(0) || n1.IsLocalPrimary(0) {
		t.Fatalf("arm debt moved RG0: n0=%v n1=%v", n0.IsLocalPrimary(0), n1.IsLocalPrimary(0))
	}
	if n0.IsLocalPrimary(1) || !n1.IsLocalPrimary(1) {
		t.Fatalf("arm debt did not yield RG1: n0=%v n1=%v", n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}

	// Recovery clears the debt, but non-preempt ownership remains where it
	// moved; RG0 remains with its original config-authority owner.
	for _, rg := range []int{0, 1} {
		n0.SetMonitorWeight(rg, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
		n0.SetRGReady(rg, true, nil)
	}
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(0) || n1.IsLocalPrimary(0) || n0.IsLocalPrimary(1) || !n1.IsLocalPrimary(1) {
		t.Fatalf("unexpected ownership after recovery: RG0 n0=%v n1=%v; RG1 n0=%v n1=%v",
			n0.IsLocalPrimary(0), n1.IsLocalPrimary(0), n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
}

// A committed RG0 primary also keeps its pin under arm debt, even when its
// prior owner has greater raw weight and wins receiver ordering.
func TestArmDebtKeepsCommittedRG0Pin12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 0, NodePriorities: map[int]int{0: 100, 1: 200},
		}},
	}
	newOwner, oldOwner := NewManager(0, 1), NewManager(1, 1)
	newOwner.UpdateConfig(cfg)
	oldOwner.UpdateConfig(cfg)
	t.Cleanup(func() { newOwner.Stop(); oldOwner.Stop() })
	for _, m := range []*Manager{newOwner, oldOwner} {
		m.SetRGReady(0, true, nil)
		m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(oldOwner, newOwner)
	if !oldOwner.IsLocalPrimary(0) || newOwner.IsLocalPrimary(0) {
		t.Fatal("precondition: old owner primary")
	}
	newOwner.SetPeerFailoverFunc(func(id int) (uint64, error) {
		_, err := oldOwner.ManualFailover(id)
		return 12164, err
	})
	newOwner.SetPeerFailoverCommitFunc(func(id int, requestID uint64) error {
		return oldOwner.FinalizePeerTransferOut(id)
	})
	if err := newOwner.RequestPeerFailover(0); err != nil {
		t.Fatalf("commit RG0 transfer: %v", err)
	}
	newOwner.mu.Lock()
	newOwner.peerTransferCommitGraceUntil[0] = time.Now().Add(-time.Second)
	newOwner.mu.Unlock()
	oldOwner.mu.Lock()
	oldOwner.localTransferOutHoldUntil[0] = time.Now().Add(-time.Second)
	oldOwner.mu.Unlock()
	exchangeElection12164(oldOwner, newOwner)
	if !newOwner.IsLocalPrimary(0) || oldOwner.IsLocalPrimary(0) {
		t.Fatal("committed transfer to new owner did not settle")
	}

	newOwner.SetRGReady(0, false, []string{"dataplane arm FAILED"})
	newOwner.SetMonitorWeight(0, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	newOwner.mu.RLock()
	pinned := newOwner.groups[0].transferCommitRolePinned
	newOwner.mu.RUnlock()
	if !pinned || !newOwner.IsLocalPrimary(0) || oldOwner.IsLocalPrimary(0) {
		t.Fatalf("arm debt released committed RG0 pin: pinned=%v newPrimary=%v oldPrimary=%v",
			pinned, newOwner.IsLocalPrimary(0), oldOwner.IsLocalPrimary(0))
	}
}

// Both nodes at the arm-debt floor (w1/w1). The higher-node-ID incumbent
// must keep the RG: the peer wins the effective tie by node ID but has no
// greater raw weight, so yielding would only move a blackholed RG.
func TestBothFloorIncumbentKeeps12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, NodePriorities: map[int]int{0: 100, 1: 200},
		}},
	}
	n0, n1 := NewManager(0, 1), NewManager(1, 1)
	n0.UpdateConfig(cfg)
	n1.UpdateConfig(cfg)
	t.Cleanup(func() { n0.Stop(); n1.Stop() })
	for _, m := range []*Manager{n0, n1} {
		m.SetRGReady(1, true, nil)
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(n0, n1)
	if !n1.IsLocalPrimary(1) || n0.IsLocalPrimary(1) {
		t.Fatal("precondition: n1 primary")
	}
	n0.SetRGReady(1, false, []string{"XDP attachment lost"})
	n0.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(n0, n1)
	n1.SetRGReady(1, false, []string{"XDP attachment lost"})
	n1.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(n0, n1)
	moves := 0
	last := n1.IsLocalPrimary(1)
	for range 8 {
		n1.handlePeerHeartbeat(n0.buildHeartbeat())
		n0.handlePeerHeartbeat(n1.buildHeartbeat())
		if now := n1.IsLocalPrimary(1); now != last {
			moves++
			last = now
		}
	}
	t.Logf("w0=%d w1=%d n0Primary=%v n1Primary=%v moves=%d",
		n0.GroupState(1).Weight, n1.GroupState(1).Weight,
		n0.IsLocalPrimary(1), n1.IsLocalPrimary(1), moves)
	if !n1.IsLocalPrimary(1) || n0.IsLocalPrimary(1) || moves != 0 {
		t.Fatalf("both-floor incumbent moved the RG: n1Primary=%v n0Primary=%v moves=%d",
			n1.IsLocalPrimary(1), n0.IsLocalPrimary(1), moves)
	}
}

// After a committed transfer to n1, the arm-debt floor on both nodes must
// preserve the pin: old owner n0 wins the effective tie but has no greater
// raw weight, so an ordering-only pin release would be unsafe.
func TestBothFloorCommittedPinHolds12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: true, NodePriorities: map[int]int{0: 100, 1: 100},
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
		t.Fatal("precondition: old owner primary")
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
		t.Fatal("committed transfer did not settle")
	}
	oldOwner.SetRGReady(1, false, []string{"XDP attachment lost"})
	oldOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	newOwner.SetRGReady(1, false, []string{"XDP attachment lost"})
	newOwner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	exchangeElection12164(oldOwner, newOwner)
	newOwner.mu.RLock()
	pinned := newOwner.groups[1].transferCommitRolePinned
	newOwner.mu.RUnlock()
	t.Logf("pinned=%v newPrimary=%v oldPrimary=%v", pinned,
		newOwner.IsLocalPrimary(1), oldOwner.IsLocalPrimary(1))
	if !pinned || !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
		t.Fatalf("both-floor pin released/moved: pinned=%v newPrimary=%v oldPrimary=%v",
			pinned, newOwner.IsLocalPrimary(1), oldOwner.IsLocalPrimary(1))
	}
}
