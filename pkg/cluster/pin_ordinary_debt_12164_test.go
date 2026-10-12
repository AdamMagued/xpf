package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// A committed transfer must not lose its pin to ordinary monitor debt.
// Only dataplane-arm debt releases the pin (#12164).
func TestCommittedPinOrdinaryDebtHolds12164(t *testing.T) {
	for _, preempt := range []bool{true, false} {
		name := "non-preempt"
		if preempt {
			name = "preempt"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.ClusterConfig{
				ControlInterface: "em0",
				RedundancyGroups: []*config.RedundancyGroup{{
					ID: 1, Preempt: preempt, NodePriorities: map[int]int{0: 200, 1: 100},
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
			newOwner.SetMonitorWeight(1, "ge-1/0/0", true, 100)
			exchangeElection12164(oldOwner, newOwner)
			newOwner.mu.RLock()
			pinned := newOwner.groups[1].transferCommitRolePinned
			newOwner.mu.RUnlock()
			if !pinned || !newOwner.IsLocalPrimary(1) || oldOwner.IsLocalPrimary(1) {
				t.Fatalf("ordinary debt released committed pin: pinned=%v newPrimary=%v oldPrimary=%v",
					pinned, newOwner.IsLocalPrimary(1), oldOwner.IsLocalPrimary(1))
			}
		})
	}
}
