package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Production-path regressions for crash-loop election debt on a lone chassis.

// Production wiring: the type the daemon actually publishes must satisfy both
// new capabilities, or helperSupervisorState() silently defaults to healthy.
var _ helperSupervisorStateSource = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
var _ helperSupervisorNotifier = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

func newDebtProbeDaemon12159(t *testing.T, rgs ...int) (*Daemon, *cluster.Manager, *supervisorRuntime12159) {
	t.Helper()
	withTempTransitForwardSysctls(t, "1")
	cm := cluster.NewManager(0, 1)
	var groups []*config.RedundancyGroup
	for _, id := range rgs {
		groups = append(groups, &config.RedundancyGroup{ID: id, NodePriorities: map[int]int{0: 200}})
	}
	cm.UpdateConfig(&config.ClusterConfig{ControlInterface: "hb0", RedundancyGroups: groups})
	for _, id := range rgs {
		cm.SetMonitorWeight(id, cluster.DataplaneArmMonitorIface, false, cluster.DataplaneArmMonitorCost)
		cm.SetRGReady(id, true, nil)
		cm.SetGroupStateForTesting(id, cluster.StatePrimary)
	}
	rt := &supervisorRuntime12159{gateRuntime9725: &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}}
	rt.setCount(1, false)
	rt.running.Store(true)
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  cm,
		vrrpMgr:  vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	d.setDataplane(dataplane.RuntimeDataPlane(rt))
	d.transitGateOwned.Store(true)
	d.dataplaneArmed.Store(true)
	return d, cm, rt
}

// RG0 carries configuration authority and remains writable when data RGs
// resign under crash-loop debt.
func TestCrashLoopLeavesRG0WritableOnLoneNode12159(t *testing.T) {
	withBarrierRecorder(t)
	d, cm, rt := newDebtProbeDaemon12159(t, 0, 1)
	d.reassertTransitGate("healthy")
	d.reconcileRG0ConfigOwnership()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("premise: healthy RG0 primary must accept config: %v", err)
	}
	d.store.ExitConfigure()

	rt.running.Store(false)
	rt.crashLoop.Store(true)
	d.reassertTransitGate("crash-loop")
	d.reconcileRG0ConfigOwnership()
	err := d.store.EnterConfigure()
	if err == nil {
		d.store.ExitConfigure()
	}
	t.Logf("crash loop on lone node: rg0=%v rg1=%v w0=%d w1=%d readOnly=%v EnterConfigure err=%v",
		cm.GroupState(0).State, cm.GroupState(1).State, rgWeight12159(cm, 0), rgWeight12159(cm, 1),
		d.store.ClusterReadOnly(), err)
	if err != nil || d.store.ClusterReadOnly() || cm.GroupState(0).State != cluster.StatePrimary {
		t.Fatalf("data-RG crash-loop debt made lone-node configuration unavailable: err=%v rg0=%v readOnly=%v",
			err, cm.GroupState(0).State, d.store.ClusterReadOnly())
	}
}

// A fence-install failure creates arm debt (weight 1). A non-looping helper
// death and subsequent mark/tick reassertions must preserve that unrelated debt.
func TestArmDebtSurvivesHelperDeathAndMark12159(t *testing.T) {
	f := withBarrierRecorder(t)
	d, cm, rt := newDebtProbeDaemon12159(t, 1)
	d.reassertTransitGate("healthy")
	f.fenceInstall10302 = func(xnft.ForwardFenceSpec) error { return errors.New("kernel says no") }
	d.reassertTransitGate("fence-fails")
	w1 := rgWeight12159(cm, 1)

	rt.running.Store(false)
	d.reassertTransitGate("helper-dead")
	w2 := rgWeight12159(cm, 1)
	d.markDataplaneArmed("helper-dead-arm-reassert")
	w3 := rgWeight12159(cm, 1)
	d.reassertTransitGate("next-tick")
	w4 := rgWeight12159(cm, 1)
	t.Logf("fence debt weight after fence failure/death/mark/tick: %d/%d/%d/%d", w1, w2, w3, w4)
	if w1 != 1 || w2 != 1 || w3 != 1 || w4 != 1 {
		t.Fatalf("helper-down reassertion wiped unrelated arm debt: %d -> %d -> %d -> %d",
			w1, w2, w3, w4)
	}
}

// A crash-looping data RG must not auto-confirm an operator's pending commit
// or make the lone-node config store read-only through RG0 demotion.
func TestCrashLoopPreservesPendingCommitOnLoneNode12159(t *testing.T) {
	withBarrierRecorder(t)
	d, cm, rt := newDebtProbeDaemon12159(t, 0, 1)
	d.reassertTransitGate("healthy")
	d.reconcileRG0ConfigOwnership()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.LoadOverride("system { host-name A; }"); err != nil {
		t.Fatalf("LoadOverride A: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := d.store.LoadOverride("system { host-name B; }"); err != nil {
		t.Fatalf("LoadOverride B: %v", err)
	}
	if _, err := d.store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	d.store.ExitConfigure()
	if !d.store.IsConfirmPending() {
		t.Fatal("commit-confirmed precondition did not create a pending window")
	}

	rt.running.Store(false)
	rt.crashLoop.Store(true)
	d.reassertTransitGate("crash-loop")
	d.reconcileRG0ConfigOwnership()
	t.Logf("pending after crash loop=%v rg0=%v readOnly=%v",
		d.store.IsConfirmPending(), cm.GroupState(0).State, d.store.ClusterReadOnly())
	if !d.store.IsConfirmPending() || d.store.ClusterReadOnly() ||
		cm.GroupState(0).State != cluster.StatePrimary {
		t.Fatal("data-RG crash-loop debt disturbed the pending config transaction")
	}
}
