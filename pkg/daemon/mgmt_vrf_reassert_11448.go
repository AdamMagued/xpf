package daemon

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

var mgmtVRFReassertInterval = 30 * time.Second

// mgmtVRFReassertLoop is the persistent owner of published management-interface
// membership in vrf-mgmt. networkd reloads, driver resets, and out-of-band
// `ip link set nomaster` can remove the binding between config applies.
func (d *Daemon) mgmtVRFReassertLoop(ctx context.Context) {
	t := time.NewTicker(mgmtVRFReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertMgmtVRFOnce(ctx)
		}
	}
}

// reassertMgmtVRFOnce restores drifted members under applySem, then refreshes
// their DHCP routes in the management table. Its quick gate also watches the
// active transport's sticky binding mismatch, since kernel drift may already
// have been repaired before the background pass runs.
func (d *Daemon) reassertMgmtVRFOnce(ctx context.Context) {
	if d.applySem == nil {
		return
	}
	bindingChanged := d.activeTransport().BindingChanged
	var drifted []string
	if d.routing != nil {
		drifted = d.mgmtVRFInterfacesOutsideVRF()
	}
	if len(drifted) == 0 && !bindingChanged {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)

	bindingChanged = d.activeTransport().BindingChanged
	drifted = nil
	if d.routing != nil {
		drifted = d.mgmtVRFInterfacesOutsideVRF()
	}
	if len(drifted) == 0 && !bindingChanged {
		return
	}
	rebound := false
	for _, name := range drifted {
		slog.Warn("management interface outside the management VRF — re-binding",
			"interface", name)
		if err := d.routing.BindInterfaceToVRF(name, config.ManagementVRFInstanceName); err != nil {
			slog.Error("management-VRF bind failed; will retry",
				"interface", name, "err", err)
			continue
		}
		rebound = true
		slog.Info("management interface bound to the management VRF", "interface", name)
	}
	if rebound || bindingChanged {
		var cfg *config.Config
		if d.store != nil {
			cfg = d.store.ActiveConfig()
		}
		if cfg != nil && cfg.Chassis.Cluster != nil && !d.inBootstrap() {
			d.reconcileClusterTransportBinding(cfg, false)
		}
	}
	if len(drifted) > 0 {
		routeErr := mgmtVRFRouteReconcileFn(d)
		d.noteMgmtRouteReconcileResult(routeErr)
	}
}

// mgmtVRFInterfacesOutsideVRF reports published management interfaces whose
// kernel master differs from vrf-mgmt. Missing links and a missing VRF device
// are left to the normal apply/reconcile owners; healthy links cause no writes.
func (d *Daemon) mgmtVRFInterfacesOutsideVRF() []string {
	mgmtSet := d.mgmtVRFIfaceSet()
	if len(mgmtSet) == 0 {
		return nil
	}
	vrf, err := d.fabricLinkByName(config.ManagementVRFDeviceName)
	if err != nil || vrf == nil || vrf.Attrs() == nil {
		return nil
	}

	var drifted []string
	for name := range mgmtSet {
		link, err := d.fabricLinkByName(name)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		if link.Attrs().MasterIndex != vrf.Attrs().Index {
			drifted = append(drifted, name)
		}
	}
	sort.Strings(drifted)
	return drifted
}
