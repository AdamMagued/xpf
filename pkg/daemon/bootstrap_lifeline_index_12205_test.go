package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// #12205 (C-016/U-024 <- D8-10): pin the no-.link/any-file-write half of the
// index-refusal contract in setupBootstrapLifeline.
//
// Overlap, stated plainly: TestBootstrapNonIndexRemedyIsActionable12151
// (#12151, merged after this PR opened) already drives these refusals end to
// end — its "higher PCI index" and "non-PCI management route" rows assert no
// rename, no reload and no fxp0 .network on exactly the shapes below. This
// file's UNIQUE contribution is the file-creation half 12151 does not assert:
// no .link write (and no file of any kind) on the index-1 and absent-index
// refusals. A mutant that writes the .link before the guard fails ONLY these
// two cells — every 12151/6789/7114/12156 control stays green — which is the
// proof this file earns its keep (see docs/log/12205.md).
//
// Production is correct as-is: the guards are explicit and return before the
// .network write, the .link write, the rename and the reload. This file is
// TEST-ONLY. The two cells drive the REAL setupBootstrapLifeline through its
// existing seams with a SUCCESSFUL default-route observation, and assert the
// refusal contract: no fxp0 .network, no .link, no rename, no reload.
//
// Deliberately NOT asserted: the lifeline record. writeLifelineRecord runs
// BEFORE the index refusals, so a "zero writes whatsoever" assertion would
// misstate the contract (reviewer consensus on C-016/U-024). The record may or
// may not exist; the naming/contract mutations must not.
//
// The tightening controls already exist. The index-0 complete-observation
// control TestCompleteObservationStillWritesAndRenames6789 proves the .network
// still writes and networkd reloads. The kernel-name first-rename control
// TestBootstrapFirstRenameWritesKernelOriginal12156 proves an index-0
// lifeline still under its kernel name still renames and persists
// OriginalName=. A change that refuses everywhere cannot satisfy these
// controls.

// lifelineIndexSeams12205 builds on staticLifelineSeams (#6789) with the
// fixture shape #12205 needs: the given enumeration, a SUCCESSFUL
// default-route observation naming lifeline, and observable (static)
// addressing. The addressing observation succeeds on purpose: under a weakened
// guard the snapshot completes and the .network/rename/reload all run, which
// is what makes the cells below fail on the mutant instead of passing
// vacuously through a later refusal.
func lifelineIndexSeams12205(t *testing.T, lifeline string, nics []pciNIC) lifelineSeamState {
	t.Helper()
	st := staticLifelineSeams(t)
	detectLifelineInterfaceFn = func() (string, bool, error) { return lifeline, true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) { return nics, nil }
	lifelineLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: lifeline, Index: 7}}, nil
	}
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}
	return st
}

// assertLifelineIndexRefused12205 checks the refusal side effects. The absent
// fixture takes the dedicated idx == -1 return; the index-1 fixture takes the
// later idx != 0 return. Both must return before the .network/.link writes,
// rename and reload. The pre-guard lifeline record is intentionally not
// examined (see the file comment).
func assertLifelineIndexRefused12205(t *testing.T, st lifelineSeamState, lifeline string, idx int) {
	t.Helper()
	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	if data, err := os.ReadFile(netPath); err == nil {
		t.Errorf("a bootstrap fxp0 .network was written for %s at enumeration index %d; "+
			"only index 0 becomes fxp0, so the lifeline must refuse before the .network "+
			"write (#12205). content:\n%s", lifeline, idx, data)
	}
	if got := filesIn(t, st.linkDir); len(got) != 0 {
		t.Errorf("files were written for %s at enumeration index %d, but the refusal "+
			"must precede the .network AND the .link writes: %v (#12205)",
			lifeline, idx, got)
	}
	if *st.renamed {
		t.Errorf("the management NIC %s at enumeration index %d was RENAMED; it would not "+
			"become fxp0, so renaming it breaks the mgmt naming contract on a box "+
			"reachable only over that NIC (#12205)", lifeline, idx)
	}
	if *st.reloaded {
		t.Errorf("networkctl reload ran for %s at enumeration index %d even though the refusal "+
			"must precede the .network/.link writes and rename (#12205)", lifeline, idx)
	}
}

// TestSetupBootstrapLifelineRefusesIndex112205: the default route names
// enumeration index 1. That NIC would NOT become fxp0 (idx 0 -> fxp0), so the
// lifeline must refuse before the .network write, the .link write, the rename
// and the reload.
//
// FAIL-ON-REVERT / MUTANT: weakening the guard to `idx < 0` (or deleting the
// guard) lets index 1 through; the addressing observation succeeds, so the
// .network IS written, the NIC IS renamed and networkd IS reloaded, reddening
// every assertion above.
func TestSetupBootstrapLifelineRefusesIndex112205(t *testing.T) {
	const lifeline = "enp6s0"
	st := lifelineIndexSeams12205(t, lifeline, []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: lifeline},
	})

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	assertLifelineIndexRefused12205(t, st, lifeline, 1)
}

// TestSetupBootstrapLifelineRefusesAbsentIndex12205: the default route names a
// NIC that is NOT among the enumerated NICs, so the index lookup finds nothing
// and idx stays -1. Same refusal contract as the index-1 cell.
//
// FAIL-ON-REVERT / MUTANT: the actual absent-index kill requires disabling the
// dedicated `idx == -1` refusal AND weakening the later `idx != 0` guard to
// `idx > 0` (or removing that later guard). Either change alone is ineffective:
// `idx > 0` alone leaves the dedicated -1 return intact. With both changes,
// the successful addressing observation proceeds to every forbidden effect.
func TestSetupBootstrapLifelineRefusesAbsentIndex12205(t *testing.T) {
	const lifeline = "enp9s0"
	st := lifelineIndexSeams12205(t, lifeline, []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "enp6s0"},
	})

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	assertLifelineIndexRefused12205(t, st, lifeline, -1)
}
