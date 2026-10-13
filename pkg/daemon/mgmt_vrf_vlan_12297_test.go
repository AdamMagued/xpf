package daemon

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

func TestManagementVRFVLANUnits12297(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:        "fxp0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
		"ge-0/0/0": {
			Name:        "ge-0/0/0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
	}
	got := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if !got[name] {
			t.Errorf("managementVRFIfaceSet omitted %s: %#v", name, got)
		}
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-0.100"} {
		if got[name] {
			t.Errorf("non-management VLAN device %s was included: %#v", name, got)
		}
	}
}

func TestUnzonedManagementVLANUnitDoesNotFailRebind12297(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set interfaces fxp0 vlan-tagging",
		"set interfaces fxp0 unit 100 vlan-id 100",
		"set interfaces fxp0 unit 100 family inet address 192.0.2.10/24",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of unzoned management VLAN config: %v", err)
	}
	mgmtSet := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if !mgmtSet[name] {
			t.Fatalf("management VRF set omitted configured device %s: %v", name, mgmtSet)
		}
	}

	ops := newReconcileFakeLinkOps()
	ops.links["fxp0"] = &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2},
	}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 9},
		Table:     config.ManagementVRFTableID,
	}
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(mgmtSet)

	if _, exists := ops.links["fxp0.100"]; exists {
		t.Fatal("fixture unexpectedly materialized the unzoned VLAN child")
	}
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("confirmed absence of the unzoned VLAN child must not fail commit: %v", err)
	}
}

// mgmtVLANRebindOps12297 records LinkSetMaster on the link itself and fails
// chosen lookups with an injected error. The inherited LinkList is empty, so
// the parent's VLAN-descendant walk binds nothing: a bound VLAN unit proves the
// rebind loop bound it directly.
type mgmtVLANRebindOps12297 struct {
	*reconcileFakeLinkOps
	lookupErr map[string]error
}

func (o *mgmtVLANRebindOps12297) LinkByName(name string) (netlink.Link, error) {
	if err := o.lookupErr[name]; err != nil {
		return nil, err
	}
	return o.reconcileFakeLinkOps.LinkByName(name)
}

func (o *mgmtVLANRebindOps12297) LinkSetMaster(link, master netlink.Link) error {
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

// newMgmtVLANRebindFixture12297 publishes fxp0 and its present tagged unit
// fxp0.100. The daemon lookup (linkByNameFn) and the routing manager read the
// same fake kernel, as they read the same netlink in production.
func newMgmtVLANRebindFixture12297() (*Daemon, *mgmtVLANRebindOps12297, *config.Config) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:        "fxp0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
	}
	ops := &mgmtVLANRebindOps12297{
		reconcileFakeLinkOps: newReconcileFakeLinkOps(),
		lookupErr:            map[string]error{},
	}
	ops.links["fxp0"] = &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2},
	}
	ops.links["fxp0.100"] = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100", Index: 3, ParentIndex: 2},
		VlanId:    100,
	}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 9},
		Table:     config.ManagementVRFTableID,
	}
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(managementVRFIfaceSet(cfg))
	return d, ops, cfg
}

// A present configured VLAN unit is not a skip candidate: the authoritative
// rebind must bind it to vrf-mgmt itself.
func TestPresentManagementVLANUnitIsRebound12297(t *testing.T) {
	d, ops, cfg := newMgmtVLANRebindFixture12297()
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("rebind with fxp0.100 present: %v", err)
	}
	vrfIndex := ops.links[config.ManagementVRFDeviceName].Attrs().Index
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if got := ops.links[name].Attrs().MasterIndex; got != vrfIndex {
			t.Errorf("%s MasterIndex = %d, want vrf-mgmt index %d", name, got, vrfIndex)
		}
	}
}

// Only netlink.LinkNotFoundError confirms absence. Any other lookup error must
// leave the unit on the bind path, whose failure fails the commit closed.
func TestManagementVLANUnitLookupErrorFailsRebind12297(t *testing.T) {
	d, ops, cfg := newMgmtVLANRebindFixture12297()
	lookupErr := errors.New("injected fxp0.100 lookup failure")
	ops.lookupErr["fxp0.100"] = lookupErr
	err := d.rebindManagementVRFIfaces(cfg)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("rebind error = %v, want the fxp0.100 lookup failure", err)
	}
}
