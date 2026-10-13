package routing

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

type childBindOps12297 struct {
	*fakeVRFOps
	masterCalls int
}

func (o *childBindOps12297) LinkSetMaster(iface, master netlink.Link) error {
	o.masterCalls++
	iface.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func TestBindManagementVLANDescendants12297(t *testing.T) {
	base := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10}}
	// A hand-built LinkAttrs zero-values NetNsID to 0, a real foreign nsid.
	// Links the walk inspects carry the -1 netlink reports for a local parent,
	// so only the kind check excludes ordinary0.
	child := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100", Index: 11, ParentIndex: 10, NetNsID: netnsIDLocal}, VlanId: 100}
	grandchild := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100.200", Index: 12, ParentIndex: 11, NetNsID: netnsIDLocal}, VlanId: 200}
	ordinaryChild := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ordinary0", Index: 13, ParentIndex: 10, NetNsID: netnsIDLocal}}
	ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
	for _, link := range []netlink.Link{base, child, grandchild, ordinaryChild} {
		ops.overlay[link.Attrs().Name] = link
		ops.extraLinks = append(ops.extraLinks, link)
	}
	ops.seed("vrf-mgmt", 999)
	ops.links["vrf-mgmt"].LinkAttrs.Index = 99
	manager := &vrfManager{ops: ops}

	if err := manager.BindInterfaceToVRF("fxp0", "mgmt"); err != nil {
		t.Fatalf("BindInterfaceToVRF: %v", err)
	}
	for _, link := range []netlink.Link{base, child, grandchild} {
		if got := link.Attrs().MasterIndex; got != 99 {
			t.Errorf("%s master index = %d, want vrf-mgmt index 99", link.Attrs().Name, got)
		}
	}
	if got := ordinaryChild.Attrs().MasterIndex; got != 0 {
		t.Errorf("non-VLAN child master index = %d, want unchanged 0", got)
	}
	if ops.masterCalls != 3 {
		t.Fatalf("LinkSetMaster calls = %d, want parent and two VLAN descendants", ops.masterCalls)
	}
	if err := manager.BindInterfaceToVRF("fxp0", "mgmt"); err != nil {
		t.Fatalf("idempotent BindInterfaceToVRF: %v", err)
	}
	if ops.masterCalls != 3 {
		t.Errorf("already-bound links were rebound: LinkSetMaster calls = %d, want 3", ops.masterCalls)
	}
}
func TestBindManagementVLANDescendantsReportsLinkListFailure12297(t *testing.T) {
	base := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10}}
	ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
	ops.overlay[base.Attrs().Name] = base
	ops.extraLinks = append(ops.extraLinks, base)
	ops.seed("vrf-mgmt", 999)
	ops.links["vrf-mgmt"].LinkAttrs.Index = 99
	listErr := errors.New("injected link-list failure")
	ops.linkListErr = listErr

	err := (&vrfManager{ops: ops}).BindInterfaceToVRF("fxp0", "mgmt")
	if !errors.Is(err, listErr) {
		t.Fatalf("BindInterfaceToVRF error = %v, want wrapped link-list failure", err)
	}
}

// Only a bind into vrf-mgmt walks VLAN descendants. A member bound to any other
// VRF moves alone and its VLAN children keep their own masters, even when the
// member has a management-class name.
func TestBindNonManagementVRFLeavesVLANChildren12297(t *testing.T) {
	for _, parentName := range []string{"fxp0", "ge-0-0-0"} {
		t.Run(parentName, func(t *testing.T) {
			parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: parentName, Index: 10}}
			child := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: parentName + ".100", Index: 11, ParentIndex: 10, NetNsID: netnsIDLocal}, VlanId: 100}
			ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
			for _, link := range []netlink.Link{parent, child} {
				ops.overlay[link.Attrs().Name] = link
				ops.extraLinks = append(ops.extraLinks, link)
			}
			ops.seed("vrf-blue", 1001)
			ops.links["vrf-blue"].LinkAttrs.Index = 77

			if err := (&vrfManager{ops: ops}).BindInterfaceToVRF(parentName, "blue"); err != nil {
				t.Fatalf("BindInterfaceToVRF: %v", err)
			}
			if got := parent.Attrs().MasterIndex; got != 77 {
				t.Errorf("%s master index = %d, want vrf-blue index 77", parentName, got)
			}
			if got := child.Attrs().MasterIndex; got != 0 {
				t.Errorf("%s master index = %d, want unchanged 0", child.Attrs().Name, got)
			}
			if ops.masterCalls != 1 {
				t.Errorf("LinkSetMaster calls = %d, want only the member", ops.masterCalls)
			}
		})
	}
}

// A VLAN whose real_dev is in another namespace keeps that namespace's ifindex
// as ParentIndex, so it can equal fxp0's local ifindex. Netlink marks it with
// a NetNsID other than -1; 0 is the first nsid a namespace assigns. The walk
// must not bind it or descend into a local VLAN stacked on it, and must still
// bind fxp0's own VLAN child.
func TestBindManagementVLANDescendantsSkipsForeignNamespace12297(t *testing.T) {
	for _, nsid := range []int{0, 3} {
		t.Run(fmt.Sprintf("netnsid_%d", nsid), func(t *testing.T) {
			base := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10}}
			local := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100", Index: 11, ParentIndex: 10, NetNsID: netnsIDLocal}, VlanId: 100}
			foreign := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "foreign7", Index: 20, ParentIndex: 10, NetNsID: nsid}, VlanId: 7}
			stacked := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "foreign7.30", Index: 21, ParentIndex: 20, NetNsID: netnsIDLocal}, VlanId: 30}
			ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
			for _, link := range []netlink.Link{base, local, foreign, stacked} {
				ops.overlay[link.Attrs().Name] = link
				ops.extraLinks = append(ops.extraLinks, link)
			}
			ops.seed("vrf-mgmt", 999)
			ops.links["vrf-mgmt"].LinkAttrs.Index = 99

			if err := (&vrfManager{ops: ops}).BindInterfaceToVRF("fxp0", "mgmt"); err != nil {
				t.Fatalf("BindInterfaceToVRF: %v", err)
			}
			for _, link := range []netlink.Link{base, local} {
				if got := link.Attrs().MasterIndex; got != 99 {
					t.Errorf("%s master index = %d, want vrf-mgmt index 99", link.Attrs().Name, got)
				}
			}
			for _, link := range []netlink.Link{foreign, stacked} {
				if got := link.Attrs().MasterIndex; got != 0 {
					t.Errorf("%s master index = %d, want unchanged 0", link.Attrs().Name, got)
				}
			}
			if ops.masterCalls != 2 {
				t.Errorf("LinkSetMaster calls = %d, want fxp0 and fxp0.100 only", ops.masterCalls)
			}
		})
	}
}
