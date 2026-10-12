package daemon

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const vrfRetry12168ChildEnv = "XPF_VRF_RETRY_12168_CHILD"

// isolatedVRFRetryChild12168 gives each real-kernel test its own user, network,
// and mount namespaces. The child test name is explicit so the outer process
// can invoke one acceptance case without rerunning the whole package.
func isolatedVRFRetryChild12168(t *testing.T) bool {
	t.Helper()
	if os.Getenv(vrfRetry12168ChildEnv) == t.Name() {
		return true
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare unavailable for isolated VRF test: %v", err)
	}
	cmd := exec.Command(unshare, "-Urnm", "--propagation", "private", "--", os.Args[0],
		"-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), vrfRetry12168ChildEnv+"="+t.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(strings.ToLower(string(output)), "operation not permitted") {
			t.Skipf("cannot create isolated user/network/mount namespaces: %s", output)
		}
		t.Fatalf("isolated VRF acceptance process failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "--- SKIP:") {
		t.Skipf("isolated kernel VRF prerequisite unavailable: %s", output)
	}
	t.Logf("isolated kernel VRF acceptance output:\n%s", output)
	return false
}

func newKernelVRFRetryFixture12168(t *testing.T) (*Daemon, *config.Config, netlink.Link, netlink.Link) {
	t.Helper()
	installFakeNetworkctl(t)
	useTemporaryDNSReconciler12168(t)
	stateDir := t.TempDir()
	if err := unix.Mount(stateDir, "/var/lib/xpf", "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot isolate keyed heartbeat epoch state: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount("/var/lib/xpf", 0); err != nil {
			t.Errorf("unmount isolated HA state directory: %v", err)
		}
	})

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName}, Table: config.ManagementVRFTableID}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create management VRF in isolated namespace: %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring up management VRF: %v", err)
	}
	control := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0"}}
	if err := netlink.LinkAdd(control); err != nil {
		t.Fatalf("create control interface: %v", err)
	}
	if err := netlink.LinkSetUp(control); err != nil {
		t.Fatalf("bring up control interface: %v", err)
	}
	addr, err := netlink.ParseAddr("198.51.100.1/24")
	if err != nil {
		t.Fatalf("parse control address: %v", err)
	}
	if err := netlink.AddrAdd(control, addr); err != nil {
		t.Fatalf("assign control address: %v", err)
	}
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-key-12168",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 198.51.100.2",
		"set interfaces em0 unit 0 family inet address 198.51.100.1/24",
	})
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture did not compile cluster config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		store:     store,
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: ctx,
		opts:      Options{NoDataplane: true},
	}
	t.Cleanup(func() {
		d.stopClusterComms()
		d.cluster.Stop() // join keyed-epoch persistence before the state mount is removed
		cancel()
	})
	return d, cfg, control, vrf
}

// TestFailedBootConvergenceBindsHeartbeatToManagementVRF12168 drives the real
// apply-tail restart path and verifies the replacement heartbeat records a
// successful SO_BINDTODEVICE bind to vrf-mgmt.
func TestFailedBootConvergenceBindsHeartbeatToManagementVRF12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, control, vrf := newKernelVRFRetryFixture12168(t)

	// Failed boot apply: comms starts while the published management-VRF set is
	// still nil, so the first heartbeat is successfully installed unbound.
	d.publishMgmtVRFIfaces(nil)
	d.startClusterComms(d.daemonCtx)
	waitForHeartbeatVRF12168(t, d.cluster, "")
	if got := d.activeTransport().VRFDevice; got != "" {
		t.Fatalf("failed-boot transport unexpectedly selected VRF %q", got)
	}

	// Converging apply: install the VRF master and publish the membership before
	// step 20 compares the active and candidate transport keys.
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatalf("enslave control interface to management VRF: %v", err)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	if got := d.activeTransport().VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("converged transport VRF = %q, want %q", got, config.ManagementVRFDeviceName)
	}
}

// TestWarmHeartbeatRetryResolvesNewVRFMembership12168 exercises the warm
// retry transition with a real kernel VRF and assigned control address. The
// resolver must run inside each attempt: after em0 is enslaved but before its
// membership is published, an unbound bind fails; publishing membership lets
// the next attempt bind its real sockets to vrf-mgmt.
func TestWarmHeartbeatRetryResolvesNewVRFMembership12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, _, control, vrf := newKernelVRFRetryFixture12168(t)
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatalf("enslave control interface to management VRF: %v", err)
	}
	d.publishMgmtVRFIfaces(nil)
	ctx, cancel := context.WithTimeout(d.daemonCtx, 7*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		d.startHeartbeatWithRetry(ctx, "em0", "198.51.100.2")
		close(done)
	}()
	time.Sleep(150 * time.Millisecond)
	if d.cluster.HeartbeatRunning() {
		t.Fatal("premise failed: heartbeat started before VRF membership was published")
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat retry did not finish after publishing VRF membership")
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
}

func waitForHeartbeatVRF12168(t *testing.T, manager *cluster.Manager, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if manager.HeartbeatRunning() && manager.HeartbeatVRFDevice() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("heartbeat did not become running with VRF device %q (running=%v device=%q)",
		want, manager.HeartbeatRunning(), manager.HeartbeatVRFDevice())
}
