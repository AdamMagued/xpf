package daemon

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/vishvananda/netlink"
)

func newVRFBindingRetryDaemon12168(t *testing.T, lines []string, withGRPC bool) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, lines)
	ctx, cancel := context.WithCancel(context.Background())
	manager := cluster.NewManager(0, 1)
	d := &Daemon{store: store, cluster: manager, daemonCtx: ctx}
	if withGRPC {
		d.grpcSrv = grpcapi.NewServer("", grpcapi.Config{Store: store, Cluster: manager})
	}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		switch name {
		case config.ManagementVRFDeviceName:
			return vrf, nil
		case "lo":
			return link, nil
		default:
			return nil, errors.New("unknown test link")
		}
	}
	d.publishMgmtVRFIfaces(map[string]bool{"lo": true})
	t.Cleanup(func() {
		d.stopClusterComms()
		manager.Stop()
		cancel()
	})
	return d
}

func waitVRFLinkLookups12168(t *testing.T, got *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if got.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("transport resolver made %d loopback lookups, want at least %d", got.Load(), want)
}

var vrfBindingFabricConfig12168 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key binding-retry-test-12168",
	"set chassis cluster fabric-interface lo",
	"set chassis cluster fabric-peer-address 127.0.0.2",
}

// This exercises the real session-sync retry loop without namespaces. The
// occupied listener forces another Start attempt; each attempt must re-resolve
// the binding rather than reuse the value computed before the loop.
func TestSessionSyncResolvesVRFBindingPerAttempt12168(t *testing.T) {
	occupier, err := net.Listen("tcp4", "127.0.0.1:4785")
	if err != nil {
		t.Fatalf("reserve session-sync listener: %v", err)
	}
	t.Cleanup(func() { _ = occupier.Close() })
	grpcProbe, err := net.Listen("tcp4", "127.0.0.1:50051")
	if err != nil {
		t.Fatalf("check fabric gRPC listener availability: %v", err)
	}
	_ = grpcProbe.Close()

	d := newVRFBindingRetryDaemon12168(t, vrfBindingFabricConfig12168, true)
	var linkLookups atomic.Int32
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == "lo" {
			linkLookups.Add(1)
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}, nil
		}
		if name == config.ManagementVRFDeviceName {
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}, nil
		}
		return nil, errors.New("unknown test link")
	}
	d.startClusterComms(d.daemonCtx)

	// One lookup computes the epoch key, one opens session sync, and one is
	// the live gRPC listener. A session retry adds another lookup; a frozen
	// session device (M7) leaves the count at three.
	waitVRFLinkLookups12168(t, &linkLookups, 4)
}

// The fabric gRPC supervisor must refresh the device on each bind retry. Keep
// the server nil until the key and session-sync lookup have settled, then make
// its real listener retry against an occupied port. This isolates gRPC's
// resolver calls from the two startup lookups.
func TestFabricGRPCResolvesVRFBindingPerAttempt12168(t *testing.T) {
	occupier, err := net.Listen("tcp4", "127.0.0.1:50051")
	if err != nil {
		t.Fatalf("reserve fabric gRPC listener: %v", err)
	}
	t.Cleanup(func() { _ = occupier.Close() })
	sessionProbe, err := net.Listen("tcp4", "127.0.0.1:4785")
	if err != nil {
		t.Fatalf("check session-sync listener availability: %v", err)
	}
	_ = sessionProbe.Close()

	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key binding-retry-test-12168",
		"set chassis cluster control-interface lo",
		"set chassis cluster peer-address 127.0.0.2",
	}, false)
	var linkLookups atomic.Int32
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == "lo" {
			linkLookups.Add(1)
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}, nil
		}
		if name == config.ManagementVRFDeviceName {
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}, nil
		}
		return nil, errors.New("unknown test link")
	}
	d.startClusterComms(d.daemonCtx)
	waitVRFLinkLookups12168(t, &linkLookups, 2)
	time.Sleep(50 * time.Millisecond)
	baseline := linkLookups.Load()

	d.grpcSrv = grpcapi.NewServer("", grpcapi.Config{Store: d.store, Cluster: d.cluster})
	deadline := time.Now().Add(1800 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := linkLookups.Load(); got >= baseline+2 {
			t.Logf("gRPC bind retries refreshed VRF resolver %d times", got-baseline)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gRPC bind retries made %d VRF lookups after server start; want at least 2",
		linkLookups.Load()-baseline)
}

// startClusterComms must install the manager's live resolver even when no
// heartbeat is configured in the active config. The direct heartbeat stands
// in for a transport that became live after startup; restarting it must consult
// the daemon resolver instead of retaining its startup device.
func TestStartClusterCommsInstallsHeartbeatVRFResolver12168(t *testing.T) {
	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key binding-retry-test-12168",
	}, false)
	d.startClusterComms(d.daemonCtx)
	if err := d.cluster.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("start control heartbeat: %v", err)
	}

	var lookups atomic.Int32
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	d.linkByNameFn = func(string) (netlink.Link, error) {
		lookups.Add(1)
		return nil, errors.New("test link unavailable")
	}
	if !d.cluster.RestartHeartbeat() {
		t.Fatal("heartbeat restart failed with an empty-device fallback")
	}
	if got := lookups.Load(); got == 0 {
		t.Fatal("heartbeat restart did not use the resolver installed by startClusterComms (M9)")
	}
}

func TestClusterTransportBindingMismatchStaysSticky12168(t *testing.T) {
	d := &Daemon{clusterCommsGen: 9, activeClusterTransport: clusterTransportKey{
		VRFDevice: config.ManagementVRFDeviceName,
	}}
	d.noteClusterTransportBinding(9, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("off-key bind did not mark the epoch binding changed")
	}
	d.noteClusterTransportBinding(9, config.ManagementVRFDeviceName)
	if !d.activeTransport().BindingChanged {
		t.Fatal("later matching bind cleared the epoch's earlier off-key bind")
	}
	d.noteClusterTransportBinding(8, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("stale epoch changed the current binding state")
	}
}
