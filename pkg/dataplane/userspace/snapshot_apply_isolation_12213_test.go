package userspace

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func withRevalidationSample12213(t *testing.T, ifindex int) {
	t.Helper()
	previousBuild := buildLinkSnapshot
	previousLookup := linkByNameFn
	t.Cleanup(func() {
		buildLinkSnapshot = previousBuild
		linkByNameFn = previousLookup
	})
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return ifindex, 1500, "", nil
	}
	linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }
}

func retainedInterfaceRows12213() []InterfaceSnapshot {
	linkUp := true
	return []InterfaceSnapshot{
		{Name: "ge-0/0/0", Zone: "blue", LinuxName: "eth12213", Ifindex: 23, RXQueues: 4, LinkUp: &linkUp},
	}
}

func TestFailedPartialPublishPreservesRetainedInterfacesAndHash12213(t *testing.T) {
	withRevalidationSample12213(t, 0) // the interface disappears at the send boundary
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	rows := retainedInterfaceRows12213()
	linkUp := false
	rows = append(rows, InterfaceSnapshot{Name: "lo0", Ifindex: 1, LinkUp: &linkUp})
	rows = append(rows, InterfaceSnapshot{Name: "tail-sentinel"})
	m.lastSnapshot = &ConfigSnapshot{
		Version: ProtocolVersion, Generation: 7,
		Config: &config.Config{}, Interfaces: rows[:2],
	}
	// Reserve spare capacity so the assertion also observes the compacted tail,
	// not only the retained slice's current length.
	beforeBacking := append([]InterfaceSnapshot(nil), m.lastSnapshot.Interfaces[:cap(m.lastSnapshot.Interfaces)]...)
	retainedLinkUp := m.lastSnapshot.Interfaces[1].LinkUp
	beforeHash, ok := snapshotContentHash(m.lastSnapshot)
	if !ok {
		t.Fatal("could not hash retained snapshot")
	}
	m.lastSnapshotHash = beforeHash
	m.generation = m.lastSnapshot.Generation
	var sentLinkUp *bool
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			if len(req.Snapshot.Interfaces) > 0 {
				sentLinkUp = req.Snapshot.Interfaces[0].LinkUp
			}
			return errors.New("scripted partial-publish failure")
		}
		return nil
	}
	err := m.UpdatePolicyScheduleStateWithLatch(m.lastSnapshot.Config, map[string]bool{}, false)
	if err == nil {
		t.Fatal("expected scripted publish failure")
	}
	if sentLinkUp == nil || sentLinkUp == retainedLinkUp {
		t.Errorf("send snapshot did not receive an independently copied LinkUp pointer")
	}
	if got := m.lastSnapshot.Interfaces[:cap(m.lastSnapshot.Interfaces)]; !reflect.DeepEqual(got, beforeBacking) {
		t.Errorf("failed partial publish mutated retained interface backing array:\n got=%+v\nwant=%+v", got, beforeBacking)
	}
	if got, ok := snapshotContentHash(m.lastSnapshot); !ok || got != beforeHash {
		t.Errorf("failed partial publish changed retained content hash: got=%x ok=%v want=%x", got, ok, beforeHash)
	}
	if m.lastSnapshotHash != beforeHash {
		t.Errorf("stored retained hash changed: got=%x want=%x", m.lastSnapshotHash, beforeHash)
	}
}

func TestCompileStoresSentPlanKeyAfterInterfaceRevalidation12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	snap := f.snap9824(9, nil, nil, nil)
	f.m.programBootstrapMapsHook = func(*ConfigSnapshot, config.UserspaceConfig) error { return nil }
	snap.Interfaces = retainedInterfaceRows12213()
	var sentPlanKey string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sentPlanKey = snapshotBindingPlanKey(req.Snapshot)
		}
		return f.model.hook(req, status)
	}
	if _, err := f.apply(t, snap); err != nil && f.m.publishedSnapshot == 0 {
		t.Fatalf("applyCompiledSnapshot failed before publication: %v", err)
	}
	if sentPlanKey == "" || sentPlanKey == snapshotBindingPlanKey(&ConfigSnapshot{Interfaces: retainedInterfaceRows12213()}) {
		t.Fatalf("test did not observe a changed sent plan key: %q", sentPlanKey)
	}
	if f.m.publishedPlanKey != sentPlanKey {
		t.Fatalf("stored plan key does not match exact sent snapshot: stored=%q sent=%q", f.m.publishedPlanKey, sentPlanKey)
	}
	if f.m.lastSnapshot.Interfaces[0].Ifindex != 99 {
		t.Fatalf("retained Compile snapshot does not match sent interface row: %+v", f.m.lastSnapshot.Interfaces)
	}
}

func TestDeferredPublishStoresSentPlanKeyAfterInterfaceRevalidation12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	snap := f.snap9824(9, nil, nil, nil)
	snap.Interfaces = retainedInterfaceRows12213()
	f.m.mu.Lock()
	f.m.lastSnapshot = snap
	f.m.generation = snap.Generation
	f.m.publishedSnapshot = 0
	f.m.publishedPlanKey = ""
	f.m.mu.Unlock()
	var sentPlanKey string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sentPlanKey = snapshotBindingPlanKey(req.Snapshot)
		}
		return f.model.hook(req, status)
	}
	if err := f.tick(t); err != nil {
		t.Fatalf("syncSnapshotLocked: %v", err)
	}
	if sentPlanKey == "" {
		t.Fatal("deferred path did not send an apply_snapshot")
	}
	if f.m.publishedPlanKey != sentPlanKey {
		t.Fatalf("stored deferred plan key does not match exact sent snapshot: stored=%q sent=%q", f.m.publishedPlanKey, sentPlanKey)
	}
	if f.m.lastSnapshot.Interfaces[0].Ifindex != 99 {
		t.Fatalf("retained deferred snapshot does not match sent interface row: %+v", f.m.lastSnapshot.Interfaces)
	}
}

func TestDeferredXSKStartupTickSamplesNothing12213(t *testing.T) {
	for _, tc := range []struct {
		name string
		live int
	}{
		{"rows-stable", 23},
		{"row-vanished-after-compile", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prevBuild, prevLookup := buildLinkSnapshot, linkByNameFn
			t.Cleanup(func() { buildLinkSnapshot, linkByNameFn = prevBuild, prevLookup })
			samples := 0
			buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
				samples++
				return tc.live, 1500, "", nil
			}
			linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }

			var logs bytes.Buffer
			prevLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(prevLogger) })

			f := newFixture9824(t)
			f.seedPublished(t, 5, nil, nil, nil)
			retained := f.snap9824(6, nil, nil, nil)
			retained.Interfaces = retainedInterfaceRows12213()
			f.m.mu.Lock()
			f.m.lastSnapshot = retained
			f.m.generation = 6
			// Neither the retained nor revalidated plan matches, so each
			// XSK-startup tick must defer before sampling or logging.
			f.m.publishedPlanKey = "a-plan-this-snapshot-does-not-have"
			f.m.mu.Unlock()
			f.forcePendingXSK()
			applies := 0
			f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				if req.Type == "apply_snapshot" {
					applies++
				}
				return f.model.hook(req, status)
			}
			const ticks = 10
			for i := range ticks {
				if err := f.tick(t); err != nil {
					t.Fatalf("tick %d: %v", i, err)
				}
			}
			warns := strings.Count(logs.String(), "snapshot row dropped")
			infos := strings.Count(logs.String(), "revalidated at apply")
			if applies != 0 {
				t.Fatalf("premise: a plan change during XSK startup must defer (sent %d)", applies)
			}
			if samples != 0 || warns != 0 || infos != 0 {
				t.Errorf("deferred ticks sampled the kernel %d times and logged %d drop warnings/%d revalidation infos",
					samples, warns, infos)
			}
		})
	}
}

func TestDeferredXSKGateDefersLiveOnlyPlanChange12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	published := f.snap9824(5, nil, nil, nil)
	published.Interfaces = retainedInterfaceRows12213()
	retained := f.snap9824(6, nil, nil, nil)
	retained.Interfaces = retainedInterfaceRows12213()
	retained.Summary.PolicyCount = 1
	f.m.mu.Lock()
	f.m.lastSnapshot = retained
	f.m.generation = 6
	f.m.publishedSnapshot = 5
	f.m.publishedPlanKey = snapshotBindingPlanKey(published)
	if h, ok := snapshotContentHash(published); ok {
		f.m.lastSnapshotHash = h
	}
	f.m.lastStatus.LastSnapshotGeneration = 5
	f.m.mu.Unlock()
	f.model.seed(5, 0, digest9824(t, published), nil)
	f.forcePendingXSK()
	var sent []string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sent = append(sent, snapshotBindingPlanKey(req.Snapshot))
		}
		return f.model.hook(req, status)
	}
	if err := f.tick(t); err != nil {
		t.Fatalf("deferred status tick: %v", err)
	}
	if len(sent) != 0 {
		t.Errorf("XSK-startup tick shipped live plan change %q under a retained same-plan verdict", sent)
	}
}

func TestCompileClassifiesOnRevalidatedSample12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	live := f.snap9824(5, nil, nil, nil)
	live.Interfaces = retainedInterfaceRows12213()
	live.Interfaces[0].Ifindex = 99
	f.m.mu.Lock()
	f.m.lastSnapshot = live
	f.m.generation = 5
	f.m.publishedSnapshot = 5
	f.m.publishedPlanKey = snapshotBindingPlanKey(live)
	if h, ok := snapshotContentHash(live); ok {
		f.m.lastSnapshotHash = h
	}
	f.m.lastStatus.LastSnapshotGeneration = 5
	f.m.xskLivenessProven = true
	f.m.mu.Unlock()
	f.model.seed(5, 0, digest9824(t, live), nil)

	bootstraps := 0
	f.m.programBootstrapMapsHook = func(*ConfigSnapshot, config.UserspaceConfig) error {
		bootstraps++
		return nil
	}
	var sentPlanKey string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sentPlanKey = snapshotBindingPlanKey(req.Snapshot)
		}
		return f.model.hook(req, status)
	}
	stale := f.snap9824(9, nil, nil, nil)
	stale.Interfaces = retainedInterfaceRows12213()
	if _, err := f.apply(t, stale); err != nil && f.m.publishedSnapshot == 0 {
		t.Fatalf("applyCompiledSnapshot failed before publication: %v", err)
	}
	if bootstraps != 0 || len(f.syncedTo) == 0 {
		t.Errorf("Compile classified on stale build rows: bootstraps=%d same-plan syncs=%d", bootstraps, len(f.syncedTo))
	}
	if sentPlanKey == "" || f.m.publishedPlanKey != sentPlanKey {
		t.Errorf("stored key %q does not match sent plan key %q", f.m.publishedPlanKey, sentPlanKey)
	}
	if got := f.m.lastSnapshot.Interfaces[0].Ifindex; got != 99 {
		t.Errorf("retained Compile row ifindex=%d, want sent ifindex 99", got)
	}
}

func ackManager12213(t *testing.T) (*Manager, **ConfigSnapshot) {
	t.Helper()
	withRevalidationSample12213(t, 99)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	m.lastSnapshot = &ConfigSnapshot{
		Version: ProtocolVersion, Generation: 7,
		Config: &config.Config{}, Interfaces: retainedInterfaceRows12213(),
	}
	m.generation = 7
	var sent *ConfigSnapshot
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			c := *req.Snapshot
			sent = &c
		}
		return nil
	}
	return m, &sent
}

func assertRetainedMatchesSent12213(t *testing.T, m *Manager, sent *ConfigSnapshot) {
	t.Helper()
	if sent == nil || len(sent.Interfaces) != 1 {
		t.Fatalf("premise: one apply_snapshot with one row, got %+v", sent)
	}
	if got, want := m.lastSnapshot.Interfaces[0].Ifindex, sent.Interfaces[0].Ifindex; got != want {
		t.Errorf("retained authority row ifindex %d diverges from sent row ifindex %d", got, want)
	}
	if got, want := snapshotBindingPlanKey(m.lastSnapshot), m.publishedPlanKey; got != want {
		t.Errorf("retained plan key %q != published plan key %q", got, want)
	}
}

func TestSchedulerAckRetainsSentRows12213(t *testing.T) {
	m, sent := ackManager12213(t)
	if err := m.UpdatePolicyScheduleStateWithLatch(m.lastSnapshot.Config, map[string]bool{}, false); err != nil {
		t.Fatalf("scheduler publish: %v", err)
	}
	assertRetainedMatchesSent12213(t, m, *sent)
}

func TestWorkerArmAckRetainsSentRows12213(t *testing.T) {
	m, sent := ackManager12213(t)
	m.lastSnapshot.DeferWorkers = true
	m.pendingWorkerArm = true
	m.mu.Lock()
	err := m.retryDeferredWorkerArmLocked()
	m.mu.Unlock()
	t.Logf("worker-arm err=%v", err)
	assertRetainedMatchesSent12213(t, m, *sent)
}
