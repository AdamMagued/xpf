package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// bootWithFailedFirstSentinel12382 arms a FIRST commit-confirmed window at
// armWall, then boots 30 days behind ArmedAt with every durable write
// failing, so the #12167 sentinel write fails (B1 path). It returns the DB
// path, the fail-closed store, the controllable wall clock, and a heal
// closure that restores durable writes.
func bootWithFailedFirstSentinel12382(t *testing.T, retry time.Duration) (string, *Store, *time.Time, func()) {
	t.Helper()
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := new(time.Time)
	*now = armWall
	confirmWallNow = func() time.Time { return *now }
	confirmBootID = func() string { return "boot-before" }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	path := filepath.Join(t.TempDir(), "xpf.conf")
	armed := newTestStoreAt(t, path)
	if err := armed.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := armed.SetFromInput("system host-name FirstWindow"); err != nil {
		t.Fatal(err)
	}
	if _, err := armed.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed A: %v", err)
	}
	armed.ExitConfigure()
	armed.CancelConfirmTimerForTesting()

	*now = armWall.Add(-30 * 24 * time.Hour)
	oldWrite := rbWriteFileDurable
	rbWriteFileDurable = func(string, []byte, os.FileMode, ...fsatomic.Option) error {
		return errors.New("injected: no space left on device")
	}
	t.Cleanup(func() { rbWriteFileDurable = oldWrite })
	recovered := newTestStoreAt(t, path)
	recovered.SetPersistRetryBackoffForTesting(retry, retry)
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if recovered.ActiveConfig() != nil || !recovered.ConfigPersistDegraded() {
		t.Fatal("PREMISE: sentinel failure did not fail closed")
	}
	heal := func() { rbWriteFileDurable = oldWrite }
	return path, recovered, now, heal
}

// TestFirstCommitStaleIntentPreservesLiveWindow12382 (F1/P1): a
// FIRST-rollback intent left pending when CommitConfirmed supersedes the
// deferred resolution must not be replayed by the retry loop over the NEW
// window's record.
func TestFirstCommitStaleIntentPreservesLiveWindow12382(t *testing.T) {
	path, recovered, now, heal := bootWithFailedFirstSentinel12382(t, time.Hour)
	heal() // storage heals before the retry tick
	*now = now.Add(time.Minute)
	if err := recovered.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := recovered.SetFromInput("system host-name SecondTry"); err != nil {
		t.Fatal(err)
	}
	// B's active write lands but its dir-fsync reports a post-rename failure.
	recovered.SetWriteActiveForTesting(postRenameFailingWriteActive(recovered))
	if _, err := recovered.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed B: %v", err)
	}
	recovered.ExitConfigure()
	recovered.SetWriteActiveForTesting(nil)
	t.Cleanup(recovered.CancelConfirmTimerForTesting)

	recovered.mu.Lock()
	bHash := guardedConfigHash(recovered.active)
	// Drive the production retry step synchronously, avoiding any backoff race.
	recovered.retryActiveConfigPersistLocked(time.Hour)
	recovered.mu.Unlock()
	if recovered.ConfigPersistDegraded() {
		t.Fatal("retry step did not heal")
	}
	after, err := recovered.db.ReadConfirm()
	if err != nil || after == nil {
		t.Fatalf("record after retry: %+v err=%v", after, err)
	}
	if after.GuardedHash != bHash {
		t.Fatalf("retry heal overwrote B's record with the stale FIRST sentinel: guards B=false first=%v deadline=%v", after.FirstCommit, after.Deadline)
	}

	// Crash inside B's window; the next boot must keep B's rollback.
	recovered.CancelConfirmTimerForTesting()
	*now = now.Add(2 * time.Minute)
	final := newTestStoreAt(t, path)
	final.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := final.Load(); err != nil {
		t.Fatalf("final Load: %v", err)
	}
	t.Cleanup(final.CancelConfirmTimerForTesting)
	host := ""
	if cfg := final.ActiveConfig(); cfg != nil {
		host = cfg.System.HostName
	}
	if host == "SecondTry" && !final.IsConfirmPending() {
		t.Error("FAIL-OPEN: unconfirmed B stands with no rollback window after restart")
	}
}

// TestFirstCommitStaleIntentPreservesConfirmedConfig12382 (F1/P1b): the stale
// intent must not survive a later confirmation and wipe the confirmed config
// on a later boot.
func TestFirstCommitStaleIntentPreservesConfirmedConfig12382(t *testing.T) {
	path, recovered, now, heal := bootWithFailedFirstSentinel12382(t, time.Hour)
	heal()
	*now = now.Add(time.Minute)
	if err := recovered.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// The operator re-applies the same day-0 config and confirms it.
	if err := recovered.SetFromInput("system host-name FirstWindow"); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed A': %v", err)
	}
	if err := recovered.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("PREMISE: confirmed window left record %+v err=%v", rec, err)
	}
	// A later no-change commit hits a post-rename dir-fsync failure.
	recovered.SetWriteActiveForTesting(postRenameFailingWriteActive(recovered))
	if _, err := recovered.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	recovered.ExitConfigure()
	recovered.SetWriteActiveForTesting(nil)
	recovered.mu.Lock()
	recovered.retryActiveConfigPersistLocked(time.Hour)
	recovered.mu.Unlock()
	if recovered.ConfigPersistDegraded() {
		t.Fatal("retry step did not heal")
	}

	*now = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC) // weeks later, clock correct
	later := newTestStoreAt(t, path)
	later.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := later.Load(); err != nil {
		t.Fatalf("later Load: %v", err)
	}
	if later.ActiveConfig() == nil {
		t.Error("confirmed config was rolled back to the empty bootstrap tree on a later boot")
	}
}

// TestFirstCommitSentinelOwedFailedArmKeepsPastDeadline12382 (F2/P2b): with
// the sentinel still owed, a CommitConfirmed whose small provisional record
// lands but whose larger active write fails must not bind the abandoned
// FIRST config to its ORIGINAL future deadline.
func TestFirstCommitSentinelOwedFailedArmKeepsPastDeadline12382(t *testing.T) {
	path, recovered, now, heal := bootWithFailedFirstSentinel12382(t, time.Hour)
	heal()                                                 // confirm.json writes succeed again ...
	recovered.SetWriteActiveForTesting(failingWriteActive) // ... but active.json still fails
	*now = now.Add(time.Minute)
	if err := recovered.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := recovered.SetFromInput("system host-name SecondTry"); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.CommitConfirmed(10); err == nil {
		t.Fatal("PREMISE: CommitConfirmed with failing active write unexpectedly succeeded")
	}
	recovered.ExitConfigure()
	rec, err := recovered.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("provisional confirm record: %+v err=%v", rec, err)
	}
	diskActive, err := recovered.db.ReadActive()
	if err != nil || diskActive == nil {
		t.Fatalf("prior active config: %+v err=%v", diskActive, err)
	}
	if rec.PreviousHash != guardedConfigHash(diskActive) {
		t.Fatalf("provisional PreviousHash = %q, want prior active hash %q", rec.PreviousHash, guardedConfigHash(diskActive))
	}
	if !rec.PreviousDeadline.Before(*now) {
		t.Fatalf("provisional PreviousDeadline = %v, want the in-memory past FIRST sentinel before %v", rec.PreviousDeadline, *now)
	}
	recovered.CancelConfirmTimerForTesting()

	*now = now.Add(10 * time.Minute) // restart; clock still ~30 days behind
	final := newTestStoreAt(t, path)
	final.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := final.Load(); err != nil {
		t.Fatalf("final Load: %v", err)
	}
	t.Cleanup(final.CancelConfirmTimerForTesting)
	host := ""
	if cfg := final.ActiveConfig(); cfg != nil {
		host = cfg.System.HostName
	}
	if host == "FirstWindow" && final.IsConfirmPending() {
		t.Error("abandoned FIRST config re-armed instead of rolled back")
	}
}

// TestFirstCommitRetryPublishesSentinelBeforeActiveMarker12382 (F3): the retry
// loop must publish the FIRST-rollback sentinel before the active rollback
// marker without depending on goroutine timing.
func TestFirstCommitRetryPublishesSentinelBeforeActiveMarker12382(t *testing.T) {
	s := newTestStore(t)
	oldWrite := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, mode os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(path) == "confirm.json" {
			return errors.New("injected sentinel failure")
		}
		return oldWrite(path, data, mode, opts...)
	}
	t.Cleanup(func() { rbWriteFileDurable = oldWrite })

	empty := &config.ConfigTree{}
	sentinel := &confirmRecord{
		Deadline:    time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC),
		ArmedAt:     time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC),
		ArmedBootID: "boot-before",
		PrevTree:    empty,
		FirstCommit: true,
		GuardedHash: "abandoned",
	}
	markerWrites := 0
	s.mu.Lock()
	s.active = empty
	s.persistDegraded = true
	s.persistMarkerCommitted = false
	s.firstCommitRecoveryIntent = sentinel
	s.writeActiveMarkerFn = func(*config.ConfigTree, bool) error {
		markerWrites++
		return nil
	}
	// Drive the production retry step synchronously, without a sleep or race.
	s.retryActiveConfigPersistLocked(time.Second)
	intentRetained := s.firstCommitRecoveryIntent == sentinel
	degraded := s.persistDegraded
	s.mu.Unlock()

	if markerWrites != 0 {
		t.Fatalf("active marker writes = %d, want none while sentinel write is failing", markerWrites)
	}
	if !intentRetained || !degraded {
		t.Fatalf("failed sentinel attempt: intent retained=%v degraded=%v, want both true", intentRetained, degraded)
	}
}

// TestFirstCommitPlainCommitSupersedesOwedIntent12382 (F1/N1): a durable plain
// `commit` after BOOTSTRAP supersedes the owed FIRST-rollback intent. A later
// post-rename commit plus the degraded retry must not resurrect the stale
// record, and a later boot must keep the committed config. Pins the
// clearConfirmResolutionPendingLocked intent clear, the only path that
// discards the intent for plain commits.
func TestFirstCommitPlainCommitSupersedesOwedIntent12382(t *testing.T) {
	for _, tc := range []struct{ name, host string }{
		{"DifferentContent", "PlainB"},
		{"SameContent", "FirstWindow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, recovered, now, heal := bootWithFailedFirstSentinel12382(t, time.Hour)
			heal()
			*now = now.Add(time.Minute)
			recovered.mu.Lock()
			intent := recovered.firstCommitRecoveryIntent
			recovered.mu.Unlock()
			if intent == nil {
				t.Fatal("PREMISE: no FIRST-rollback intent owed after failed sentinel boot")
			}
			if err := recovered.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := recovered.SetFromInput("system host-name " + tc.host); err != nil {
				t.Fatal(err)
			}
			if _, err := recovered.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			recovered.mu.Lock()
			sameHash := guardedConfigHash(recovered.active) == intent.GuardedHash
			intentSurvived := recovered.firstCommitRecoveryIntent != nil
			recovered.mu.Unlock()
			if tc.name == "SameContent" && !sameHash {
				t.Fatal("PREMISE: same-content commit did not restore the abandoned FIRST config")
			}
			if tc.name == "DifferentContent" && sameHash {
				t.Fatal("PREMISE: different-content commit unexpectedly matches the abandoned guard")
			}
			if intentSurvived {
				t.Error("owed FIRST intent survived a durable plain commit")
			}
			if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
				t.Fatalf("record after durable plain commit: %+v err=%v", rec, err)
			}
			// A later commit hits a post-rename dir-fsync failure; the retry
			// heal must converge the active write without replaying the intent.
			recovered.SetWriteActiveForTesting(postRenameFailingWriteActive(recovered))
			if _, err := recovered.Commit(); err != nil {
				t.Fatalf("later Commit: %v", err)
			}
			if !recovered.ConfigPersistDegraded() {
				t.Fatal("PREMISE: later Commit did not hit the post-rename failure")
			}
			recovered.ExitConfigure()
			recovered.SetWriteActiveForTesting(nil)
			recovered.mu.Lock()
			recovered.retryActiveConfigPersistLocked(time.Hour)
			recovered.mu.Unlock()
			if recovered.ConfigPersistDegraded() {
				t.Fatal("retry step did not heal")
			}
			if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
				t.Fatalf("stale record resurrected by retry: %+v err=%v", rec, err)
			}
			if _, err := os.Stat(recovered.db.confirmPath()); !os.IsNotExist(err) {
				t.Fatalf("confirm.json present after retry heal: %v", err)
			}

			*now = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC) // weeks later, clock correct
			later := newTestStoreAt(t, path)
			later.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
			if err := later.Load(); err != nil {
				t.Fatalf("later Load: %v", err)
			}
			t.Cleanup(later.CancelConfirmTimerForTesting)
			host := ""
			if cfg := later.ActiveConfig(); cfg != nil {
				host = cfg.System.HostName
			}
			if host != tc.host || later.IsConfirmPending() {
				t.Errorf("reboot host=%q pending=%v, want %q standing with no window", host, later.IsConfirmPending(), tc.host)
			}
		})
	}
}

// TestFirstCommitSyncSupersedesOwedIntent12382 (F1/N1): a durable HA SyncApply
// after BOOTSTRAP supersedes the owed FIRST-rollback intent, including a
// same-content re-apply of the abandoned config. A later post-rename sync
// plus the degraded retry must not resurrect the stale record, and a later
// boot must keep the synced config. Pins the
// clearConfirmResolutionPendingLocked intent clear, the only path that
// discards the intent for syncs.
func TestFirstCommitSyncSupersedesOwedIntent12382(t *testing.T) {
	for _, tc := range []struct{ name, host string }{
		{"DifferentContent", "SyncS"},
		{"SameContent", "FirstWindow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, recovered, now, heal := bootWithFailedFirstSentinel12382(t, time.Hour)
			heal()
			*now = now.Add(time.Minute)
			recovered.mu.Lock()
			intent := recovered.firstCommitRecoveryIntent
			recovered.mu.Unlock()
			if intent == nil {
				t.Fatal("PREMISE: no FIRST-rollback intent owed after failed sentinel boot")
			}
			content := "system {\n    host-name " + tc.host + ";\n}\n"
			if _, err := recovered.SyncApply(content, nil); err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			recovered.mu.Lock()
			sameHash := guardedConfigHash(recovered.active) == intent.GuardedHash
			intentSurvived := recovered.firstCommitRecoveryIntent != nil
			recovered.mu.Unlock()
			if tc.name == "SameContent" && !sameHash {
				t.Fatal("PREMISE: same-content sync did not restore the abandoned FIRST config")
			}
			if tc.name == "DifferentContent" && sameHash {
				t.Fatal("PREMISE: different-content sync unexpectedly matches the abandoned guard")
			}
			if intentSurvived {
				t.Error("owed FIRST intent survived a durable sync")
			}
			if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
				t.Fatalf("record after durable sync: %+v err=%v", rec, err)
			}
			// A later sync hits a post-rename dir-fsync failure; the retry
			// heal must converge the active write without replaying the intent.
			recovered.SetWriteActiveForTesting(postRenameFailingWriteActive(recovered))
			if _, err := recovered.SyncApply(content, nil); err != nil {
				t.Fatalf("later SyncApply: %v", err)
			}
			if !recovered.ConfigPersistDegraded() {
				t.Fatal("PREMISE: later SyncApply did not hit the post-rename failure")
			}
			recovered.SetWriteActiveForTesting(nil)
			recovered.mu.Lock()
			recovered.retryActiveConfigPersistLocked(time.Hour)
			recovered.mu.Unlock()
			if recovered.ConfigPersistDegraded() {
				t.Fatal("retry step did not heal")
			}
			if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
				t.Fatalf("stale record resurrected by retry: %+v err=%v", rec, err)
			}
			if _, err := os.Stat(recovered.db.confirmPath()); !os.IsNotExist(err) {
				t.Fatalf("confirm.json present after retry heal: %v", err)
			}

			*now = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC) // weeks later, clock correct
			later := newTestStoreAt(t, path)
			later.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
			if err := later.Load(); err != nil {
				t.Fatalf("later Load: %v", err)
			}
			t.Cleanup(later.CancelConfirmTimerForTesting)
			host := ""
			if cfg := later.ActiveConfig(); cfg != nil {
				host = cfg.System.HostName
			}
			if host != tc.host || later.IsConfirmPending() {
				t.Errorf("reboot host=%q pending=%v, want %q standing with no window", host, later.IsConfirmPending(), tc.host)
			}
		})
	}
}
