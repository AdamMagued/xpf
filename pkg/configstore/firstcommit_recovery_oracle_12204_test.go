package configstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #12204: the expired-first-commit boot-recovery branch
// (recoverPendingConfirmLocked, rec.FirstCommit) clears everCommitted and
// persists committed=false when the confirm window expired during downtime.
// TestActiveSnapshotRecoveryFirstCommitNil9905 executes this branch but
// asserts only the published nil snapshot. The rescue-path test
// TestRescueFallbackExpiredConfirmRecoveryKeepsBootstrapProvenance11802
// kills retained-marker mutants M1/M3 only indirectly — via Load's return
// value with a rescue.conf present (loadRescueFallbackLocked re-clears
// both flags) — and cannot see the persistMarkerCommitted seed; #12167
// pins that seed through the sentinel-failure heal. This oracle directly pins
// the plain no-rescue expiry path: EverCommitted immediately after Load, and
// committed=false on disk after reopen and after a failed-write/heal cycle.
//
// It exercises the plain no-rescue expiry path through Load (restart) and
// directly asserts:
//   - ActiveConfig()==nil and EverCommitted()==false immediately after recovery;
//   - committed=false on disk via ReadActiveMeta and after a fresh Load;
//   - the retry after a failed recovery write persists committed=false.
//
// The three retained-marker mutants are killed by these direct assertions:
// M1 (everCommitted=false -> true) by Immediate;
// M2 (persistMarkerCommitted=false -> true) by FailedWriteHealsUncommitted;
// M3 (writeActiveMarker(prevTree, false -> true)) by ReopenReadsUncommitted.

// armExpiredFirstCommit is the shared fixture: a genuine first commit
// confirmed (FirstCommit=true) whose window expired during downtime. The
// arming store is closed for restart semantics: its timer is cancelled so no
// in-process rollback can race the fresh Load below (#9615).
func armExpiredFirstCommit(t *testing.T, path string) {
	t.Helper()
	s0 := newTestStoreAt(t, path)
	if err := s0.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s0.SetFromInput("system host-name First"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s0.db.ReadConfirm(); err != nil || rec == nil || !rec.FirstCommit {
		t.Fatalf("premise broken: want persisted FirstCommit record, rec=%v err=%v", rec, err)
	}
	s0.CancelConfirmTimerForTesting()
	forceConfirmDeadlinePast(t, path)
}

func TestFirstCommitRecoveryOracle12204(t *testing.T) {
	t.Run("Immediate", func(t *testing.T) {
		// Right after the expired-window Load: the rollback target is the
		// empty bootstrap tree, so recovery publishes nil — AND the store
		// must already read never-committed in memory. M1 (everCommitted
		// stays true) survives the nil-snapshot assert but dies here.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommit(t, path)
		s := newTestStoreAt(t, path)
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if s.ActiveConfig() != nil {
			t.Fatal("ActiveConfig non-nil after first-commit recovery rollback")
		}
		if s.EverCommitted() {
			t.Fatal("EverCommitted=true after an expired first-commit window " +
				"recovered on boot; the in-memory boot predicate now reads " +
				"operator-committed-empty (M1 survives the nil-snapshot assert)")
		}
	})

	t.Run("ReopenReadsUncommitted", func(t *testing.T) {
		// The durable half: a FRESH store reopened over the recovered DB
		// must read committed=false from disk. M3 (marker written true)
		// leaves EverCommitted false in memory (M1's line still clears it)
		// but poisons the disk — the reopen is what observes it, and the
		// NEXT restart would then classify NORMAL.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommit(t, path)
		s := newTestStoreAt(t, path)
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		reopened := newTestStoreAt(t, path)
		_, committed, err := reopened.db.ReadActiveMeta()
		if err != nil {
			t.Fatalf("ReadActiveMeta: %v", err)
		}
		if committed {
			t.Fatal("disk marker committed=true after first-commit boot recovery; " +
				"want committed=false (M3: the recovery wrote the committed bit)")
		}
		if err := reopened.Load(); err != nil {
			t.Fatalf("reopen Load: %v", err)
		}
		if reopened.EverCommitted() {
			t.Fatal("reopened EverCommitted=true; the recovered DB must stay " +
				"never-committed across restarts")
		}
	})

	t.Run("FailedWriteHealsUncommitted", func(t *testing.T) {
		// The degraded half: the recovery rollback write FAILS (disk full),
		// then the retry loop heals it. The heal must re-write committed=0 —
		// the seed for that is persistMarkerCommitted=false, set on the same
		// branch. M2 flips the seed to true: the immediate write still lands
		// committed=0, so only the heal leg observes the poison.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommit(t, path)
		s := newTestStoreAt(t, path)
		s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
		s.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, _ bool) error {
			return errDiskFull
		})
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !s.ConfigPersistDegraded() {
			t.Fatal("premise broken: failed recovery write must set degraded")
		}
		// Disk heals; restore the real write so the retry lands durably.
		s.SetWriteActiveMarkerForTesting(nil)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
			time.Sleep(5 * time.Millisecond)
		}
		if s.ConfigPersistDegraded() {
			t.Fatal("recovery rollback retry did not converge")
		}
		prober := newTestStoreAt(t, path)
		_, committed, err := prober.db.ReadActiveMeta()
		if err != nil {
			t.Fatalf("ReadActiveMeta: %v", err)
		}
		if committed {
			t.Fatal("healed marker committed=true; the degraded retry must " +
				"re-write committed=false for a first-commit rollback (M2: the " +
				"retry seed was flipped to committed)")
		}
	})

}
