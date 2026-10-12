package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

func TestBackwardFirstCommitTeardownMarkerGapRecovery12167(t *testing.T) {
	for _, crash := range []bool{false, true} {
		name := "marker-write-error"
		if crash {
			name = "crash-before-marker"
		}
		t.Run(name, func(t *testing.T) {
			originalNow, originalBootID := confirmWallNow, confirmBootID
			armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
			now := armWall
			confirmWallNow = func() time.Time { return now }
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
				t.Fatalf("CommitConfirmed: %v", err)
			}
			armed.ExitConfigure()
			t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

			rec, err := armed.db.ReadConfirm()
			if err != nil || rec == nil || !rec.FirstCommit {
				t.Fatalf("FIRST confirm record = %+v, err=%v", rec, err)
			}
			if !rec.ArmedAt.Equal(armWall) {
				t.Fatalf("ArmedAt = %v, want %v", rec.ArmedAt, armWall)
			}

			now = armWall.Add(-30 * 24 * time.Hour)
			oldWrite := rbWriteFileDurable
			injected := errors.New("injected marker boundary")
			rbWriteFileDurable = func(p string, b []byte, mode os.FileMode, opts ...fsatomic.Option) error {
				if filepath.Base(p) == firstCommitTeardownMarkerBase {
					if crash {
						panic(injected)
					}
					return injected
				}
				return oldWrite(p, b, mode, opts...)
			}
			t.Cleanup(func() { rbWriteFileDurable = oldWrite })

			interrupted := newTestStoreAt(t, path)
			interrupted.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
			func() {
				defer func() {
					if r := recover(); r != nil && r != injected {
						panic(r)
					}
				}()
				if err := interrupted.Load(); err != nil {
					t.Fatalf("first Load: %v", err)
				}
			}()
			if _, committed, err := interrupted.db.ReadActiveMeta(); err != nil || committed {
				t.Fatalf("rollback active marker: committed=%v err=%v", committed, err)
			}
			if rec, err := interrupted.db.ReadConfirm(); err != nil || rec == nil || rec.Resolved {
				t.Fatalf("confirm recovery record was not retained: rec=%+v err=%v", rec, err)
			}

			rbWriteFileDurable = oldWrite
			confirmBootID = func() string { return "boot-after" }
			restarted := newTestStoreAt(t, path)
			if err := restarted.Load(); err != nil {
				t.Fatalf("restart Load: %v", err)
			}
			if !restarted.FirstCommitTeardownOwed() {
				t.Fatal("backward-clock FIRST rollback lost teardown debt across marker publication gap")
			}
		})
	}
}

func TestFirstCommitTeardownMarkerGapClockIndependent12167(t *testing.T) {
	for _, trigger := range []string{"corrected-clock", "clock-skew-alarm"} {
		for _, crash := range []bool{false, true} {
			name := trigger + "/marker-write-error"
			if crash {
				name = trigger + "/crash-before-marker"
			}
			t.Run(name, func(t *testing.T) {
				originalNow, originalBootID := confirmWallNow, confirmBootID
				armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
				now := armWall
				confirmWallNow = func() time.Time { return now }
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
					t.Fatalf("CommitConfirmed: %v", err)
				}
				armed.ExitConfigure()
				t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

				rec, err := armed.db.ReadConfirm()
				if err != nil || rec == nil || !rec.FirstCommit {
					t.Fatalf("FIRST confirm record = %+v, err=%v", rec, err)
				}
				if trigger == "corrected-clock" {
					now = armWall.Add(-30 * 24 * time.Hour)
				} else {
					now = armWall.Add(time.Minute)
				}

				oldWrite := rbWriteFileDurable
				injected := errors.New("injected marker boundary")
				rbWriteFileDurable = func(p string, b []byte, mode os.FileMode, opts ...fsatomic.Option) error {
					if filepath.Base(p) == firstCommitTeardownMarkerBase {
						if crash {
							panic(injected)
						}
						return injected
					}
					return oldWrite(p, b, mode, opts...)
				}
				t.Cleanup(func() { rbWriteFileDurable = oldWrite })

				interrupted := newTestStoreAt(t, path)
				interrupted.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
				if trigger == "corrected-clock" {
					interrupted.SetWriteActiveMarkerForTesting(func(tree *config.ConfigTree, committed bool) error {
						now = armWall.Add(time.Minute)
						return interrupted.db.WriteActiveMarker(tree, committed)
					})
				} else {
					interrupted.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return true })
				}
				func() {
					defer func() {
						if r := recover(); r != nil && r != injected {
							panic(r)
						}
					}()
					if err := interrupted.Load(); err != nil {
						t.Fatalf("first Load: %v", err)
					}
				}()
				if _, committed, err := interrupted.db.ReadActiveMeta(); err != nil || committed {
					t.Fatalf("rollback active marker: committed=%v err=%v", committed, err)
				}
				retained, err := interrupted.db.ReadConfirm()
				if err != nil || retained == nil || retained.Resolved {
					t.Fatalf("confirm recovery record was not retained: rec=%+v err=%v", retained, err)
				}
				if !retained.Deadline.Before(armWall) {
					t.Fatalf("rollback intent deadline = %v, want past sentinel before %v", retained.Deadline, armWall)
				}

				rbWriteFileDurable = oldWrite
				confirmBootID = func() string { return "boot-after" }
				restarted := newTestStoreAt(t, path)
				restarted.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return false })
				if err := restarted.Load(); err != nil {
					t.Fatalf("restart Load: %v", err)
				}
				if !restarted.FirstCommitTeardownOwed() {
					t.Fatal("FIRST rollback lost teardown debt across clock-independent marker gap")
				}
			})
		}
	}
}

func TestFirstCommitRollbackSentinelWriteFailureFailsClosed12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	confirmWallNow = func() time.Time { return now }
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
		t.Fatalf("CommitConfirmed: %v", err)
	}
	armed.ExitConfigure()
	t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

	now = armWall.Add(-30 * 24 * time.Hour)
	injected := errors.New("injected: no space left on device")
	oldWrite := rbWriteFileDurable
	rbWriteFileDurable = func(string, []byte, os.FileMode, ...fsatomic.Option) error {
		return injected
	}
	t.Cleanup(func() { rbWriteFileDurable = oldWrite })

	recovered := newTestStoreAt(t, path)
	recovered.SetPersistRetryBackoffForTesting(5*time.Millisecond, 5*time.Millisecond)
	var activeMarkerWrites atomic.Int32
	recovered.SetWriteActiveMarkerForTesting(func(tree *config.ConfigTree, committed bool) error {
		activeMarkerWrites.Add(1)
		rec, err := recovered.db.ReadConfirm()
		if err != nil || rec == nil || !rec.Deadline.Before(armWall) {
			return fmt.Errorf("active marker write preceded durable sentinel: rec=%+v err=%v", rec, err)
		}
		return recovered.db.WriteActiveMarker(tree, committed)
	})
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v; rollback must continue in memory despite failed sentinel write", err)
	}
	if recovered.ActiveConfig() != nil {
		t.Fatalf("ActiveConfig() = %v, want nil after fail-closed FIRST rollback", recovered.ActiveConfig())
	}
	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("failed FIRST sentinel write lost teardown debt")
	}
	if !recovered.ConfigPersistDegraded() {
		t.Fatal("failed FIRST sentinel write did not degrade persistence health")
	}
	if recovered.IsConfirmPending() {
		t.Fatal("failed FIRST sentinel write re-armed a timer")
	}
	if activeMarkerWrites.Load() != 0 {
		t.Fatalf("active marker writes = %d, want none until sentinel is durable", activeMarkerWrites.Load())
	}
	if _, committed, err := recovered.db.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("active marker after sentinel-write failure: committed=%v err=%v; want original committed state", committed, err)
	}
	rec, err := recovered.db.ReadConfirm()
	if err != nil || rec == nil || !rec.Deadline.Equal(armWall.Add(10*time.Minute)) {
		t.Fatalf("original confirm record after sentinel-write failure = %+v, err=%v", rec, err)
	}
	rbWriteFileDurable = oldWrite
	retryDeadline := time.Now().Add(2 * time.Second)
	for recovered.ConfigPersistDegraded() && time.Now().Before(retryDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if recovered.ConfigPersistDegraded() {
		t.Fatal("sentinel-then-active retry did not clear degraded health")
	}
	if activeMarkerWrites.Load() != 1 {
		t.Fatalf("active marker writes after retry = %d, want one after sentinel durability", activeMarkerWrites.Load())
	}
	if _, committed, err := recovered.db.ReadActiveMeta(); err != nil || committed {
		t.Fatalf("active marker after retry: committed=%v err=%v; want never-committed rollback", committed, err)
	}
	if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm record after durable retry = %+v err=%v; want removed", rec, err)
	}
}

func TestFirstCommitLegacyTeardownGapBeforeArmedAt12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	confirmWallNow = func() time.Time { return now }
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
		t.Fatalf("CommitConfirmed: %v", err)
	}
	armed.ExitConfigure()
	t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

	// Reproduce the legacy crash gap: active.json contains the never-committed
	// rollback marker but confirm.json has no #12167 past-deadline sentinel.
	if err := armed.db.WriteActiveMarker(&config.ConfigTree{}, false); err != nil {
		t.Fatalf("WriteActiveMarker(empty, false): %v", err)
	}
	now = armWall.Add(-30 * 24 * time.Hour)
	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load of legacy sentinel-less gap: %v", err)
	}
	if !restarted.FirstCommitTeardownOwed() {
		t.Fatal("legacy sentinel-less backward-clock gap lost FIRST teardown debt")
	}
}

func TestFirstCommitRollbackSentinelPreservesPreviousDeadline12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return "boot-before" }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newTestStoreAt(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name FirstWindow"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("first CommitConfirmed: %v", err)
	}
	store.ExitConfigure()

	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name NestedWindow"); err != nil {
		t.Fatal(err)
	}
	crashCommitConfirmedAtStage(t, store, commitConfirmedStageRecord)
	store.CancelConfirmTimerForTesting()
	record, err := store.db.ReadConfirm()
	if err != nil || record == nil || !record.FirstCommit || record.PreviousDeadline.IsZero() {
		t.Fatalf("nested FIRST record = %+v, err=%v; want previous deadline", record, err)
	}

	now = armWall.Add(11 * time.Minute)
	restarted := newTestStoreAt(t, path)
	restarted.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	injectedCrash := errors.New("crash after sentinel before active rollback")
	restarted.SetWriteActiveMarkerForTesting(func(*config.ConfigTree, bool) error {
		panic(injectedCrash)
	})
	func() {
		defer func() {
			if got := recover(); got != injectedCrash {
				t.Fatalf("Load panic = %v, want injected active-marker crash", got)
			}
		}()
		_ = restarted.Load()
	}()
	record, err = restarted.db.ReadConfirm()
	if err != nil || record == nil {
		t.Fatalf("ReadConfirm after sentinel: record=%+v err=%v", record, err)
	}
	if !record.PreviousDeadline.Before(armWall) {
		t.Fatalf("sentinel PreviousDeadline = %v, want past sentinel before %v", record.PreviousDeadline, armWall)
	}
}
