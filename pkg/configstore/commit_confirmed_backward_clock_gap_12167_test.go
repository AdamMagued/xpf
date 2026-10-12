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

func TestFirstCommitRollbackSentinelWriteFailureKeepsActive12167(t *testing.T) {
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
	injected := errors.New("injected confirm sentinel write failure")
	oldWrite := rbWriteFileDurable
	rbWriteFileDurable = func(p string, b []byte, mode os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(p) == "confirm.json" {
			return injected
		}
		return oldWrite(p, b, mode, opts...)
	}
	t.Cleanup(func() { rbWriteFileDurable = oldWrite })

	recovered := newTestStoreAt(t, path)
	activeMarkerWrites := 0
	recovered.SetWriteActiveMarkerForTesting(func(tree *config.ConfigTree, committed bool) error {
		activeMarkerWrites++
		return recovered.db.WriteActiveMarker(tree, committed)
	})
	err := recovered.Load()
	if !errors.Is(err, injected) {
		t.Fatalf("Load error = %v, want sentinel-write failure %v", err, injected)
	}
	if activeMarkerWrites != 0 {
		t.Fatalf("active marker writes = %d, want none before sentinel durability", activeMarkerWrites)
	}
	if _, committed, err := recovered.db.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("active marker after sentinel-write failure: committed=%v err=%v; want original committed state", committed, err)
	}
	rec, err := recovered.db.ReadConfirm()
	if err != nil || rec == nil || !rec.Deadline.Equal(armWall.Add(10*time.Minute)) {
		t.Fatalf("original confirm record after sentinel-write failure = %+v, err=%v", rec, err)
	}
}
