package configstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestConfirmRecoveryArmedAtBoundary12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return "boot-before" }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	tests := []struct {
		name         string
		offset       time.Duration
		wantRollback bool
	}{
		{name: "59-minutes-before-arm", offset: -59 * time.Minute, wantRollback: true},
		{name: "one-second-before-arm", offset: -time.Second, wantRollback: true},
		{name: "at-arm-time", offset: 0},
		{name: "one-second-after-arm", offset: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now = armWall
			path := filepath.Join(t.TempDir(), "config")
			armed := armedConfirmStore(t, path, 10)
			t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })
			rec, err := armed.db.ReadConfirm()
			if err != nil || rec == nil || !rec.ArmedAt.Equal(armWall) {
				t.Fatalf("armed record = %+v, err=%v; want ArmedAt=%v", rec, err, armWall)
			}

			now = armWall.Add(tt.offset)
			recovered := newTestStoreAt(t, path)
			recovered.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return false })
			if err := recovered.Load(); err != nil {
				t.Fatalf("Load: %v", err)
			}
			t.Cleanup(func() { recovered.CancelConfirmTimerForTesting() })

			if tt.wantRollback {
				if recovered.IsConfirmPending() {
					t.Fatal("wall clock before ArmedAt re-armed instead of rolling back")
				}
				if got := recovered.ActiveConfig().System.HostName; got != "Base" {
					t.Fatalf("active host-name = %q, want Base after backward step", got)
				}
				return
			}
			if !recovered.IsConfirmPending() {
				t.Fatal("wall clock at or after ArmedAt did not re-arm the open window")
			}
			if got := recovered.ActiveConfig().System.HostName; got != "Confirmed" {
				t.Fatalf("active host-name = %q, want Confirmed while window remains open", got)
			}
		})
	}
}

func TestConfirmRecoveryRechecksClockAfterAlarmCallback12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return "boot-before" }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	path := filepath.Join(t.TempDir(), "config")
	armed := armedConfirmStore(t, path, 10)
	t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

	now = armWall.Add(time.Minute)
	recovered := newTestStoreAt(t, path)
	recovered.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool {
		// Simulate a wall-clock step after the initial sample and before the
		// post-callback re-read; production callback only samples the alarm.
		now = armWall.Add(-time.Second)
		return false
	})
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { recovered.CancelConfirmTimerForTesting() })

	if recovered.IsConfirmPending() {
		t.Fatal("clock step during alarm check was missed; recovery re-armed the window")
	}
	if got := recovered.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("active host-name after post-callback clock step = %q, want Base", got)
	}
	if rec, err := recovered.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm record after post-callback rollback = %+v, err=%v; want removed", rec, err)
	}
}
