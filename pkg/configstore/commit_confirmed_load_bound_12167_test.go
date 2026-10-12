package configstore

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadBoundsLegacyConfirmRearmDelay12167(t *testing.T) {
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
	rec, err := armed.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	rec.ArmedAt = time.Time{}
	rec.ArmedBootID = ""
	maxDelay := time.Duration(MaxCommitConfirmedMinutes) * time.Minute
	rec.Deadline = armWall.Add(maxDelay + time.Minute)
	if err := armed.db.WriteConfirm(rec); err != nil {
		t.Fatalf("write legacy confirm record: %v", err)
	}

	var logs bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	recovered := newTestStoreAt(t, path)
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { recovered.CancelConfirmTimerForTesting() })
	if !recovered.IsConfirmPending() {
		t.Fatal("legacy record with a future deadline did not re-arm")
	}
	want := "remaining=" + maxDelay.String()
	if !strings.Contains(logs.String(), want) {
		t.Fatalf("Load re-arm log lacks bounded remaining %q; logs:\n%s", want, logs.String())
	}
}
