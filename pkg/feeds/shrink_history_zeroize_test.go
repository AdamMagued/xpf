package feeds

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestEraseShrinkHistoryCrashTempsRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed-shrink-history.json")
	temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte("prior tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, temp); err != nil {
		t.Fatal(err)
	}

	if err := EraseShrinkHistoryCrashTemps(path); err == nil {
		t.Fatal("symlinked crash temp must be refused")
	}
	if _, err := os.Lstat(temp); err != nil {
		t.Fatalf("refusal must retain symlink: %v", err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "prior tenant" {
		t.Fatalf("refusal must retain symlink target: body=%q err=%v", body, err)
	}
}

func TestEraseShrinkHistoryCrashTempsRefusesHardlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed-shrink-history.json")
	temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.WriteFile(temp, []byte("prior tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(temp, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}

	var hardlinkErr *configstore.FactoryResetHardlinkError
	if err := EraseShrinkHistoryCrashTemps(path); !errors.As(err, &hardlinkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	if len(hardlinkErr.Paths) != 1 || hardlinkErr.Paths[0].Path != temp {
		t.Fatalf("hardlink error paths = %+v, want crash temp %s", hardlinkErr.Paths, temp)
	}
	for _, file := range []string{temp, sibling} {
		if _, err := os.Lstat(file); err != nil {
			t.Fatalf("refusal must retain hardlink %s: %v", file, err)
		}
	}
}
