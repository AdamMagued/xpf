package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

// TestFirstCommitRollbackRepairCannotOrphanRemovedUserPassword12169 holds the
// stale owner's password repair in chpasswd while a later commit removes the
// account. The repair must re-check live intent under applySem and leave no
// working password after that removal wins.
func TestFirstCommitRollbackRepairCannotOrphanRemovedUserPassword12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: s.ConfigPath()}}
	d.applyBodyForTest = func(*config.Config) {}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	oldConfig := fmt.Sprintf("system { host-name abandoned; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } } }", lateFenceHash12169)
	if err := s.LoadOverride(oldConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}

	lockStarted := filepath.Join(root, "lock-started")
	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	finalLock := filepath.Join(root, "final-lock")
	gateLock := filepath.Join(root, "gate-lock")
	gateRepair := filepath.Join(root, "gate-repair")
	counter := filepath.Join(root, "lock-count")
	for _, gate := range []string{gateLock, gateRepair} {
		if err := unix.Mkfifo(gate, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then n=0; [ ! -f '" + counter + "' ] || read -r n < '" + counter + "'; echo $((n+1)) > '" + counter + "'; " +
		"if [ \"$n\" -eq 0 ]; then touch '" + lockStarted + "'; read -r x < '" + gateLock + "'; else touch '" + finalLock + "'; fi; " +
		"else if [ -f '" + blockRepair + "' ]; then touch '" + repairStarted + "'; read -r x < '" + gateRepair + "'; fi; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	oldBudget := hostAuthCloseoutBudget
	hostAuthCloseoutBudget = 80 * time.Millisecond
	t.Cleanup(func() { hostAuthCloseoutBudget = oldBudget })

	rollbackDone := make(chan struct{})
	go func() { s.InvokeRollbackTimerForTesting(gen); close(rollbackDone) }()
	waitFile12169(t, lockStarted)
	select {
	case <-rollbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded rollback did not return while stale lock was blocked")
	}

	liveConfig := fmt.Sprintf("system { host-name legitimate; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } } }", lateFenceHash12169)
	if err := s.LoadOverride(liveConfig); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applySystemLogin(cfg) }
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateLock, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, repairStarted)

	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) {
		d.applyErrForTest = errors.Join(d.applySystemLogin(cfg), d.reconcileAbsentLoginUsers(cfg))
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if hash, _ := currentShadowHash("alice"); hash != "!" {
		t.Fatalf("removal commit must win before stale repair finishes; hash=%q", hash)
	}
	if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("removal commit did not clear the password marker: %v", err)
	}

	if err := os.Remove(blockRepair); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, finalLock)

	// This later commit must wait for the stale owner to finish its fenced
	// convergence, then leave the removed account locked and untracked.
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name still-removed; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, _ := currentShadowHash("alice"); hash == lateFenceHash12169 {
		t.Fatal("stale repair left a working password for the removed account")
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); !os.IsNotExist(err) {
			t.Errorf("removed account retained marker in %s: %v", dir, err)
		}
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("removed account password did not remain locked: hash=%q present=%v", hash, ok)
	}
}
