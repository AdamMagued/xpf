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
// account. A subsequent re-add commit holds applySem during stale settlement;
// the owner must wait and leave the newly committed password and markers live.
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
	repairDone := filepath.Join(root, "repair-done")
	finalLock := filepath.Join(root, "final-lock")
	gateLock := filepath.Join(root, "gate-lock")
	gateRepair := filepath.Join(root, "gate-repair")
	counter := filepath.Join(root, "lock-count")
	for _, gate := range []string{gateLock, gateRepair} {
		if err := unix.Mkfifo(gate, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then n=0; [ ! -f '" + counter + "' ] || read -r n < '" + counter + "'; echo $((n+1)) > '" + counter + "'; " +
		"if [ \"$n\" -eq 0 ]; then touch '" + lockStarted + "'; read -r x < '" + gateLock + "'; else touch '" + finalLock + "'; fi; " +
		"else if [ -f '" + blockRepair + "' ]; then touch '" + repairStarted + "'; read -r x < '" + gateRepair + "'; fi; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"[ ! -f '" + repairStarted + "' ] || touch '" + repairDone + "'\n"
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

	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	laterHash := "$6$othersalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	liveAgain := fmt.Sprintf("system { host-name still-live; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } } }", laterHash)
	if err := s.LoadOverride(liveAgain); err != nil {
		t.Fatal(err)
	}
	commitHeld := make(chan struct{})
	releaseCommit := make(chan struct{}, 1)
	commitDone := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case releaseCommit <- struct{}{}:
		default:
		}
	})
	d.applyBodyForTest = func(cfg *config.Config) {
		close(commitHeld)
		<-releaseCommit
		d.applyErrForTest = d.applySystemLogin(cfg)
	}
	go func() {
		_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		commitDone <- err
	}()
	select {
	case <-commitHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("later commit did not reach its held apply body")
	}

	if err := os.Remove(blockRepair); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, repairDone)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hash, _ := currentShadowHash("alice"); hash == laterHash {
			t.Fatal("stale password settlement crossed applySem and wrote the later commit's password while that commit was held")
		}
		time.Sleep(time.Millisecond)
	}
	if hash, _ := currentShadowHash("alice"); hash != lateFenceHash12169 {
		t.Fatalf("stale repair shadow hash changed before the held commit applied: %q", hash)
	}

	releaseCommit <- struct{}{}
	if err := <-commitDone; err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != laterHash {
		t.Fatalf("later commit did not apply its password after releasing applySem: hash=%q present=%v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); err != nil {
			t.Errorf("later commit did not restore account marker in %s: %v", dir, err)
		}
	}
}

// TestFirstCommitRollbackRootPasswordRepairCannotOutrunRemoval12169 reproduces
// C5: a timed-out closeout locks root, a later commit re-adds root's password,
// and a following commit removes it while the stale repair is blocked.
func TestFirstCommitRollbackRootPasswordRepairCannotOutrunRemoval12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:$6$oldsalt1$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: s.ConfigPath()}}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name abandoned; root-authentication { encrypted-password \"$6$oldsalt1$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/\"; } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}

	lockStarted := filepath.Join(root, "lock-started")
	gateLock := filepath.Join(root, "gate-lock")
	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	gateRepair := filepath.Join(root, "gate-repair")
	finalLock := filepath.Join(root, "final-lock")
	finalLockDone := filepath.Join(root, "final-lock-done")
	counter := filepath.Join(root, "lock-count")
	for _, gate := range []string{gateLock, gateRepair} {
		if err := unix.Mkfifo(gate, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then n=0; [ ! -f '" + counter + "' ] || read -r n < '" + counter + "'; echo $((n+1)) > '" + counter + "'; " +
		"if [ \"$n\" -eq 0 ]; then touch '" + lockStarted + "'; read -r x < '" + gateLock + "'; else touch '" + finalLock + "'; fi; " +
		"else if [ -f '" + blockRepair + "' ]; then touch '" + repairStarted + "'; read -r x < '" + gateRepair + "'; fi; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"[ \"$hash\" != '!' ] || [ ! -f '" + finalLock + "' ] || touch '" + finalLockDone + "'\n"
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
		t.Fatal("bounded rollback did not return while root lock was blocked")
	}

	if err := s.LoadOverride("system { host-name readded; root-authentication { encrypted-password \"" + lateFenceHash12169 + "\"; } }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applyRootAuth(cfg) }
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
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applyRootAuth(cfg) }
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if hash, _ := currentShadowHash("root"); hash != "!" {
		t.Fatalf("root-auth removal commit must leave root locked before the stale repair resumes; hash=%q", hash)
	}

	if err := os.Remove(blockRepair); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(finalLockDone); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(finalLockDone); err != nil {
		hash, _ := currentShadowHash("root")
		t.Fatalf("stale root-password repair left the commit-2 password usable after commit 3 removed root-authentication: hash=%q; final relock: %v", hash, err)
	}
	if hash, ok := currentShadowHash("root"); !ok || hash != "!" {
		t.Fatalf("root password was not left locked after stale repair settled: hash=%q present=%v", hash, ok)
	}
}
