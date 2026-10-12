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

// TestFirstCommitRollbackRepairRemovalWins12169 restores the a72c02443
// removal-wins scenario as its own test: the stale owner's password repair is
// held in chpasswd while a later commit removes the account. The repair must
// re-check live intent under applySem and leave no working password after that
// removal wins. The adjacent held-commit test keeps its own coverage intact.
func TestFirstCommitRollbackRepairRemovalWins12169(t *testing.T) {
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

// TestFirstCommitRollbackRootPasswordRepairHeldCommit12169 pins root's stale
// settlement behind a later commit's applySem, independently of the removal
// scenario in TestFirstCommitRollbackRootPasswordRepairCannotOutrunRemoval12169.
func TestFirstCommitRollbackRootPasswordRepairHeldCommit12169(t *testing.T) {
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
	lockDone := filepath.Join(root, "lock-done")
	gateLock := filepath.Join(root, "gate-lock")
	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	repairDone := filepath.Join(root, "repair-done")
	gateRepair := filepath.Join(root, "gate-repair")
	repairWriteCount := filepath.Join(root, "repair-write-count")
	repairWritePrefix := filepath.Join(root, "repair-write-")
	repairWriteTwo := filepath.Join(root, "repair-write-2")
	for _, gate := range []string{gateLock, gateRepair} {
		if err := unix.Mkfifo(gate, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gateLockFD, err := os.OpenFile(gateLock, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	gateRepairFD, err := os.OpenFile(gateRepair, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = gateLockFD.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = gateLockFD.Close()
		_ = gateRepairFD.Close()
	})

	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then if [ ! -f '" + lockStarted + "' ]; then touch '" + lockStarted + "'; read -r x < '" + gateLock + "'; fi; " +
		"else if [ -f '" + blockRepair + "' ]; then touch '" + repairStarted + "'; read -r x < '" + gateRepair + "'; fi; fi\n" +
		"if [ -f '" + repairStarted + "' ] && [ \"$hash\" != '!' ]; then n=0; [ ! -f '" + repairWriteCount + "' ] || read -r n < '" + repairWriteCount + "'; n=$((n+1)); echo $n > '" + repairWriteCount + "'; touch '" + repairWritePrefix + "'$n; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"[ \"$hash\" != '!' ] || [ ! -f '" + lockStarted + "' ] || touch '" + lockDone + "'\n" +
		"[ ! -f '" + repairStarted + "' ] || [ \"$hash\" = '!' ] || touch '" + repairDone + "'\n"
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
	rollbackStarted := false
	rollbackDoneRead := false
	commitHeld := make(chan struct{})
	releaseCommit := make(chan struct{}, 1)
	commitDone := make(chan error, 1)
	commitStarted := false
	commitDoneRead := false
	releaseGate := func(gate *os.File) {
		_, _ = gate.Write([]byte("continue\n"))
	}
	t.Cleanup(func() {
		// Release both named-pipe gates before draining any goroutine so a
		// failed assertion cannot strand a chpasswd child or stale closeout.
		_ = os.Remove(blockRepair)
		releaseGate(gateLockFD)
		releaseGate(gateRepairFD)
		if rollbackStarted {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(lockStarted); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if _, err := os.Stat(lockStarted); err == nil {
				deadline = time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Stat(lockDone); err == nil {
						break
					}
					time.Sleep(time.Millisecond)
				}
			}
		}
		if _, err := os.Stat(repairStarted); err == nil {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(repairDone); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
		}
		select {
		case releaseCommit <- struct{}{}:
		default:
		}
		if commitStarted && !commitDoneRead {
			select {
			case <-commitDone:
			case <-time.After(2 * time.Second):
			}
		}
		if rollbackStarted && !rollbackDoneRead {
			select {
			case <-rollbackDone:
			case <-time.After(2 * time.Second):
			}
		}
		// The stale owner enters root settlement immediately after the
		// repair command completes. Drain its semaphore work while the
		// isolated fixture globals are still installed.
		if _, err := os.Stat(repairDone); err == nil {
			time.Sleep(10 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if d.applySem.Acquire(ctx, 1) == nil {
				d.applySem.Release(1)
			}
			cancel()
		}
	})

	rollbackStarted = true
	go func() { s.InvokeRollbackTimerForTesting(gen); close(rollbackDone) }()
	waitFile12169(t, lockStarted)
	select {
	case <-rollbackDone:
		rollbackDoneRead = true
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

	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	laterHash := "$6$othersalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	if laterHash == lateFenceHash12169 {
		t.Fatal("held root commit hash must differ from the stale repair's captured hash")
	}
	if err := s.LoadOverride("system { host-name live-again; root-authentication { encrypted-password \"" + laterHash + "\"; } }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) {
		close(commitHeld)
		<-releaseCommit
		d.applyErrForTest = d.applyRootAuth(cfg)
	}
	commitStarted = true
	go func() {
		_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		commitDone <- err
	}()
	select {
	case <-commitHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("later root-password commit did not reach its held apply body")
	}

	if err := os.Remove(blockRepair); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, repairDone)
	if hash, ok := currentShadowHash("root"); !ok || hash != lateFenceHash12169 {
		t.Fatalf("stale repair did not finish its captured password before root settlement: hash=%q present=%v", hash, ok)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(repairWriteTwo); err == nil {
			t.Fatal("root settlement wrote again while the later root-password commit held applySem")
		}
		if hash, ok := currentShadowHash("root"); !ok || hash != lateFenceHash12169 {
			t.Fatalf("root settlement changed shadow state while the later commit was held: hash=%q present=%v", hash, ok)
		}
		time.Sleep(time.Millisecond)
	}

	releaseCommit <- struct{}{}
	select {
	case err := <-commitDone:
		commitDoneRead = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("held root-password commit did not finish after applySem was released")
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash("root"); !ok || hash != laterHash {
		t.Fatalf("later root-password commit did not apply after releasing applySem: hash=%q present=%v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "root")); err != nil {
			t.Errorf("later root-password commit did not restore root marker in %s: %v", dir, err)
		}
	}
}
