package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
	"testing"
)

const lateFenceHash12169 = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"

// TestFirstCommitRollbackLateRevocationReconcilesLiveCommit12169 reproduces
// the bounded-runner case: rollback returns while an old chpasswd invocation
// is blocked, a real commitConfirmedAndApply promotes the same three accounts,
// then the old invocation resumes. Its lock must be repaired to the live
// password before it can complete or drop the accounts' provenance markers.
func TestFirstCommitRollbackLateRevocationReconcilesLiveCommit12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	shadowPath = filepath.Join(root, "shadow")
	passwdPath = filepath.Join(root, "passwd")
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	homeBaseDir = filepath.Join(root, "home")
	rootSSHDir = filepath.Join(root, "root-ssh")
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir(), homeBaseDir, rootSSHDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"alice", "bob", "carol"}
	oldHash := "$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var passwd, shadow strings.Builder
	passwd.WriteString("root:x:0:0::/root:/bin/bash\n")
	shadow.WriteString("root:!:19000:0:99999:7:::\n")
	for i, name := range names {
		fmt.Fprintf(&passwd, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, 1001+i, 1001+i, name)
		fmt.Fprintf(&shadow, "%s:%s:19000:0:99999:7:::\n", name, oldHash)
	}
	if err := os.WriteFile(passwdPath, []byte(passwd.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte(shadow.String()), 0o600); err != nil {
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
	var oldConfig strings.Builder
	oldConfig.WriteString("system { host-name abandoned; login {")
	for _, name := range names {
		fmt.Fprintf(&oldConfig, " user %s { class super-user; authentication { encrypted-password \"%s\"; } }", name, lateFenceHash12169)
	}
	oldConfig.WriteString("} }")
	if err := s.LoadOverride(oldConfig.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	for i, name := range names {
		if err := markProvisioned(name, 1001+i); err != nil {
			t.Fatal(err)
		}
		if err := markPasswordProvisioned(name, 1001+i); err != nil {
			t.Fatal(err)
		}
	}

	started := filepath.Join(root, "lock-started")
	repaired := filepath.Join(root, "repaired")
	staleWrite := filepath.Join(root, "stale-write")
	events := filepath.Join(root, "password-events")
	failLock := filepath.Join(root, "fail-lock")
	gate := filepath.Join(root, "release-lock")
	if err := unix.Mkfifo(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then printf 'lock-start:%s\\n' \"$user\" >> '" + events + "'; printf '%s\\n' \"$user\" > '" + started + "'; read -r release < '" + gate + "'; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"if [ \"$hash\" = '!' ]; then printf 'stale-write:%s\\n' \"$user\" >> '" + events + "'; touch '" + staleWrite + "'; [ ! -f '" + failLock + "' ] || exit 1; else printf 'password-write:%s\\n' \"$user\" >> '" + events + "'; touch '" + repaired + "'; fi\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	oldBudget := hostAuthCloseoutBudget
	hostAuthCloseoutBudget = 80 * time.Millisecond
	t.Cleanup(func() { hostAuthCloseoutBudget = oldBudget })

	rollbackDone := make(chan struct{})
	go func() {
		s.InvokeRollbackTimerForTesting(gen)
		close(rollbackDone)
	}()
	waitFile12169(t, started)
	select {
	case <-rollbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded rollback did not return with old owner blocked")
	}

	var candidate strings.Builder
	candidate.WriteString("system { host-name legitimate; login {")
	for _, name := range names {
		fmt.Fprintf(&candidate, " user %s { class super-user; authentication { encrypted-password \"%s\"; } }", name, lateFenceHash12169)
	}
	candidate.WriteString("} }")
	if err := s.LoadOverride(candidate.String()); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applySystemLogin(cfg) }
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if got, ok := currentShadowHash(name); !ok || got != lateFenceHash12169 {
			t.Fatalf("real commit did not apply the live password for %s before the old owner resumed: %q %v", name, got, ok)
		}
	}
	for _, path := range []string{repaired, events} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(failLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, staleWrite)
	waitFile12169(t, repaired)
	victimData, err := os.ReadFile(started)
	if err != nil {
		t.Fatal(err)
	}
	victim := strings.TrimSpace(string(victimData))
	// Give the old inventory owner time to visit every remaining name. A
	// second lock-start would prove a post-promotion cascade, even if a later
	// repair happened to restore its hash.
	time.Sleep(100 * time.Millisecond)
	wantEvents := "stale-write:" + victim + "\npassword-write:" + victim + "\n"
	if got, err := os.ReadFile(events); err != nil || string(got) != wantEvents {
		t.Fatalf("stale owner started post-promotion revocations or repaired out of order: events=%q err=%v want=%q", got, err, wantEvents)
	}
	for _, name := range names {
		if got, ok := currentShadowHash(name); !ok || got != lateFenceHash12169 {
			t.Errorf("stale rollback owner left live password for %s revoked: %q %v", name, got, ok)
		}
		if _, err := os.Stat(markerPath(name)); err != nil {
			t.Errorf("live account %s provenance marker was dropped by stale owner: %v", name, err)
		}
		if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), name)); err != nil {
			t.Errorf("live account %s password provenance marker was dropped by stale owner: %v", name, err)
		}
	}
	if !s.IsConfirmPending() {
		t.Fatal("new commit-confirmed window was lost")
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	t.Log("accelerated 80ms closeout: real runner returned with one chpasswd blocked; real confirmed commit promoted three accounts; stale write was synchronously repaired before owner completion, other accounts were not revoked, and every live marker remained")
}

// TestFirstCommitRollbackPreLockRepairCannotOrphanRemovedUser12169 models a
// stale deprovision owner that repairs the live password before commit N+1
// removes the account. The post-repair settle must relock it before markers
// are forgotten.
func TestFirstCommitRollbackPreLockRepairCannotOrphanRemovedUser12169(t *testing.T) {
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
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	nConfig := fmt.Sprintf("system { host-name n; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } } }", lateFenceHash12169)
	if err := s.LoadOverride(nConfig); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(*config.Config) {}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}

	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	gateRepair := filepath.Join(root, "gate-repair")
	finalLock := filepath.Join(root, "final-lock")
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" != '!' ] && [ -f '" + blockRepair + "' ] && [ ! -f '" + repairStarted + "' ]; then touch '" + repairStarted + "'; while [ ! -f '" + gateRepair + "' ]; do sleep 0.01; done; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"[ \"$hash\" != '!' ] || touch '" + finalLock + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	t.Cleanup(func() { _ = os.WriteFile(gateRepair, nil, 0o600) })
	if err := os.WriteFile(blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	staleDone := make(chan error, 1)
	staleDoneRead := false
	t.Cleanup(func() {
		_ = os.WriteFile(gateRepair, nil, 0o600)
		if !staleDoneRead {
			select {
			case <-staleDone:
			case <-time.After(3 * time.Second):
			}
		}
	})
	go func() { staleDone <- d.deprovisionLoginUser("alice") }()
	waitFile12169(t, repairStarted)
	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) {
		d.applyErrForTest = errors.Join(d.applySystemLogin(cfg), d.reconcileAbsentLoginUsers(cfg))
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("commit N+1 removal: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("commit N+1 did not lock alice before stale repair resumed: hash=%q present=%v", hash, ok)
	}
	if err := os.Remove(finalLock); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-staleDone:
		staleDoneRead = true
		if err != nil {
			t.Fatalf("stale deprovision: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stale deprovision did not finish after repair release")
	}
	if _, err := os.Stat(finalLock); err != nil {
		hash, _ := currentShadowHash("alice")
		t.Fatalf("ORPHAN: stale pre-lock repair left hash=%q without relocking: %v", hash, err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("stale repair did not relock alice: hash=%q present=%v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); !os.IsNotExist(err) {
			t.Errorf("removed alice retained marker in %s: %v", dir, err)
		}
	}
}

// TestFirstCommitRollbackPreLockRepairCannotOrphanRemovedUserE2E12169 drives
// the real bounded rollback closeout. Its stale owner waits behind the first
// removed account's lock, then repairs the second (re-presented) account while
// that commit is held. A following removal lands before the repair is released.
func TestFirstCommitRollbackPreLockRepairCannotOrphanRemovedUserE2E12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::\nbob:$6$olderb$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:19000:0:99999:7:::\n"), 0o600); err != nil {
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
	abandoned := fmt.Sprintf("system { host-name abandoned; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } user bob { class super-user; authentication { encrypted-password \"%s\"; } } } }", lateFenceHash12169, lateFenceHash12169)
	if err := s.LoadOverride(abandoned); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	for _, user := range []struct {
		name string
		uid  int
	}{{"alice", 1001}, {"bob", 1002}} {
		if err := markProvisioned(user.name, user.uid); err != nil {
			t.Fatal(err)
		}
		if err := markPasswordProvisioned(user.name, user.uid); err != nil {
			t.Fatal(err)
		}
	}

	firstLock := filepath.Join(root, "first-lock")
	gateLock := filepath.Join(root, "gate-lock")
	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	gateRepair := filepath.Join(root, "gate-repair")
	watchFinalLock := filepath.Join(root, "watch-final-lock")
	finalLock := filepath.Join(root, "final-lock")
	trace := filepath.Join(root, "trace")
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" = '!' ]; then if [ ! -f '" + firstLock + "' ]; then printf '%s\\n' \"$user\" > '" + firstLock + "'; while [ ! -f '" + gateLock + "' ]; do sleep 0.01; done; fi; " +
		"[ ! -f '" + watchFinalLock + "' ] || touch '" + finalLock + "'; " +
		"else if [ -f '" + blockRepair + "' ] && [ ! -f '" + repairStarted + "' ]; then touch '" + repairStarted + "'; while [ ! -f '" + gateRepair + "' ]; do sleep 0.01; done; fi; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n" +
		"printf '%s:%s\\n' \"$user\" \"$hash\" >> '" + trace + "'\n"
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
	t.Cleanup(func() {
		_ = os.WriteFile(gateLock, nil, 0o600)
		_ = os.WriteFile(gateRepair, nil, 0o600)
	})

	rollbackDone := make(chan struct{})
	go func() { s.InvokeRollbackTimerForTesting(gen); close(rollbackDone) }()
	waitFile12169(t, firstLock)
	select {
	case <-rollbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded rollback did not return while the first lock was held")
	}
	firstBytes, err := os.ReadFile(firstLock)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.TrimSpace(string(firstBytes))
	target := "alice"
	if first == "alice" {
		target = "bob"
	} else if first != "bob" {
		t.Fatalf("first closeout lock was for unexpected user %q", first)
	}
	targetUID := 1001
	if target == "bob" {
		targetUID = 1002
	}

	nConfig := fmt.Sprintf("system { host-name n; login { user %s { class super-user; authentication { encrypted-password \"%s\"; } } } }", target, lateFenceHash12169)
	if err := s.LoadOverride(nConfig); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nHeld := make(chan struct{})
	releaseN := make(chan struct{}, 1)
	nDone := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case releaseN <- struct{}{}:
		default:
		}
	})
	d.applyBodyForTest = func(cfg *config.Config) {
		close(nHeld)
		<-releaseN
		d.applyErrForTest = d.applySystemLogin(cfg)
	}
	go func() {
		_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		nDone <- err
	}()
	select {
	case <-nHeld:
	case <-time.After(3 * time.Second):
		t.Fatal("commit N did not reach its held apply")
	}
	if err := os.WriteFile(gateLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile12169(t, repairStarted)
	if err := os.Remove(blockRepair); err != nil {
		t.Fatal(err)
	}
	releaseN <- struct{}{}
	if err := <-nDone; err != nil {
		t.Fatalf("commit N: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash(target); !ok || hash != lateFenceHash12169 {
		t.Fatalf("commit N did not apply the re-presented password for %s: hash=%q present=%v", target, hash, ok)
	}

	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) {
		d.applyErrForTest = errors.Join(d.applySystemLogin(cfg), d.reconcileAbsentLoginUsers(cfg))
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("commit N+1 removal: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash(target); !ok || hash != "!" {
		t.Fatalf("commit N+1 did not lock removed user %s before stale repair resumed: hash=%q present=%v", target, hash, ok)
	}
	// Re-seed markers as completion sentinels: the stale owner must finish
	// provenance cleanup before the test restores these package-level paths.
	if err := markProvisioned(target, targetUID); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned(target, targetUID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watchFinalLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceBytes, _ := os.ReadFile(trace)
		if strings.Count(string(traceBytes), target+":"+lateFenceHash12169) >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	traceBytes, _ := os.ReadFile(trace)
	if strings.Count(string(traceBytes), target+":"+lateFenceHash12169) < 2 {
		t.Fatalf("stale owner did not finish its pre-lock password repair: trace=%q", traceBytes)
	}
	finalLockSeen := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(finalLock); err == nil {
			finalLockSeen = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	markersGone := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, acctErr := os.Stat(markerPathIn(provisionedUsersDir, target))
		_, pwErr := os.Stat(markerPathIn(provisionedPasswordsDir(), target))
		if os.IsNotExist(acctErr) && os.IsNotExist(pwErr) {
			markersGone = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !markersGone {
		t.Fatalf("stale closeout owner did not finish provenance cleanup for %s", target)
	}
	if !finalLockSeen {
		hash, _ := currentShadowHash(target)
		t.Fatalf("ORPHAN (e2e): stale pre-lock repair left removed user %s with hash=%q and no provenance markers", target, hash)
	}

	// The final lock sentinel is written inside chpasswd while settle holds
	// applySem; acquiring it here also waits for marker cleanup and owner return.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	d.applySem.Release(1)
	if hash, ok := currentShadowHash(target); !ok || hash != "!" {
		t.Fatalf("settled stale owner left removed user %s unlocked: hash=%q present=%v", target, hash, ok)
	}
	if err := s.LoadOverride("system { host-name removed-again; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("ordinary N+2 apply: %v", err)
	}
	if hash, ok := currentShadowHash(target); !ok || hash != "!" {
		t.Fatalf("ordinary N+2 apply changed removed user's locked password: hash=%q present=%v", hash, ok)
	}
	t.Logf("real rollback closeout repaired %s across held commit N, commit N+1 removed it, and stale settlement relocked it before dropping provenance", target)
}

func waitFile12169(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
