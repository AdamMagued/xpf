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
)

// A stale deprovision owner's pre-lock repair is held in chpasswd while
// commit N+1 removes alice (lock + marker drop) and commit N+2 re-adds alice
// WITHOUT a password. The stale write then lands; settlement sees alice
// desired and delegates to reconcileUserPassword, whose D2 lock is gated on
// the password marker N+1 dropped.
func TestFirstCommitRollbackPasswordlessReaddRelocksStaleRepair12169(t *testing.T) {
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
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" != '!' ] && [ -f '" + blockRepair + "' ] && [ ! -f '" + repairStarted + "' ]; then touch '" + repairStarted + "'; while [ ! -f '" + gateRepair + "' ]; do sleep 0.01; done; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
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

	d.applyBodyForTest = func(cfg *config.Config) {
		d.applyErrForTest = errors.Join(d.applySystemLogin(cfg), d.reconcileAbsentLoginUsers(cfg))
	}
	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("commit N+1 removal: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("premise: N+1 did not lock alice: %q %v", hash, ok)
	}
	if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("premise: N+1 did not drop alice's password marker: %v", err)
	}

	if err := s.LoadOverride("system { host-name readded; login { user alice { class super-user; } } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("commit N+2 password-less re-add: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("premise: N+2 changed alice before the stale write: %q %v", hash, ok)
	}

	if err := os.WriteFile(gateRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-staleDone:
		staleDoneRead = true
		t.Logf("stale deprovision returned err=%v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("stale deprovision did not finish")
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	d.applySem.Release(1)
	hash, _ := currentShadowHash("alice")
	_, pwMarkerErr := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice"))
	_, acctMarkerErr := os.Stat(markerPathIn(provisionedUsersDir, "alice"))
	// A later ordinary apply of the same live config must also converge.
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatalf("N+3 no-op commit: %v", err)
	}
	hashAfter, _ := currentShadowHash("alice")
	t.Logf("after settle: alice hash=%q pwMarkerPresent=%v; after later apply hash=%q", hash, pwMarkerErr == nil, hashAfter)
	if hash != "!" || hashAfter != "!" {
		t.Fatalf("password-less re-added alice was not locked after stale repair: after settle=%q after later apply=%q", hash, hashAfter)
	}
	if pwMarkerErr != nil {
		t.Fatalf("stale repair was not re-claimed before the D2 lock: password marker missing: %v", pwMarkerErr)
	}
	if acctMarkerErr != nil {
		t.Fatalf("stale repair was not re-claimed before the D2 lock: account marker missing: %v", acctMarkerErr)
	}
}

// The deprovision tail's live restore must serialize with a later removal.
func TestFirstCommitRollbackTailRestoreSerializesRemoval12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n"), 0o600); err != nil {
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
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("premise: alice must have only account provenance before the tail restore: %v", err)
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
	d.applyBodyForTest = func(cfg *config.Config) {
		d.applyErrForTest = errors.Join(d.applySystemLogin(cfg), d.reconcileAbsentLoginUsers(cfg))
	}

	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	gateRepair := filepath.Join(root, "gate-repair")
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" != '!' ] && [ -f '" + blockRepair + "' ] && [ ! -f '" + repairStarted + "' ]; then touch '" + repairStarted + "'; while [ ! -f '" + gateRepair + "' ]; do sleep 0.01; done; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	if err := os.WriteFile(blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	staleDone := make(chan error, 1)
	removeDone := make(chan error, 1)
	staleDoneRead, removeDoneRead := false, false
	t.Cleanup(func() {
		_ = os.WriteFile(gateRepair, nil, 0o600)
		if !staleDoneRead {
			select {
			case <-staleDone:
			case <-time.After(3 * time.Second):
			}
		}
		if !removeDoneRead {
			select {
			case <-removeDone:
			case <-time.After(3 * time.Second):
			}
		}
	})
	go func() { staleDone <- d.deprovisionLoginUser("alice") }()
	waitFile12169(t, repairStarted)

	permitHeld := !d.applySem.TryAcquire(1)
	if !permitHeld {
		d.applySem.Release(1)
	}
	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		removeDone <- err
	}()
	if !permitHeld {
		select {
		case err := <-removeDone:
			removeDoneRead = true
			if err != nil {
				t.Fatalf("commit N+1 removal: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("unfenced stale restore unexpectedly blocked removal")
		}
		if err := s.ConfirmCommit(); err != nil {
			t.Fatal(err)
		}
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
		t.Fatal("stale deprovision did not finish")
	}
	if permitHeld {
		select {
		case err := <-removeDone:
			removeDoneRead = true
			if err != nil {
				t.Fatalf("commit N+1 removal: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("removal did not finish after stale restore released applySem")
		}
		if err := s.ConfirmCommit(); err != nil {
			t.Fatal(err)
		}
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("ORPHAN: stale tail restore left removed alice's password live: %q %v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); !os.IsNotExist(err) {
			t.Errorf("removed alice retained marker in %s: %v", dir, err)
		}
	}
}
