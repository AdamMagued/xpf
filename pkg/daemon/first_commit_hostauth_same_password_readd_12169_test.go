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

const samePasswordReaddOldHash12169 = "$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type samePasswordReadd12169 struct {
	t                                      *testing.T
	root                                   string
	store                                  *configstore.Store
	daemon                                 *Daemon
	blockRepair, repairStarted, gateRepair string
	staleDone                              chan error
	staleRead                              bool
}

func newSamePasswordReadd12169(t *testing.T) *samePasswordReadd12169 {
	t.Helper()
	isolateFirstCommitRollbackHostAuth12169(t)
	f := &samePasswordReadd12169{t: t, root: t.TempDir()}
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+samePasswordReaddOldHash12169+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(f.root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	f.daemon = &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: store.ConfigPath()}}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	f.daemon.applyBodyForTest = func(*config.Config) {}
	if err := f.commit(samePasswordReaddConfig12169("initial")); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}

	f.blockRepair = filepath.Join(f.root, "block-repair")
	f.repairStarted = filepath.Join(f.root, "repair-started")
	f.gateRepair = filepath.Join(f.root, "gate-repair")
	bin, err := filepath.Abs(filepath.Join(f.root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" != '!' ] && [ -f '" + f.blockRepair + "' ] && [ ! -f '" + f.repairStarted + "' ]; then touch '" + f.repairStarted + "'; while [ ! -f '" + f.gateRepair + "' ]; do sleep 0.01; done; fi\n" +
		"sed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })
	if err := os.WriteFile(f.blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func samePasswordReaddConfig12169(host string) string {
	return fmt.Sprintf("system { host-name %s; login { user alice { class super-user; authentication { encrypted-password \"%s\"; } } } }", host, lateFenceHash12169)
}

func (f *samePasswordReadd12169) commit(text string) error {
	f.t.Helper()
	if err := f.store.LoadOverride(text); err != nil {
		return err
	}
	if _, err := f.daemon.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		return err
	}
	return f.store.ConfirmCommit()
}

func (f *samePasswordReadd12169) applyLogins() {
	f.daemon.applyBodyForTest = func(cfg *config.Config) {
		f.daemon.applyErrForTest = errors.Join(f.daemon.applySystemLogin(cfg), f.daemon.reconcileAbsentLoginUsers(cfg))
	}
}

func (f *samePasswordReadd12169) startStale() {
	f.staleDone = make(chan error, 1)
	f.t.Cleanup(func() {
		_ = os.WriteFile(f.gateRepair, nil, 0o600)
		if !f.staleRead {
			select {
			case <-f.staleDone:
			case <-time.After(3 * time.Second):
			}
		}
	})
	go func() { f.staleDone <- f.daemon.deprovisionLoginUser("alice") }()
	waitFile12169(f.t, f.repairStarted)
}

func (f *samePasswordReadd12169) waitStale() {
	f.t.Helper()
	select {
	case err := <-f.staleDone:
		f.staleRead = true
		if err != nil {
			f.t.Fatalf("stale deprovision: %v", err)
		}
	case <-time.After(5 * time.Second):
		f.t.Fatal("stale deprovision did not finish")
	}
}

func (f *samePasswordReadd12169) waitShadow(want string) {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hash, ok := currentShadowHash("alice"); ok && hash == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := currentShadowHash("alice")
	f.t.Fatalf("shadow did not reach %q (have %q)", want, got)
}

func (f *samePasswordReadd12169) markers() (pw, acct bool) {
	_, pwErr := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice"))
	_, acctErr := os.Stat(markerPathIn(provisionedUsersDir, "alice"))
	return pwErr == nil, acctErr == nil
}

func (f *samePasswordReadd12169) heldCommit(text string) func() error {
	f.t.Helper()
	held, releaseApply := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	f.daemon.applyBodyForTest = func(cfg *config.Config) {
		close(held)
		<-releaseApply
		f.daemon.applyErrForTest = errors.Join(f.daemon.applySystemLogin(cfg), f.daemon.reconcileAbsentLoginUsers(cfg))
	}
	if err := f.store.LoadOverride(text); err != nil {
		f.t.Fatal(err)
	}
	go func() {
		_, err := f.daemon.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		done <- err
	}()
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		f.t.Fatal("held commit never reached its apply body")
	}
	released := false
	f.t.Cleanup(func() {
		if !released {
			close(releaseApply)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	})
	return func() error {
		released = true
		close(releaseApply)
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-time.After(5 * time.Second):
			return errors.New("held commit did not finish")
		}
		return f.store.ConfirmCommit()
	}
}

// TestZZR3ReaddSamePasswordAfterRemoval covers the B2 gap where a stale
// chpasswd repair lands after removal and the account is re-added with that
// same hash. The later apply sees a no-op and does not claim provenance, so
// settlement must reclaim both markers before the next removal.
func TestZZR3ReaddSamePasswordAfterRemoval(t *testing.T) {
	f := newSamePasswordReadd12169(t)
	f.startStale()

	f.applyLogins()
	if err := f.commit("system { host-name removed; }"); err != nil {
		t.Fatalf("commit N+1 removal: %v", err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("N+1 did not lock alice: hash=%q present=%v", hash, ok)
	}
	if pw, acct := f.markers(); pw || acct {
		t.Fatalf("N+1 did not drop provenance: pw=%v acct=%v", pw, acct)
	}

	release := f.heldCommit(samePasswordReaddConfig12169("readded-same"))
	if err := os.WriteFile(f.gateRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitShadow(lateFenceHash12169)
	time.Sleep(100 * time.Millisecond)
	if err := release(); err != nil {
		t.Fatalf("commit N+2 same-password re-add: %v", err)
	}
	f.waitStale()
	if hash, _ := currentShadowHash("alice"); hash != lateFenceHash12169 {
		t.Fatalf("N+2 same-password re-add hash = %q, want repaired hash", hash)
	}
	if pw, acct := f.markers(); !pw || !acct {
		t.Fatalf("N+2 same-password re-add failed to reclaim markers: pw=%v acct=%v", pw, acct)
	}

	f.applyLogins()
	if err := f.commit("system { host-name removed-again; }"); err != nil {
		t.Fatalf("commit N+3 removal: %v", err)
	}
	if hash, _ := currentShadowHash("alice"); hash != "!" {
		t.Fatalf("N+3 removal left stale password usable: %q", hash)
	}
}

// TestZZR3SameHashWithoutOwnerWriteSkipsRemark pins the precise fold option:
// if shadow already held the configured hash before this owner's repair, the
// owner was a no-op and must not claim an operator-set password.
func TestZZR3SameHashWithoutOwnerWriteSkipsRemark(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+lateFenceHash12169+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: store.ConfigPath()}}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(*config.Config) {}
	if err := store.LoadOverride(samePasswordReaddConfig12169("same-hash")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}

	_, _, release, err := d.settleStaleLoginPassword12169("alice", 1001, lateFenceHash12169, lateFenceHash12169, true)
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("settle identical pre-existing hash: %v", err)
	}
	if _, err := os.Stat(markerPathIn(provisionedPasswordsDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("same-hash no-op claimed password marker: %v", err)
	}
	if _, err := os.Stat(markerPathIn(provisionedUsersDir, "alice")); !os.IsNotExist(err) {
		t.Fatalf("same-hash no-op claimed account marker: %v", err)
	}
}
