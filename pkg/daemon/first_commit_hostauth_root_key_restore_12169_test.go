package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// TestZZR3RootKeyRestoreOutrunsRemoval pins the B1 serialization pattern for
// the stale root-key restore. The stale owner blocks while applying live root
// auth; a later removal must wait for applySem, then revoke the password and
// key file after the restore owner returns.
func TestZZR3RootKeyRestoreOutrunsRemoval(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	if err := markProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootAuthorizedKeysPath(), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0ld root@old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: store.ConfigPath()}}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI12169 root@xpf"
	if err := store.LoadOverride("system { host-name n; root-authentication { encrypted-password \"" + lateFenceHash12169 + "\"; ssh-ed25519 \"" + key + "\"; } }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(*config.Config) {}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}

	blockRepair := filepath.Join(root, "block-repair")
	repairStarted := filepath.Join(root, "repair-started")
	gate := filepath.Join(root, "gate")
	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\n" +
		"if [ \"$hash\" != '!' ] && [ -f '" + blockRepair + "' ] && [ ! -f '" + repairStarted + "' ]; then touch '" + repairStarted + "'; while [ ! -f '" + gate + "' ]; do sleep 0.01; done; fi\n" +
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
	staleRead := false
	t.Cleanup(func() {
		_ = os.WriteFile(gate, nil, 0o600)
		if !staleRead {
			select {
			case <-staleDone:
			case <-time.After(3 * time.Second):
			}
		}
	})
	go func() { staleDone <- d.applyRootAuth(&config.Config{}) }()
	waitFile12169(t, repairStarted)
	permitFree := d.applySem.TryAcquire(1)
	if permitFree {
		d.applySem.Release(1)
	}
	if permitFree {
		t.Fatal("stale root-key restore reached chpasswd without holding applySem")
	}

	if err := store.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(cfg *config.Config) { d.applyErrForTest = d.applyRootAuth(cfg) }
	removalStarted := make(chan struct{})
	removalDone := make(chan error, 1)
	go func() {
		close(removalStarted)
		_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever)
		removalDone <- err
	}()
	<-removalStarted
	select {
	case err := <-removalDone:
		t.Fatalf("root-auth removal completed while stale restore held applySem: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if hash, _ := currentShadowHash("root"); hash != "!" {
		t.Fatalf("root removal unexpectedly changed shadow before stale restore finished: %q", hash)
	}

	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-staleDone:
		staleRead = true
		// On unprivileged test runs, root authorized_keys replacement may fail
		// at fsatomic.WithOwner(0,0); the password write is the observable proof.
		t.Logf("stale root restore returned (root-key installation may be EPERM): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("stale root restore did not finish after gate release")
	}
	select {
	case err := <-removalDone:
		if err != nil {
			t.Fatalf("commit root-auth removal: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("root-auth removal did not finish after stale restore released applySem")
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if hash, _ := currentShadowHash("root"); hash != "!" {
		t.Fatalf("serialized removal left root password usable: %q", hash)
	}
	if _, err := os.Stat(rootAuthorizedKeysPath()); !os.IsNotExist(err) {
		t.Fatalf("serialized removal left root authorized_keys: %v", err)
	}
}
