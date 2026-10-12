package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

// m1: site-(b)-only repair pin.
//
// Forces initial liveDesired=false, blocks the stale deprovision inside its
// first currentShadowHash read on a FIFO, promotes password-bearing alice via
// a no-op commitConfirmedAndApply while blocked, then swaps the FIFO pathname
// for a regular shadow file and releases the reader. The mutation-boundary
// live reread at old login_password.go:735 (site b) is then the ONLY promotion
// detector: site A already observed liveDesired=false before the block.
//
// Site-A unreachable proof (scenario, not hook):
//   - initial active is "removed" (asserted liveDesired=false, unlocked old
//     hash, ownsPassword=true).
//   - FIFO writer open blocks until the deprovision reader opens; the writer
//     signals only after Write. That rendezvous proves the deprovision passed
//     its initial liveDesired check (false) and entered currentShadowHash.
//   - promotion lands strictly after that signal, so site A's
//     `if liveDesired && password != ""` cannot observe it.
//   - first shadow read returns unlocked (FIFO content), so the
//     `else if !isLockedShadow(cur)` arm is taken and site B rereads live.
//   - repairStarted proves site-B reconcileUserPassword entered and blocked.
//
// After site-B repair blocks in chpasswd, a real N+1 removal (applySystemLogin
// + reconcileAbsentLoginUsers) locks alice, then the stale write is released.
// Correct settle relocks the removal-wins hash; a site-b-only revert leaves an
// unlocked orphan.
//
// Targeted mutant (must fail with ORPHAN, not timeout/fixture error):
//   - at site b only: delete the settleStaleLoginPassword12169 call and its
//     releaseApply assignment, restore `liveUser, liveDesired = current, true`
//     (or equivalent pre-settle assignment). The stale repair then writes the
//     live hash over the N+1 lock with no relock, and the final assertions below
//     report ORPHAN.
func TestFirstCommitRollbackSettleSiteBOnlyRepairs12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	oldHash := "$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shadowContent := "root:!:19000:0:99999:7:::\nalice:" + oldHash + ":19000:0:99999:7:::\n"
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0o600); err != nil {
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
	d.applyBodyForTest = func(*config.Config) {}
	if err := s.LoadOverride("system { host-name removed; }"); err != nil {
		t.Fatal(err)
	}
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
	if _, desired := d.liveDesiredLoginUser12169("alice"); desired {
		t.Fatalf("premise: alice must start undesired (removed active)")
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != oldHash {
		t.Fatalf("premise: alice must start unlocked with prior hash: hash=%q present=%v", hash, ok)
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
	if err := os.WriteFile(blockRepair, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Swap the shadow pathname for a FIFO. The writer below supplies one valid
	// unlocked entry but holds its fd open, so the deprovision's first ReadFile
	// consumes the entry then blocks waiting EOF.
	fifoContent := shadowContent
	if err := os.Remove(shadowPath); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(shadowPath, 0o600); err != nil {
		t.Fatal(err)
	}

	staleDone := make(chan error, 1)
	staleDoneRead := false
	wrote := make(chan struct{})
	releaseWriter := make(chan struct{}, 1)
	writerDone := make(chan error, 1)
	writerDoneRead := false
	t.Cleanup(func() {
		_ = os.WriteFile(gateRepair, nil, 0o600)
		select {
		case releaseWriter <- struct{}{}:
		default:
		}
		if !staleDoneRead {
			select {
			case <-staleDone:
			case <-time.After(3 * time.Second):
			}
		}
		if !writerDoneRead {
			select {
			case <-writerDone:
			case <-time.After(3 * time.Second):
			}
		}
	})

	go func() { staleDone <- d.deprovisionLoginUser("alice") }()
	go func() {
		f, err := os.OpenFile(shadowPath, os.O_WRONLY, 0o600)
		if err != nil {
			writerDone <- err
			return
		}
		if _, err := f.Write([]byte(fifoContent)); err != nil {
			_ = f.Close()
			writerDone <- err
			return
		}
		close(wrote)
		<-releaseWriter
		writerDone <- f.Close()
	}()

	select {
	case <-wrote:
	case <-time.After(3 * time.Second):
		t.Fatal("stale deprovision never entered FIFO shadow read")
	}
	// Promotion has not landed yet: site A already missed.
	if _, desired := d.liveDesiredLoginUser12169("alice"); desired {
		t.Fatal("premise broken: promotion leaked before FIFO rendezvous")
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
	if liveUser, desired := d.liveDesiredLoginUser12169("alice"); !desired || liveUser.EncryptedPassword.Reveal() != lateFenceHash12169 {
		t.Fatalf("premise: N promotion must desire alice password")
	}

	// Replace the FIFO pathname with a regular shadow file BEFORE closing the
	// writer, so the resumed reconcile's fresh opens hit the regular file while
	// the first ReadFile's held fd still refers to the old FIFO and unblocks
	// on close with the unlocked entry.
	if err := os.Remove(shadowPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}
	releaseWriter <- struct{}{}
	select {
	case err := <-writerDone:
		writerDoneRead = true
		if err != nil {
			t.Fatalf("FIFO writer: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO writer did not close")
	}

	// Only site b can be repairing: site A saw removed, first hash is unlocked.
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
		t.Fatalf("ORPHAN: site-b settle revert left hash=%q without relocking: %v", hash, err)
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != "!" {
		t.Fatalf("ORPHAN: stale site-b repair left alice unlocked: hash=%q present=%v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); !os.IsNotExist(err) {
			t.Errorf("removed alice retained marker in %s: %v", dir, err)
		}
	}
}

// settlePermitProbe12169 synchronously observes the stale owner's
// remove-user-keys supersede log, which fires after password settlement and
// before the B1 tail restore, while the retained settle permit must still be
// held. Handle runs on the deprovision goroutine, so TryAcquire observes the
// permit state exactly at that point with no sleep synchronization.
type settlePermitProbe12169 struct {
	daemon *Daemon
	seen   atomic.Bool
	held   atomic.Bool
}

func (p *settlePermitProbe12169) Enabled(context.Context, slog.Level) bool { return true }

func (p *settlePermitProbe12169) Handle(_ context.Context, r slog.Record) error {
	var op, target string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "op" {
			op = a.Value.String()
		}
		if a.Key == "target" {
			target = a.Value.String()
		}
		return true
	})
	if op == "remove-user-keys" && target == "alice" {
		p.seen.Store(true)
		if p.daemon.applySem.TryAcquire(1) {
			p.daemon.applySem.Release(1)
			p.held.Store(false)
		} else {
			p.held.Store(true)
		}
	}
	return nil
}

func (p *settlePermitProbe12169) WithAttrs([]slog.Attr) slog.Handler { return p }

func (p *settlePermitProbe12169) WithGroup(string) slog.Handler { return p }

// m2: retained settle permit pin.
//
// A stale deprovision whose password path settles (site a here; all sites
// a/b/c share the single retained releaseApply closure through function
// return) must still hold applySem when it reaches the keys cleanup that logs
// staleRevocationSuperseded12169("remove-user-keys", name). The probe asserts
// applySem.TryAcquire(1)==false synchronously inside that log record, before
// any B1 tail restore reacquisition.
//
// Fixture is fully synchronous: live desires alice password+keys, ownsKey is
// true, deprovision runs on the test goroutine, no sleeps, no background
// goroutines to join. slog.Default is restored via Cleanup.
//
// Targeted mutant (must fail specifically for crossed permit):
//   - unified retention: after each of the three settle-return assignments,
//     immediately call release() and set releaseApply=nil (avoiding the
//     deferred double-release). The probe then observes TryAcquire==true at
//     remove-user-keys and reports CROSSED PERMIT.
func TestFirstCommitRollbackSettlePermitRetainedAcrossCleanup12169(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	root := t.TempDir()
	oldHash := "$6$older$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+oldHash+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI12169 alice@xpf"
	keysFile := managedAuthorizedKeysPath("alice")
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bin, err := filepath.Abs(filepath.Join(root, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nIFS=: read -r user hash\nsed -i \"s#^$user:[^:]*#$user:$hash#\" '" + shadowPath + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "chpasswd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })

	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: s.ConfigPath()}}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	liveCfg := fmt.Sprintf("system { host-name live; login { user alice { class super-user; authentication { encrypted-password \"%s\"; ssh-ed25519 \"%s\"; } } } }", lateFenceHash12169, key)
	if err := s.LoadOverride(liveCfg); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(*config.Config) {}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if liveUser, desired := d.liveDesiredLoginUser12169("alice"); !desired || liveUser.EncryptedPassword.Reveal() != lateFenceHash12169 || len(liveUser.SSHKeys) == 0 {
		t.Fatalf("premise: live must desire alice password+keys")
	}

	probe := &settlePermitProbe12169{daemon: d}
	prevLog := slog.Default()
	slog.SetDefault(slog.New(probe))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	if err := d.deprovisionLoginUser("alice"); err != nil {
		t.Fatalf("stale deprovision: %v", err)
	}
	if !probe.seen.Load() {
		t.Fatal("remove-user-keys probe never fired: live keys premise broken")
	}
	if !probe.held.Load() {
		t.Fatal("CROSSED PERMIT: applySem free at remove-user-keys; retained settle permit must cover cleanup (immediate-release mutant)")
	}
	if hash, ok := currentShadowHash("alice"); !ok || hash != lateFenceHash12169 {
		t.Fatalf("live password not converged: hash=%q present=%v", hash, ok)
	}
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir()} {
		if _, err := os.Stat(markerPathIn(dir, "alice")); err != nil {
			t.Errorf("live alice lost marker in %s: %v", dir, err)
		}
	}
}
