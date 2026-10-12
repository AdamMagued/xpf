package userspace

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const nmPersistentHelper12159 = `#!/usr/bin/python3
import socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
while True:
    time.sleep(300)
`

const nmRetryThenStayHelper12159 = `#!/usr/bin/python3
import os, socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
counter = os.path.join(os.path.dirname(path), "attempts")
try:
    n = int(open(counter).read())
except Exception:
    n = 0
n += 1
open(counter, "w").write(str(n))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
if n == 1:
    time.sleep(0.1)
    os._exit(7)
while True:
    time.sleep(300)
`

func startNMHelper12159(t *testing.T, script string, timer func(time.Duration, func())) *Manager {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "helper")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.mode = ModeUserspaceCompat
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	m.restartTimerFn = timer
	cfg := config.UserspaceConfig{
		Binary:        binary,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "s.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}
	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("initial real-helper bring-up: %v", err)
	}
	t.Cleanup(func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
	})
	return m
}

func waitNMSupervisorRunning12159(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		running := m.proc != nil && m.proc.Process != nil && m.procSup != nil
		m.mu.Unlock()
		if running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("real helper did not return under the production supervisor")
}

func killNMSupervisedChild12159(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	cmd, sup := m.proc, m.procSup
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil || sup == nil {
		t.Fatal("no real supervised child to kill")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill real helper: %v", err)
	}
	awaitSupervisor(t, m, sup.exited)
}

// NM-2: crashes separated by more than the backoff quiet window begin fresh
// count episodes. Each crash and retry is a real helper child owned by Manager.
func TestIsolatedCrashesResetRestartCount12159(t *testing.T) {
	oldBase, oldMax := helperRestartBackoffBase, helperRestartBackoffMax
	helperRestartBackoffBase, helperRestartBackoffMax = time.Millisecond, 64*time.Millisecond
	t.Cleanup(func() {
		helperRestartBackoffBase, helperRestartBackoffMax = oldBase, oldMax
	})
	m := startNMHelper12159(t, nmPersistentHelper12159, func(d time.Duration, fn func()) {
		time.AfterFunc(d, fn)
	})

	for i := 1; i <= 8; i++ {
		waitNMSupervisorRunning12159(t, m)
		if i > 1 {
			time.Sleep(300 * time.Millisecond) // > 2x the compressed 64ms cap
		}
		killNMSupervisedChild12159(t, m)
		rec := m.HelperCrashState()
		running, looping := m.HelperSupervisorState()
		t.Logf("isolated crash %d: running=%v looping=%v Restarts=%d", i, running, looping, rec.Restarts)
		if running || looping {
			t.Fatalf("isolated crash %d entered crash-loop state: running=%v looping=%v Restarts=%d",
				i, running, looping, rec.Restarts)
		}
		if rec.Restarts != 1 {
			t.Fatalf("isolated crash %d inherited the previous count: Restarts=%d, want 1", i, rec.Restarts)
		}
		if i < 8 {
			waitNMSupervisorRunning12159(t, m)
		}
	}
	_, recovered := m.HelperCrashHistory()
	if recovered != 7 {
		t.Fatalf("quietly ended recovered episodes=%d, want 7 (one journal entry per episode)", recovered)
	}
}

// NM-3: a real supervisor retry landing is reported as recovered while the
// child runs, and an intentional stop cannot leave a stale "running" marker.
func TestSupervisorRetryRecoveryState12159(t *testing.T) {
	var mu sync.Mutex
	var retry func()
	m := startNMHelper12159(t, nmRetryThenStayHelper12159, func(_ time.Duration, fn func()) {
		mu.Lock()
		retry = fn
		mu.Unlock()
	})
	m.mu.Lock()
	exited := m.procSup.exited
	m.mu.Unlock()
	awaitSupervisor(t, m, exited)

	mu.Lock()
	fn := retry
	mu.Unlock()
	if fn == nil {
		t.Fatal("production crash handler did not arm a retry callback")
	}
	fn() // invokes restartHelperAfterCrash against a second real child
	waitNMSupervisorRunning12159(t, m)
	rec := m.HelperCrashState()
	running, looping := m.HelperSupervisorState()
	t.Logf("landed retry: running=%v looping=%v crash=%v recovered=%v restarts=%d",
		running, looping, rec.LastExitWasCrash, rec.RecoveredSinceCrash, rec.Restarts)
	if !running || looping || !rec.LastExitWasCrash || !rec.RecoveredSinceCrash {
		t.Fatalf("landed retry state = running:%v looping:%v record:%+v; want live recovered helper",
			running, looping, rec)
	}
	history, total := m.HelperCrashHistory()
	if total != 0 || len(history) != 0 {
		t.Fatalf("landed retry was journaled before the quiet window: total:%d episodes:%+v",
			total, history)
	}

	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	rec = m.HelperCrashState()
	if rec.RecoveredSinceCrash {
		t.Fatalf("intentional stop retained the live-recovery marker: %+v", rec)
	}
	// A generation-advancing Compile remains an immediate episode boundary,
	// even after an intentional stop cleared the live-recovery marker.
	m.mu.Lock()
	m.completeHelperCrashRecoveryLocked(time.Now())
	m.mu.Unlock()
	_, total = m.HelperCrashHistory()
	if total != 1 {
		t.Fatalf("Compile recovery history total=%d, want 1", total)
	}
	m.mu.Lock()
	m.completeHelperCrashRecoveryLocked(time.Now())
	m.mu.Unlock()
	_, total = m.HelperCrashHistory()
	if total != 1 {
		t.Fatalf("repeated Compile recovery duplicated the episode: total=%d, want 1", total)
	}
}

// NM-2: an already-running recovered helper is journaled by the existing
// periodic status loop after the quiet window, without requiring another crash.
func TestRecoveredEpisodeJournalsAfterQuietWindowWithoutSecondCrash12159(t *testing.T) {
	oldBase, oldMax, oldInterval := helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval
	helperRestartBackoffBase, helperRestartBackoffMax = time.Millisecond, 64*time.Millisecond
	statusLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval = oldBase, oldMax, oldInterval
	})

	m := startNMHelper12159(t, nmPersistentHelper12159, func(d time.Duration, fn func()) {
		time.AfterFunc(d, fn)
	})
	killNMSupervisedChild12159(t, m)
	waitNMSupervisorRunning12159(t, m)

	recovered := m.HelperCrashState()
	if !recovered.RecoveredSinceCrash || recovered.RecoveredAt.IsZero() {
		t.Fatalf("supervisor retry did not establish recovered state: %+v", recovered)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		episodes, total := m.HelperCrashHistory()
		if total > 0 {
			if total != 1 || len(episodes) != 1 {
				t.Fatalf("history after quiet expiry = total:%d episodes:%+v, want one entry",
					total, episodes)
			}
			if !episodes[0].RecoveredAt.Equal(recovered.RecoveredAt) {
				t.Fatalf("journal RecoveredAt=%s, want readiness time %s",
					episodes[0].RecoveredAt, recovered.RecoveredAt)
			}
			if rec := m.HelperCrashState(); rec.LastExitWasCrash || rec.Restarts != 0 {
				t.Fatalf("quiet expiry did not clear the live episode: %+v", rec)
			}
			if running, looping := m.HelperSupervisorState(); !running || looping {
				t.Fatalf("helper state after quiet expiry = running:%v looping:%v; want still running",
					running, looping)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("healthy recovered helper was not journaled after the quiet window without a second crash")
}
