package userspace

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const crashWindowHelper12159 = `#!/usr/bin/python3
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
def ready_then_crash(life):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(4)
    time.sleep(life)
    os._exit(7)

if n % 6 == 1:
    ready_then_crash(0.1)
os._exit(3)
`

func runCrashWindowCadence12159(t *testing.T, readyEverySixth bool) (bool, int) {
	t.Helper()
	dir, err := os.MkdirTemp("/var/tmp/ContinuedFalcon-12159", "cadence-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	binary := filepath.Join(dir, "helper")
	script := crashWindowHelper12159
	if !readyEverySixth {
		script = `#!/usr/bin/python3
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
time.sleep(0.1)
os._exit(7)
`
	}
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.UserspaceConfig{
		Binary:        binary,
		ControlSocket: filepath.Join(dir, "control.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
		EventSocket:   filepath.Join(dir, "events.sock"),
	}
	m := New()
	m.mode = ModeUserspaceCompat
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	m.restartTimerFn = func(_ time.Duration, retry func()) {
		go retry()
	}
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("initial helper bring-up failed: %v", err)
	}
	readAttempts := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "attempts"))
		var n int
		_, _ = fmt.Sscanf(string(b), "%d", &n)
		return n
	}
	looping := false
	attempts := 0
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		attempts = readAttempts()
		_, looping = m.HelperSupervisorState()
		if looping || attempts >= 45 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	return looping, attempts
}

func TestCrashAfterEveryReadyStartCountsTowardLoop12159(t *testing.T) {
	looping, attempts := runCrashWindowCadence12159(t, false)
	if !looping {
		t.Fatalf("post-ready crash cadence never reached crash-loop verdict after %d real child starts", attempts)
	}
}

func TestFivePreReadyCrashesThenReadyCrashCountsTowardLoop12159(t *testing.T) {
	looping, attempts := runCrashWindowCadence12159(t, true)
	if !looping {
		t.Fatalf("mixed pre-/post-ready crash cadence never reached crash-loop verdict after %d real child starts", attempts)
	}
}
