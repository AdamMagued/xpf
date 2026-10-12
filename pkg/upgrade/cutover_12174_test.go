// #12174: a STOPPED journal does not prove the unit stayed down, and neither
// current nor loaded ExecStart alone identifies the process that could commit.
// A restart between FLIP 6a and successful 6c reload can run the old binary;
// a reload also leaves an already-running old process untouched. Its commits
// must survive auto-rollback. Conversely, a target process may have migrated
// the DB, so that snapshot must not be replaced.
//
// FAIL-ON-REVERT: omitting the re-stop or fresh snapshot makes the
// live-old-process cells restore pre-restart content. Re-snapshotting after a
// target process ran restores a migrated envelope and fails rollback.
package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedStoppedSameVersionCut drives a cut to 2.0.0 up to and including STOPPED
// through the Runner's own phase methods (authentic journal + on-disk state),
// with the cut-boundary snapshot taken over boundaryContent. It returns the
// runner/cfg and the config DB file path. The caller models the interruption
// window (old-unit restart + distinguishable commit) before re-running.
func seedStoppedSameVersionCut(t *testing.T, fs *fakeSystem, boundaryContent string) (*Runner, Config, string) {
	t.Helper()
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, dbFile, boundaryContent)
	stageSecondCut(t, r, cfg, fs)

	// Drive the second cut to durable STOPPED exactly as Run would: preflight
	// through VERIFY, then STOP + the cut-boundary snapshot + STOPPED journal.
	// (seedCrashState's STOPPED arm skips the cut-boundary snapshot, so the
	// phases are driven explicitly here.)
	prev, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read previous version for stopped journal: %v", err)
	}
	sourceGeneration, err := r.stagedGenConfig().ResolveCurrent()
	if err != nil {
		t.Fatalf("resolve staged generation for stopped journal: %v", err)
	}
	j := &Journal{
		State: StateInit, TargetVersion: fs.stagedVersion,
		PreviousVersion: prev, StartedAtUnixNano: fs.Now().UnixNano(),
		SourceGeneration: sourceGeneration,
	}
	must(t, r.transition(j, StateStaged))
	must(t, r.preflight(j))
	must(t, r.transition(j, StatePreflight))
	must(t, r.copyStaged(j))
	must(t, r.transition(j, StateCopied))
	must(t, r.verify(j))
	must(t, r.transition(j, StateVerified))
	must(t, fs.StopUnit(cfg.Unit))
	must(t, r.snapshotConfigDB(j))
	must(t, r.saveJournal(j))
	must(t, r.transition(j, StateStopped))
	return r, cfg, dbFile
}

// TestRun_StoppedResumeLiveOldUnitPreservesCommits12174 is the issue's
// scenario: interrupted-STOPPED + old-unit-started + distinguishable-commit,
// resumed to the same version.
func TestRun_StoppedResumeLiveOldUnitPreservesCommits12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundaryContent = "#xpf-config-envelope v=1\n{\"gen\":\"cut-boundary-before-restart\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundaryContent)

	// THE INTERRUPTION WINDOW. The cut stopped the unit and journaled STOPPED
	// but died before FLIP. The enabled old unit then started again (reboot /
	// postinst restart of an inactive unit / operator action) and the operator
	// committed a distinguishable config against the live old daemon.
	must(t, fs.StartUnit(cfg.Unit))
	const windowContent = "#xpf-config-envelope v=1\n{\"gen\":\"committed-after-old-unit-restart\"}"
	mkfile(t, dbFile, windowContent)

	// StartUnit returns success with unitRunning already true, matching
	// systemd's start-on-active behavior. The version-bound health probe
	// therefore sees the OLD binary unless this resume stops the old unit.
	// After the fix re-stops it, deliberately fail target health anyway so the
	// test observes auto-rollback restoring the FRESH snapshot (not merely a
	// successful cut leaving the live DB untouched).
	resumeStopped := false
	const committedAtStop = "#xpf-config-envelope v=1\n{\"gen\":\"committed-at-resume-stop-boundary\"}"
	fs.stopHook = func() {
		resumeStopped = true
		mkfile(t, dbFile, committedAtStop)
	}
	resumeCallOffset := len(fs.calls)
	fs.healthProbe = func(ver string, _ time.Duration) error {
		if ver == "2.0.0" && !resumeStopped {
			return errors.New("armed helper still executes old unit version")
		}
		if ver == "2.0.0" {
			return errors.New("synthetic target health failure")
		}
		return nil
	}

	// Resume: same staged version, journaled target unchanged.
	runErr := r.Run(Options{})

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after resume: %v", err)
	}
	if string(got) == boundaryContent {
		t.Fatalf("resumed STOPPED cut with a LIVE old unit rolled the config DB back "+
			"to the PRE-RESTART cut-boundary snapshot, silently discarding commits "+
			"made after the old daemon restarted.\n got=%q\nwant=%q\n"+
			"The resume skipped STOP + fresh snapshot at >= STOPPED (#12174).",
			got, committedAtStop)
	}
	if string(got) != committedAtStop {
		t.Fatalf("auto-rollback did not restore the snapshot taken after STOP.\n got=%q\nwant=%q",
			got, committedAtStop)
	}
	if runErr == nil || !strings.Contains(runErr.Error(), "rolled back") {
		t.Fatalf("resume must reach target health failure and auto-rollback; Run error = %v", runErr)
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read current version after rollback: %v", err)
	}
	if current != "1.0.0" {
		t.Fatalf("auto-rollback current version = %q, want previous 1.0.0", current)
	}
	resumeCalls := fs.calls[resumeCallOffset:]
	resumeStop, resumeFlip := -1, -1
	for i, call := range resumeCalls {
		if call == "stop" && resumeStop < 0 {
			resumeStop = i
		}
		if call == "dropin" && resumeFlip < 0 {
			resumeFlip = i
		}
	}
	if resumeStop < 0 || resumeFlip < 0 || resumeStop >= resumeFlip {
		t.Fatalf("STOP must happen before FLIP on the STOPPED resume; calls=%v", resumeCalls)
	}
}
func TestRun_Stopped6aOnlyResumePreservesCommits12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundary)
	must(t, r.repointSymlink(r.currentPath(), "2.0.0"))
	must(t, fs.StartUnit(cfg.Unit))
	const committed = "#xpf-config-envelope v=1\n{\"gen\":\"old-unit-commit-after-6a\"}"
	mkfile(t, dbFile, committed)
	fs.healthFailVersions["2.0.0"] = true

	resumeOffset := len(fs.calls)
	err := r.Run(Options{})
	got, readErr := os.ReadFile(dbFile)
	if readErr != nil {
		t.Fatalf("read config DB after rollback: %v", readErr)
	}
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("resume must reach target-health rollback, got %v", err)
	}
	if string(got) != committed {
		t.Fatalf("6a-only resume lost old-unit commit: got %q want %q", got, committed)
	}
	assertResumeStopBeforeFlip12174(t, fs.calls[resumeOffset:])
}

func TestRun_Stopped6cWrittenBeforeReloadUsesLoadedExecStart12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundary)
	must(t, r.repointSymlink(r.currentPath(), "2.0.0"))
	must(t, r.writeUnitDropin("2.0.0")) // 6c persisted; crash before daemon-reload
	must(t, fs.StartUnit(cfg.Unit))     // systemd still has the old loaded ExecStart
	const committed = "#xpf-config-envelope v=1\n{\"gen\":\"old-unit-commit-before-reload\"}"
	mkfile(t, dbFile, committed)
	fs.healthFailVersions["2.0.0"] = true

	err := r.Run(Options{})
	got, readErr := os.ReadFile(dbFile)
	if readErr != nil {
		t.Fatalf("read config DB after rollback: %v", readErr)
	}
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("resume must reach target-health rollback, got %v", err)
	}
	if string(got) != committed {
		t.Fatalf("resume trusted the on-disk drop-in instead of systemd's loaded ExecStart: got %q want %q",
			got, committed)
	}
}

func TestRun_StoppedResumeOldProcessSurvivesSuccessfulReload12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundary)
	must(t, r.repointSymlink(r.currentPath(), "2.0.0"))
	must(t, fs.StartUnit(cfg.Unit))
	oldExe := filepath.Join(r.versionDir("1.0.0"), "xpfd")
	if fs.runningUnitExe != oldExe {
		t.Fatalf("fixture running exe = %q, want old binary %q", fs.runningUnitExe, oldExe)
	}
	must(t, r.writeUnitDropin("2.0.0"))
	must(t, fs.DaemonReload()) // loaded ExecStart is target; old process survives
	if fs.runningUnitExe != oldExe {
		t.Fatalf("daemon-reload replaced the running process: got %q want %q",
			fs.runningUnitExe, oldExe)
	}
	const committed = "#xpf-config-envelope v=1\n{\"gen\":\"old-process-after-reload\"}"
	mkfile(t, dbFile, committed)
	originalStat := statConfigDBDir
	statConfigDBDir = func(string) (os.FileInfo, error) {
		return nil, errors.New("injected snapshot EIO")
	}
	t.Cleanup(func() { statConfigDBDir = originalStat })

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "fresh cut-boundary snapshot config DB") {
		t.Fatalf("Run error = %v, want fresh snapshot failure", err)
	}
	if !fs.unitRunning || fs.runningUnitExe != oldExe {
		t.Fatalf("snapshot failure did not safely restart old binary: running=%v exe=%q want=%q",
			fs.unitRunning, fs.runningUnitExe, oldExe)
	}
	if fs.loadedExecStart != fakeSystemdExecStart(oldExe) {
		t.Fatalf("snapshot failure left target ExecStart loaded: %q", fs.loadedExecStart)
	}
	current, readErr := r.readCurrentVersion()
	if readErr != nil || current != "2.0.0" {
		t.Fatalf("current after failed resume = %q, err=%v; want target still selected", current, readErr)
	}
}

func TestRun_Stopped6aOnlyHealthyTargetPreservesCommits12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundary)
	must(t, r.repointSymlink(r.currentPath(), "2.0.0"))
	must(t, fs.StartUnit(cfg.Unit))
	const committed = "#xpf-config-envelope v=1\n{\"gen\":\"healthy-old-unit-commit\"}"
	mkfile(t, dbFile, committed)
	oldStopped := false
	fs.stopHook = func() { oldStopped = true }
	fs.healthProbe = func(ver string, _ time.Duration) error {
		if ver == "2.0.0" && !oldStopped {
			return errors.New("loaded ExecStart still runs old binary")
		}
		return nil
	}

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy target resume failed: %v", err)
	}
	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after resume: %v", err)
	}
	if string(got) != committed {
		t.Fatalf("healthy 6a-only resume changed the old-unit commit: got %q want %q", got, committed)
	}
}

func TestRun_StoppedFullFlipKeepsOriginalSnapshot12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"pre-upgrade-boundary\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundary)
	must(t, r.flip("2.0.0"))
	must(t, fs.StartUnit(cfg.Unit))
	const migrated = "#xpf-config-envelope v=1 min-reader=99\n{}"
	mkfile(t, dbFile, migrated)
	fs.healthFailVersions["2.0.0"] = true

	resumeOffset := len(fs.calls)
	err := r.Run(Options{})
	got, readErr := os.ReadFile(dbFile)
	if readErr != nil {
		t.Fatalf("read config DB after rollback: %v", readErr)
	}
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("full-flip resume must reach target-health rollback, got %v", err)
	}
	if string(got) != boundary {
		t.Fatalf("full-flip resume replaced the original rollback snapshot: got %q want %q",
			got, boundary)
	}
	assertResumeStopBeforeFlip12174(t, fs.calls[resumeOffset:])
}

func TestRun_StoppedNeitherVersionRefusesWithRecoveryHint12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, _, _ := seedStoppedSameVersionCut(t, fs, boundary)
	if _, err := copyTree(r.versionDir("1.0.0"), r.versionDir("1.5.0")); err != nil {
		t.Fatalf("seed alternate version: %v", err)
	}
	must(t, r.repointSymlink(r.currentPath(), "1.5.0"))

	resumeOffset := len(fs.calls)
	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "inspect versions/current") ||
		!strings.Contains(err.Error(), "without deleting the journal or snapshot") {
		t.Fatalf("neither-version refusal lacks recovery guidance: %v", err)
	}
	if fs.unitRunning {
		t.Fatal("neither-version refusal unexpectedly started the unit")
	}
	for _, call := range fs.calls[resumeOffset:] {
		if call == "stop" || call == "dropin" || call == "start" {
			t.Fatalf("live mutation %q happened on refusal: calls=%v", call, fs.calls[resumeOffset:])
		}
	}
}

func TestRun_StoppedResumeSnapshotPersistFailureRestartsDaemon12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, _, _ := seedStoppedSameVersionCut(t, fs, boundary)
	previousWriter := writeUpgradeJournal
	writeUpgradeJournal = func(string, []byte, os.FileMode) error {
		return errors.New("injected journal EIO")
	}
	t.Cleanup(func() { writeUpgradeJournal = previousWriter })

	resumeOffset := len(fs.calls)
	err := r.Run(Options{})
	if err == nil {
		t.Fatal("Run succeeded after fresh-snapshot journal persistence failure")
	}
	for _, call := range fs.calls[resumeOffset:] {
		if call == "dropin" {
			t.Fatalf("FLIP ran after snapshot persistence failure: calls=%v", fs.calls[resumeOffset:])
		}
	}
	if !strings.Contains(err.Error(), "persist fresh cut-boundary snapshot") {
		t.Fatalf("Run error = %v, want fresh-snapshot journal persistence failure", err)
	}
	if !fs.unitRunning {
		t.Fatal("old daemon remained stopped after journal persistence failure")
	}
}

func TestRun_StoppedResumeSnapshotFailureRestartsDaemon12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, _, _ := seedStoppedSameVersionCut(t, fs, boundary)
	originalStat := statConfigDBDir
	statConfigDBDir = func(string) (os.FileInfo, error) {
		return nil, errors.New("injected snapshot EIO")
	}
	t.Cleanup(func() { statConfigDBDir = originalStat })

	resumeOffset := len(fs.calls)
	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "fresh cut-boundary snapshot config DB") {
		t.Fatalf("Run error = %v, want fresh snapshot failure", err)
	}
	if !fs.unitRunning {
		t.Fatal("old daemon remained stopped after fresh snapshot failure")
	}
	if !containsCall12174(fs.calls[resumeOffset:], "start") {
		t.Fatalf("old daemon restart missing after fresh snapshot failure: %v", fs.calls[resumeOffset:])
	}
	for _, call := range fs.calls[resumeOffset:] {
		if call == "dropin" {
			t.Fatalf("FLIP ran after fresh snapshot failure: calls=%v", fs.calls[resumeOffset:])
		}
	}
}

func TestRun_StoppedResumeCallerOwnedStoppedUnitRemainsDown12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundary = "#xpf-config-envelope v=1\n{\"gen\":\"boundary\"}"
	r, _, _ := seedStoppedSameVersionCut(t, fs, boundary)
	originalStat := statConfigDBDir
	statConfigDBDir = func(string) (os.FileInfo, error) {
		return nil, errors.New("injected snapshot EIO")
	}
	t.Cleanup(func() { statConfigDBDir = originalStat })

	resumeOffset := len(fs.calls)
	err := r.Run(Options{UnitAlreadyStopped: true})
	if err == nil || !strings.Contains(err.Error(), "fresh cut-boundary snapshot config DB") {
		t.Fatalf("Run error = %v, want fresh snapshot failure", err)
	}
	if fs.unitRunning {
		t.Fatal("caller-owned stopped unit was restarted after snapshot failure")
	}
	for _, call := range fs.calls[resumeOffset:] {
		if call == "stop" || call == "start" {
			t.Fatalf("caller-owned unit lifecycle was changed by Run: calls=%v", fs.calls[resumeOffset:])
		}
	}
}

func assertResumeStopBeforeFlip12174(t *testing.T, calls []string) {
	t.Helper()
	stop, flip := -1, -1
	for i, call := range calls {
		if call == "stop" && stop < 0 {
			stop = i
		}
		if call == "dropin" && flip < 0 {
			flip = i
		}
	}
	if stop < 0 || flip < 0 || stop >= flip {
		t.Fatalf("STOP must precede FLIP on a STOPPED resume; calls=%v", calls)
	}
}

func containsCall12174(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}
