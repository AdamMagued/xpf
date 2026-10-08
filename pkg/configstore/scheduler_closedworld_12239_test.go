package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const schedulerDenyCheckTextBase12239 = `interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.2.1/24; } } }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/1.0; } }
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { deny; }
                scheduler-name deny-test;
            }
            policy p2 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`

func TestClosedWorldSchedulerAcceptsSupportedShapes12239(t *testing.T) {
	flat := []struct {
		name  string
		lines []string
		check func(*testing.T, *config.SchedulerConfig)
	}{
		{
			name: "description and daily window",
			lines: []string{
				`schedulers scheduler S description "business hours"`,
				"schedulers scheduler S daily all-day",
			},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				if !s.Daily || !s.AllDay {
					t.Fatalf("daily all-day was not compiled: %+v", s)
				}
			},
		},
		{
			name:  "R1a monday all-day exclude",
			lines: []string{"schedulers scheduler S monday all-day exclude"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if w == nil || !w.AllDay || !w.Exclude {
					t.Fatalf("flat-run lost all-day/exclude: %+v", s)
				}
			},
		},
		{
			name:  "R1b/VF17 daily all-day exclude",
			lines: []string{"schedulers scheduler S daily all-day exclude"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				if !s.Daily || !s.AllDay {
					t.Fatalf("daily flat-run was not compiled: %+v", s)
				}
			},
		},
		{
			name:  "R1c monday exclude all-day",
			lines: []string{"schedulers scheduler S monday exclude all-day"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if w == nil || !w.AllDay || !w.Exclude {
					t.Fatalf("reversed flat-run lost all-day/exclude: %+v", s)
				}
			},
		},
		{
			name:  "VF12 three-leaf flat-run",
			lines: []string{"schedulers scheduler S monday all-day exclude start-time 08:00:00"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if w == nil || !w.AllDay || !w.Exclude || w.StartTime != "08:00:00" {
					t.Fatalf("three-leaf flat-run differs from the separate-command reference: %+v", s)
				}
			},
		},
		{
			name:  "VF16 exclude then window",
			lines: []string{"schedulers scheduler S monday exclude start-time 08:00:00 stop-time 17:00:00"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if w == nil || !w.Exclude || w.StartTime != "08:00:00" || w.StopTime != "17:00:00" {
					t.Fatalf("exclude/window flat-run lost a value: %+v", s)
				}
			},
		},
		{
			name:  "canonical weekday window one-liner",
			lines: []string{"schedulers scheduler S monday start-time 09:00:00 stop-time 17:00:00"},
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
					t.Fatalf("weekday one-liner did not compile its day window: %+v", s)
				}
			},
		},
	}
	for _, tc := range flat {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			for _, line := range tc.lines {
				if err := store.SetFromInput(line); err != nil {
					t.Fatalf("SetFromInput(%q): %v", line, err)
				}
			}
			cfg, err := store.CommitCheck()
			if err != nil {
				t.Fatalf("CommitCheck: %v", err)
			}
			s := cfg.Schedulers["S"]
			if s == nil {
				t.Fatal("compiled config is missing scheduler S")
			}
			tc.check(t, s)
		})
	}

	for _, tc := range []struct {
		name  string
		text  string
		check func(*testing.T, *config.SchedulerConfig)
	}{
		{
			name: "hierarchical description",
			text: `schedulers { scheduler S { description "business hours"; daily all-day; } }`,
			check: func(t *testing.T, s *config.SchedulerConfig) {
				if !s.Daily || !s.AllDay {
					t.Fatalf("daily all-day was not compiled: %+v", s)
				}
			},
		},
		{
			name: "hierarchical packed valid leaves",
			text: `schedulers { scheduler S { daily all-day; monday exclude; tuesday { start-time 09:00:00; stop-time 17:00:00; } } }`,
			check: func(t *testing.T, s *config.SchedulerConfig) {
				mon, tue := s.Days["monday"], s.Days["tuesday"]
				if !s.AllDay || mon == nil || !mon.Exclude || tue == nil ||
					tue.StartTime != "09:00:00" || tue.StopTime != "17:00:00" {
					t.Fatalf("packed/braced day windows were not compiled: %+v", s)
				}
			},
		},
		{
			name: "braced all-day and exclude",
			text: `schedulers { scheduler S { monday { all-day; exclude; } } }`,
			check: func(t *testing.T, s *config.SchedulerConfig) {
				if w := s.Days["monday"]; w == nil || !w.AllDay || !w.Exclude {
					t.Fatalf("braced all-day/exclude lost a flag: %+v", s)
				}
			},
		},
		{
			name: "canonical Junos day window lines",
			text: `schedulers { scheduler S { daily start-time 08:00:00 stop-time 18:00:00; monday start-time 09:00:00 stop-time 17:00:00; } }`,
			check: func(t *testing.T, s *config.SchedulerConfig) {
				w := s.Days["monday"]
				if s.StartTime != "08:00:00" || s.StopTime != "18:00:00" || w == nil ||
					w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
					t.Fatalf("canonical day window lines compiled the wrong windows: %+v", s)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("CheckText rejected supported scheduler shape: %v", err)
			}
			s := cfg.Schedulers["S"]
			if s == nil {
				t.Fatal("CheckText compiled no scheduler S")
			}
			tc.check(t, s)
		})
	}
}

func TestClosedWorldSchedulerPackedDayTailsRejectThroughCheckText12239(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		bad  string
		deny bool
	}{
		{"I1a daily all-dya", `schedulers { scheduler deny-test { daily all-dya; } }`, "all-dya", true},
		{"I1b monday all-dya", `schedulers { scheduler deny-test { monday all-dya; } }`, "all-dya", true},
		{"I1c sunday exclud", `schedulers { scheduler deny-test { daily { start-time 09:00:00; stop-time 17:00:00; } sunday exclud; } }`, "exclud", true},
		{"TH08 monday exclud", `schedulers { scheduler S { monday exclud; } }`, "exclud", false},
		{"TH09 daily all-dya", `schedulers { scheduler S { daily all-dya; } }`, "all-dya", false},
		// The compiler reads only the first packed token; name the one it drops.
		{"packed all-day then exclude", `schedulers { scheduler S { monday all-day exclude; } }`, `unexpected "exclude" after "monday" "all-day"`, false},
		{"packed exclude then start-time", `schedulers { scheduler S { monday exclude start-time 08:00:00; } }`, `unexpected "start-time" after "monday" "exclude"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.text
			if tc.deny {
				text = schedulerDenyCheckTextBase12239 + text
			}
			_, err := CheckText(text, -1)
			if err == nil || !strings.Contains(err.Error(), tc.bad) || !strings.Contains(err.Error(), "scheduler") {
				t.Fatalf("CheckText error = %v, want rejection naming scheduler and %q", err, tc.bad)
			}
		})
	}
}

func TestClosedWorldSchedulerFlatRunRejectsUnknownLeaves12239(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		bad  string
	}{
		{"TF06 all-dya", "schedulers scheduler S monday all-dya", "all-dya"},
		{"TF07 exclud", "schedulers scheduler S monday exclud", "exclud"},
		{"TF11 typo after all-day", "schedulers scheduler S monday all-day exclud", "exclud"},
		{"TF12 typo after exclude", "schedulers scheduler S monday exclude star-time 08:00:00", "star-time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.SetFromInput(tc.line); err != nil {
				t.Fatalf("SetFromInput: %v", err)
			}
			_, err := store.CommitCheck()
			if err == nil || !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("CommitCheck error = %v, want rejection naming %q", err, tc.bad)
			}
		})
	}
}

// Expanding day runs makes the flat weekday one-liner commit-acceptable, and
// the #9235 residue hoist also lifts its stop-time to the scheduler level.
// That stray must never silently replace a configured daily window (a deny
// would then lapse early on every other day): strict commit either refuses
// the pair (today, via the #11358 repeated-boundary check) or compiles the
// daily window intact.
func TestClosedWorldSchedulerWeekdayRunKeepsDailyWindow12239(t *testing.T) {
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"schedulers scheduler S daily start-time 08:00:00",
		"schedulers scheduler S daily stop-time 18:00:00",
		"schedulers scheduler S monday start-time 09:00:00 stop-time 17:00:00",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	cfg, err := store.CommitCheck()
	if err != nil {
		if !strings.Contains(err.Error(), `scheduler "S"`) && !strings.Contains(err.Error(), "scheduler S") {
			t.Fatalf("CommitCheck refused for an unrelated reason: %v", err)
		}
		return
	}
	s := cfg.Schedulers["S"]
	if s == nil || s.StartTime != "08:00:00" || s.StopTime != "18:00:00" {
		t.Fatalf("weekday one-liner replaced the daily window: %+v", s)
	}
}

func TestClosedWorldSchedulerPackedDayTailLoadDoesNotBrick12239(t *testing.T) {
	text := `schedulers { scheduler S { daily all-dya; } }`
	tree, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse persisted scheduler: %v", parseErrs[0])
	}
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	db.SetWriterVersion("older-binary-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	store, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("lenient Load must not brick on the persisted typo: %v", err)
	}
	if store.ActiveConfig().Schedulers["S"] == nil {
		t.Fatal("lenient Load succeeded without retaining scheduler S")
	}
}

func TestClosedWorldSchedulerDescriptionAndFlatRunWedgesAreGone12239(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		parse bool
	}{
		{
			name:  "persisted description",
			text:  `system { host-name before; } schedulers { scheduler S { description "business hours"; daily all-day; } }`,
			parse: true,
		},
		{
			name: "persisted #8939 flat-run",
			text: "set system host-name before\nset schedulers scheduler S monday all-day exclude\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var tree *config.ConfigTree
			if tc.parse {
				var parseErrs []config.ParseError
				tree, parseErrs = config.NewParser(tc.text).Parse()
				if len(parseErrs) != 0 {
					t.Fatalf("parse persisted config: %v", parseErrs[0])
				}
			} else {
				tree = &config.ConfigTree{}
				for _, line := range strings.Split(strings.TrimSpace(tc.text), "\n") {
					path, err := config.ParseSetCommand(line)
					if err != nil {
						t.Fatalf("ParseSetCommand(%q): %v", line, err)
					}
					if err := tree.SetPath(path); err != nil {
						t.Fatalf("SetPath(%q): %v", line, err)
					}
				}
			}
			db, err := NewDB(filepath.Join(dir, ".configdb"))
			if err != nil {
				t.Fatalf("NewDB: %v", err)
			}
			db.SetWriterVersion("older-binary-1.0")
			if err := db.WriteActive(tree); err != nil {
				t.Fatalf("WriteActive: %v", err)
			}
			store, err := New(filepath.Join(dir, "xpf.conf"))
			if err != nil {
				t.Fatalf("New store: %v", err)
			}
			if err := store.Load(); err != nil {
				t.Fatalf("lenient Load: %v", err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := store.SetFromInput("system host-name after"); err != nil {
				t.Fatalf("SetFromInput unrelated change: %v", err)
			}
			if _, err := store.CommitCheck(); err != nil {
				t.Fatalf("unrelated commit was wedged by valid persisted scheduler config: %v", err)
			}
		})
	}
}
