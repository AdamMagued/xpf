package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func malformedZonePairSnapshot12039(t *testing.T, action string, fallback string) (*config.Config, *ConfigSnapshot) {
	t.Helper()
	tree := &config.ConfigTree{}
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone A to-zone [ B C ] policy p1 match source-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match destination-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match application any",
		"set security policies from-zone A to-zone [ B C ] policy p1 then " + action,
	}
	if fallback == "global permit" {
		commands = append(commands,
			"set security policies global policy g-permit match source-address any",
			"set security policies global policy g-permit match destination-address any",
			"set security policies global policy g-permit match application any",
			"set security policies global policy g-permit then permit")
	} else if fallback == "default permit-all" {
		commands = append(commands, "set security policies default-policy permit-all")
	}
	for _, command := range commands {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return cfg, snap
}

// #12039 wire-path proof: a malformed multizone context containing a DENY
// must poison the complete snapshot, not disappear and leave A->B/A->C to a
// global permit or default-policy permit-all. The existing
// LenientContentDropped lowering emits the __unsupported__ application term,
// which the Rust helper's integrity preflight rejects for the whole snapshot.
func TestMalformedZonePairSnapshotRefused12039(t *testing.T) {
	for _, fallback := range []string{"global permit", "default permit-all"} {
		t.Run(fallback, func(t *testing.T) {
			cfg, snap := malformedZonePairSnapshot12039(t, "deny", fallback)
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatal("fixture did not record a malformed zone pair")
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatalf("snapshot has no whole-snapshot refusal diagnostic: malformed A->B/A->C DENY "+
					"was dropped and traffic falls through to %s; policies=%+v", fallback, snap.Policies)
			}
			sawSentinel := false
			for _, rule := range snap.Policies {
				for _, term := range rule.ApplicationTerms {
					if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
						sawSentinel = true
					}
				}
			}
			if !sawSentinel {
				t.Fatalf("snapshot carries a rejection reason but no __unsupported__ wire sentinel; "+
					"helper preflight cannot refuse the malformed pair before %s fallback", fallback)
			}
			if fallback == "global permit" {
				found := false
				for _, rule := range snap.Policies {
					if rule.Name == "g-permit" && rule.Action == "permit" {
						found = true
					}
				}
				if !found {
					t.Fatal("fixture lacks its global permit fallback")
				}
			}
			if fallback == "default permit-all" && snap.DefaultPolicy != "permit" {
				t.Fatalf("default policy = %q, want permit fallback", snap.DefaultPolicy)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
				t.Fatalf("config-level simulator does not refuse the malformed snapshot: %v", reasons)
			}
		})
	}
}

// The #11366 then-permit fixture remains part of the contract: both actions
// must remain bootable at tolerant compile, warn, and poison rather than
// partially enforce the first listed zone.
func TestMalformedZonePairPermitStillPoisonsSnapshot12039(t *testing.T) {
	cfg, snap := malformedZonePairSnapshot12039(t, "permit", "default permit-all")
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("malformed then-permit context must remain quarantined; warnings=%s", strings.Join(cfg.Warnings, "\n"))
	}
}

func mixedZonePairSnapshot12231(t *testing.T, fromZone string) (*config.Config, *ConfigSnapshot) {
	t.Helper()
	text := `security {
    zones { security-zone A; security-zone B; }
    policies {
        ` + fromZone + `
        global {
            policy g-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy permit-all;
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse mixed zone-pair shape %q: %v", fromZone, errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return cfg, snap
}

func TestMixedZonePairSnapshotCells12231(t *testing.T) {
	deny := `policy p1 {
        match { source-address any; destination-address any; application any; }
        then { deny; }
    }`
	permit := `policy ok {
        match { source-address any; destination-address any; application any; }
        then { permit; }
    }`
	for _, tc := range []struct {
		name       string
		fromZone   string
		policy     string
		from       string
		to         string
		action     string
		wantPoison bool
	}{
		{
			name:     "X03-nested-to-zone-deny",
			fromZone: `from-zone { A to-zone B { to-zone { B { ` + deny + ` } } } }`,
			policy:   "p1", from: "A", to: "B", action: "deny",
		},
		{
			name:     "M8-policy-less-mixed",
			fromZone: `from-zone { A to-zone B; }`,
		},
		{
			name:       "S07-mixed-direct-policy",
			fromZone:   `from-zone { A to-zone B { ` + deny + ` } }`,
			wantPoison: true,
		},
		{
			name:     "X15-mixed-with-valid-sibling",
			fromZone: `from-zone { A to-zone B { ` + deny + ` } B { to-zone { A { ` + permit + ` } } } }`,
			policy:   "ok", from: "B", to: "A", action: "permit",
			wantPoison: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, snap := mixedZonePairSnapshot12231(t, tc.fromZone)
			ruleIndex := func(name, from, to string) int {
				for i, rule := range snap.Policies {
					if rule.Name == name && rule.FromZone == from && rule.ToZone == to {
						return i
					}
				}
				return -1
			}
			globalIndex := -1
			for i, rule := range snap.Policies {
				if rule.Name == "g-permit" && rule.Action == "permit" {
					globalIndex = i
					break
				}
			}
			if globalIndex < 0 || snap.Policies[globalIndex].Action != "permit" {
				t.Fatalf("snapshot does not preserve global g-permit: %+v", snap.Policies)
			}
			if tc.policy != "" {
				i := ruleIndex(tc.policy, tc.from, tc.to)
				if i < 0 {
					t.Fatalf("snapshot lacks %s %s->%s: %+v", tc.policy, tc.from, tc.to, snap.Policies)
				}
				if snap.Policies[i].Action != tc.action {
					t.Fatalf("snapshot %s action = %q, want %q", tc.policy, snap.Policies[i].Action, tc.action)
				}
				if i >= globalIndex {
					t.Fatalf("snapshot %s %s->%s is not before g-permit: %+v", tc.policy, tc.from, tc.to, snap.Policies)
				}
			}

			sawSentinel := false
			for _, rule := range snap.Policies {
				for _, term := range rule.ApplicationTerms {
					if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
						sawSentinel = true
					}
				}
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if tc.wantPoison {
				malformed := strings.Join(cfg.Security.MalformedZonePairs, "\n")
				if !strings.Contains(malformed, "#11346") {
					t.Fatalf("mixed config diagnostic lost #11346: %q", malformed)
				}
				if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#11346") {
					t.Fatalf("mixed config warning lost #11346: %q", cfg.Warnings)
				}
				if config.LenientDroppedPolicyLocator(cfg) == "" {
					t.Fatal("mixed policy has no lenient poison locator")
				}
				if !sawSentinel || len(snap.Capabilities.PolicyContentRejected) == 0 || len(reasons) == 0 {
					t.Fatalf("mixed policy did not poison/refuse snapshot: sentinel=%v rejected=%v reasons=%v",
						sawSentinel, snap.Capabilities.PolicyContentRejected, reasons)
				}
			} else {
				if len(cfg.Security.MalformedZonePairs) != 0 || config.LenientDroppedPolicyLocator(cfg) != "" {
					t.Fatalf("clean mixed shape was recorded/poisoned: malformed=%q poison=%q",
						cfg.Security.MalformedZonePairs, config.LenientDroppedPolicyLocator(cfg))
				}
				if sawSentinel || len(snap.Capabilities.PolicyContentRejected) != 0 || len(reasons) != 0 {
					t.Fatalf("policy-less/enforceable mixed shape was poisoned: sentinel=%v rejected=%v reasons=%v",
						sawSentinel, snap.Capabilities.PolicyContentRejected, reasons)
				}
				if tc.name == "M8-policy-less-mixed" && ruleIndex("p1", "A", "B") >= 0 {
					t.Fatalf("policy-less mixed shape emitted a fabricated A->B p1 rule: %+v", snap.Policies)
				}
			}
		})
	}
}
