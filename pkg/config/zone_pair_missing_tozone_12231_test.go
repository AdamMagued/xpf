package config

import (
	"strings"
	"testing"
)

func toZoneLessFromZoneTree12231(t *testing.T) *ConfigTree {
	t.Helper()
	const text = `security {
    zones { security-zone A; security-zone B; }
    policies {
        from-zone {
            A {
                policy p1 {
                    match { source-address any; destination-address any; application any; }
                    then { deny; }
                }
            }
        }
        global {
            policy g-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy permit-all;
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse to-zone-less policy tree: %v", errs)
	}
	return tree
}

func TestToZoneLessFromZoneTolerantCompilePoisons12231(t *testing.T) {
	cfg, err := CompileConfigLenient(toZoneLessFromZoneTree12231(t))
	if err != nil {
		t.Fatalf("tolerant compile must remain bootable: %v", err)
	}
	if len(cfg.Security.Policies) != 0 {
		t.Fatalf("to-zone-less context compiled %d zone pairs, want none", len(cfg.Security.Policies))
	}
	if len(cfg.Security.MalformedZonePairs) != 1 {
		t.Fatalf("MalformedZonePairs = %q, want one missing-to-zone context", cfg.Security.MalformedZonePairs)
	}
	if diagnostic := cfg.Security.MalformedZonePairs[0]; !strings.Contains(diagnostic, `from-zone "A"`) || !strings.Contains(diagnostic, "no to-zone") {
		t.Fatalf("missing-to-zone diagnostic is not specific: %q", diagnostic)
	}
	if got := LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("tolerant compile did not add the poison carrier; the dropped deny could fall through to permit-all")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
		t.Fatalf("tolerant warning must explain the dropped context and snapshot refusal: %v", cfg.Warnings)
	}
}

func TestToZoneLessFromZoneBareCompileRejects12231(t *testing.T) {
	_, err := CompileConfig(toZoneLessFromZoneTree12231(t))
	if err == nil {
		t.Fatal("bare CompileConfig accepted a from-zone context without any to-zone")
	}
	if !strings.Contains(err.Error(), "#12231") || !strings.Contains(err.Error(), "no to-zone") {
		t.Fatalf("bare CompileConfig error does not identify the missing-to-zone context: %v", err)
	}
}

func TestInactiveToZoneLessFromZoneIsNotRecorded12231(t *testing.T) {
	const text = `security {
    zones { security-zone A; }
    policies {
        from-zone {
            A {
                inactive: policy parked { then { deny; } }
            }
        }
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse inactive policy tree: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("inactive policy must remain ignored: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 0 || LenientDroppedPolicyLocator(cfg) != "" {
		t.Fatalf("pruned inactive policy caused missing-to-zone poison: malformed=%q poison=%q",
			cfg.Security.MalformedZonePairs, LenientDroppedPolicyLocator(cfg))
	}
}

func toZoneLessShapeTree12231(t *testing.T, fromZone string) *ConfigTree {
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
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse zone-pair shape %q: %v", fromZone, errs)
	}
	return tree
}

func TestToZoneLessFromZoneAdditionalShapes12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	ok := `policy ok { match { source-address any; destination-address any; application any; } then { permit; } }`
	bad := []struct {
		name      string
		fromZone  string
		wantPairs int
	}{
		{"S2-keyed-direct-policy", `from-zone A { ` + deny + ` }`, 0},
		{"S3-keyed-dangling-to-zone", `from-zone A to-zone { ` + deny + ` }`, 0},
		{"S4-container-missing-to-zone-keyword", `from-zone { A { B { ` + deny + ` } } }`, 0},
		{"S5-container-to-zone-and-direct-policy", `from-zone { A { to-zone { B { ` + ok + ` } } ` + deny + ` } }`, 1},
		{"S6-container-to-zone-leaf-and-direct-policy", `from-zone { A { to-zone; ` + deny + ` } }`, 0},
		{"S14-two-from-zone-blocks", `from-zone { A { ` + deny + ` } } from-zone { A { to-zone { B { ` + ok + ` } } } }`, 1},
		{"S15-container-two-sources-one-bad", `from-zone { A { ` + deny + ` } B { to-zone { A { ` + ok + ` } } } }`, 1},
		{"S21-keyed-nested-to-zone-plus-direct-policy", `from-zone A { to-zone B { ` + ok + ` } ` + deny + ` }`, 0},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			tree := toZoneLessShapeTree12231(t, tc.fromZone)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("bare CompileConfig accepted a skipped active policy context")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatal("active policy context was not recorded in MalformedZonePairs")
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("lenient compile did not add the snapshot poison carrier")
			}
			if got := len(cfg.Security.Policies); got != tc.wantPairs {
				t.Fatalf("compiled zone-pair count=%d, want %d", got, tc.wantPairs)
			}
			if tc.name == "S5-container-to-zone-and-direct-policy" {
				pair := cfg.Security.Policies[0]
				if pair.FromZone != "A" || pair.ToZone != "B" || len(pair.Policies) != 1 {
					t.Fatalf("S5 valid A->B policy was not preserved: %+v", pair)
				}
			}
		})
	}
}

func TestToZoneLessFromZoneKeyedDiagnosticsNameSource12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
	}{
		{"S8-keyed-container-to-zone", `from-zone A to-zone { B { ` + deny + ` } }`},
		{"S19-keyed-misspelled-to-zone", `from-zone A { to-zon B { ` + deny + ` } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(toZoneLessShapeTree12231(t, tc.fromZone))
			if err == nil {
				t.Fatal("bare CompileConfig accepted a skipped keyed policy context")
			}
			if !strings.Contains(err.Error(), `from-zone "A"`) {
				t.Fatalf("diagnostic does not name the keyed source zone: %v", err)
			}
			if strings.Contains(err.Error(), `from-zone "B"`) || strings.Contains(err.Error(), `from-zone "to-zon"`) {
				t.Fatalf("diagnostic reports a child/destination instead of source zone A: %v", err)
			}
		})
	}
}

func TestToZoneLessFromZoneControlsRemainClean12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
	}{
		{"S11-combined-keyed-zone-pair", `from-zone A to-zone B { ` + deny + ` }`},
		{"S12-full-container-zone-pair", `from-zone { A { to-zone { B { ` + deny + ` } } } }`},
		{"S13-inactive-direct-policy", `from-zone { A { inactive: policy parked { then { deny; } } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := toZoneLessShapeTree12231(t, tc.fromZone)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("valid/inactive control rejected: %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile rejected control: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) != 0 || LenientDroppedPolicyLocator(cfg) != "" {
				t.Fatalf("control was poisoned: malformed=%q poison=%q",
					cfg.Security.MalformedZonePairs, LenientDroppedPolicyLocator(cfg))
			}
		})
	}
}

func TestMixedZonePairTolerantContent12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	ok := `policy ok { match { source-address any; destination-address any; application any; } then { permit; } }`
	for _, tc := range []struct {
		name       string
		fromZone   string
		wantFrom   string
		wantTo     string
		wantPolicy string
		wantAction PolicyAction
		wantPoison bool
	}{
		{"X03-keys-carry-nested-to-zone", `from-zone { A to-zone B { to-zone { B { ` + deny + ` } } } }`, "A", "B", "p1", PolicyDeny, false},
		{"M8-policy-less-mixed", `from-zone { A to-zone B; }`, "", "", "", PolicyDeny, false},
		{"S07-mixed-direct-policy", `from-zone { A to-zone B { ` + deny + ` } }`, "", "", "", PolicyDeny, true},
		{"X15-mixed-and-valid-sibling", `from-zone { A to-zone B { ` + deny + ` } B { to-zone { A { ` + ok + ` } } } }`, "B", "A", "ok", PolicyPermit, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := toZoneLessShapeTree12231(t, tc.fromZone)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#11346") {
				t.Fatalf("strict mixed-shape diagnostic = %v, want #11346", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant mixed shape must remain bootable: %v", err)
			}
			wantPairs := 0
			if tc.wantPolicy != "" {
				wantPairs = 1
			}
			if got := len(cfg.Security.Policies); got != wantPairs {
				t.Fatalf("compiled zone-pair count=%d, want %d", got, wantPairs)
			}
			if wantPairs != 0 {
				pair := cfg.Security.Policies[0]
				if pair.FromZone != tc.wantFrom || pair.ToZone != tc.wantTo || len(pair.Policies) != 1 {
					t.Fatalf("compiled pair = %+v, want %s->%s(1)", pair, tc.wantFrom, tc.wantTo)
				}
				policy := pair.Policies[0]
				if policy.Name != tc.wantPolicy || policy.Action != tc.wantAction || policy.LenientContentDropped {
					t.Fatalf("compiled policy = %+v, want enforceable %s action %v", policy, tc.wantPolicy, tc.wantAction)
				}
			}
			wantRecords := 0
			if tc.wantPoison {
				wantRecords = 1
			}
			if len(cfg.Security.MalformedZonePairs) != wantRecords || (LenientDroppedPolicyLocator(cfg) != "") != tc.wantPoison {
				t.Fatalf("malformed=%q poison=%q, want records=%d poison=%v",
					cfg.Security.MalformedZonePairs, LenientDroppedPolicyLocator(cfg), wantRecords, tc.wantPoison)
			}
			if tc.wantPoison {
				want := mixedKeyedZonePairError11346("A", "B").Error()
				if cfg.Security.MalformedZonePairs[0] != want {
					t.Fatalf("mixed diagnostic = %q, want shared remediation %q", cfg.Security.MalformedZonePairs[0], want)
				}
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warnings, "#11346") {
				t.Fatalf("mixed-shape warning lost: %q", cfg.Warnings)
			}
			if strings.Contains(warnings, "security policies security policies") {
				t.Fatalf("mixed-shape warning duplicated the shared prefix: %q", cfg.Warnings)
			}
			if tc.wantPoison && !strings.Contains(warnings, mixedKeyedZonePairError11346("A", "B").Error()+" (downgraded to warning on tolerant path") {
				t.Fatalf("tolerant warning does not carry the shared mixed-shape diagnostic: %q", cfg.Warnings)
			}
		})
	}
}

func TestToZoneLessSourceLessContainerDiagnostic12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
	}{
		{"X02-container-to-zone-no-source", `from-zone { to-zone { B { ` + deny + ` } } }`},
		{"X02-keyed-to-zone-no-source", `from-zone { to-zone B { ` + deny + ` } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := toZoneLessShapeTree12231(t, tc.fromZone)
			_, strictErr := CompileConfig(tree)
			if strictErr == nil {
				t.Fatal("source-less container accepted by bare CompileConfig")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant source-less container must remain bootable: %v", err)
			}
			if len(cfg.Security.Policies) != 0 || len(cfg.Security.MalformedZonePairs) != 1 || LenientDroppedPolicyLocator(cfg) == "" {
				t.Fatalf("source-less policy was not quarantined: pairs=%v malformed=%q poison=%q",
					cfg.Security.Policies, cfg.Security.MalformedZonePairs, LenientDroppedPolicyLocator(cfg))
			}
			for _, message := range []string{strictErr.Error(), cfg.Security.MalformedZonePairs[0]} {
				if strings.Contains(message, `from-zone "to-zone"`) || strings.Contains(message, "no to-zone context") ||
					!strings.Contains(message, "has no source zone before to-zone") || !strings.Contains(message, "#12231") {
					t.Fatalf("X02 diagnostic does not report the missing source zone: %q", message)
				}
			}
		})
	}
}
