package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestStoreLoadRecordsToZoneLessFromZone12231(t *testing.T) {
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
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse persisted config: %v", errs)
	}

	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load must remain bootable for the legacy config: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Store.Load")
	}
	if len(active.Security.Policies) != 0 {
		t.Fatalf("Store.Load installed %d zone pairs from a context with no to-zone", len(active.Security.Policies))
	}
	if len(active.Security.MalformedZonePairs) != 1 {
		t.Fatalf("Store.Load did not record the missing-to-zone context on ActiveConfig: %q", active.Security.MalformedZonePairs)
	}
	if got := config.LenientDroppedPolicyLocator(active); got == "" {
		t.Fatal("Store.Load did not retain the poison carrier for the dropped deny; snapshot may fall through to permit-all")
	}
	if warnings := strings.Join(active.Warnings, "\n"); !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
		t.Fatalf("Store.Load warning does not surface fail-closed handling: %v", active.Warnings)
	}
}

func securityPolicyShapeText12231(fromZone string) string {
	return `security {
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
}

func TestStoreLoadPoisonsToZoneLessShapes12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	ok := `policy ok { match { source-address any; destination-address any; application any; } then { permit; } }`
	for _, tc := range []struct {
		name      string
		fromZone  string
		wantPairs int
		wantDiag  string
	}{
		{"S2-keyed-direct-policy", `from-zone A { ` + deny + ` }`, 0, ""},
		{"S3-keyed-dangling-to-zone", `from-zone A to-zone { ` + deny + ` }`, 0, ""},
		{"S4-container-missing-to-zone-keyword", `from-zone { A { B { ` + deny + ` } } }`, 0, ""},
		{"S5-container-to-zone-and-direct-policy", `from-zone { A { to-zone { B { ` + ok + ` } } ` + deny + ` } }`, 1, ""},
		{"S6-container-to-zone-leaf-and-direct-policy", `from-zone { A { to-zone; ` + deny + ` } }`, 0, ""},
		{"S7-container-keyed-to-zone-in-keys", `from-zone { A to-zone B { ` + deny + ` } }`, 0, "#11346"},
		{"S8-keyed-container-to-zone", `from-zone A to-zone { B { ` + deny + ` } }`, 0, ""},
		{"S19-keyed-misspelled-to-zone", `from-zone A { to-zon B { ` + deny + ` } }`, 0, ""},
		{"S21-keyed-nested-to-zone-plus-direct-policy", `from-zone A { to-zone B { ` + ok + ` } ` + deny + ` }`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := config.NewParser(securityPolicyShapeText12231(tc.fromZone)).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse persisted shape: %v", errs)
			}
			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.db.WriteActive(tree); err != nil {
				t.Fatalf("write active config: %v", err)
			}
			if err := store.Load(); err != nil {
				t.Fatalf("Store.Load must remain bootable: %v", err)
			}
			active := store.ActiveConfig()
			if active == nil {
				t.Fatal("ActiveConfig is nil after Store.Load")
			}
			if got := len(active.Security.Policies); got != tc.wantPairs {
				t.Fatalf("Store.Load installed %d zone pairs, want %d", got, tc.wantPairs)
			}
			if len(active.Security.MalformedZonePairs) == 0 {
				t.Fatal("Store.Load did not record the malformed policy context")
			}
			if got := config.LenientDroppedPolicyLocator(active); got == "" {
				t.Fatal("Store.Load did not retain the snapshot poison carrier")
			}
			if tc.wantDiag != "" && !strings.Contains(strings.Join(active.Security.MalformedZonePairs, "\n"), tc.wantDiag) {
				t.Fatalf("Store.Load diagnostic %q does not contain %q", active.Security.MalformedZonePairs, tc.wantDiag)
			}
			if tc.name == "S8-keyed-container-to-zone" || tc.name == "S19-keyed-misspelled-to-zone" {
				if !strings.Contains(strings.Join(active.Security.MalformedZonePairs, "\n"), `from-zone "A"`) {
					t.Fatalf("Store.Load diagnostic does not name source A: %q", active.Security.MalformedZonePairs)
				}
			}
		})
	}
}

func TestStoreLoadKeepsNestedDenyUnderMixedNode12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	tree, errs := config.NewParser(securityPolicyShapeText12231(`from-zone { A to-zone B { to-zone { B { ` + deny + ` } } } }`)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse X03 shape: %v", errs)
	}
	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load must remain bootable: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Store.Load")
	}
	if len(active.Security.Policies) != 1 {
		t.Fatalf("Store.Load installed %d zone pairs, want the nested A->B deny", len(active.Security.Policies))
	}
	pair := active.Security.Policies[0]
	if pair.FromZone != "A" || pair.ToZone != "B" || len(pair.Policies) != 1 ||
		pair.Policies[0].Name != "p1" || pair.Policies[0].Action != config.PolicyDeny || pair.Policies[0].LenientContentDropped {
		t.Fatalf("Store.Load dropped the nested deny under the mixed node: %+v", pair)
	}
	if len(active.Security.MalformedZonePairs) != 0 || config.LenientDroppedPolicyLocator(active) != "" {
		t.Fatalf("enforced nested deny was poisoned: malformed=%q poison=%q",
			active.Security.MalformedZonePairs, config.LenientDroppedPolicyLocator(active))
	}
	if !strings.Contains(strings.Join(active.Warnings, "\n"), "#11346") {
		t.Fatalf("Store.Load lost the mixed-shape warning: %q", active.Warnings)
	}
}

func TestCheckTextReports11346BeforeOtherPolicyDiagnostics12231(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	text := securityPolicyShapeText12231(`from-zone { A to-zone B { ` + deny + ` } }`)
	_, err := CheckText(text, -1)
	if err == nil {
		t.Fatal("CheckText accepted the mixed container/keyed zone-pair spelling")
	}
	message := err.Error()
	if !strings.HasPrefix(strings.ToLower(message), "commit check failed: security policies contain a mixed zone-pair brace spelling:") {
		t.Fatalf("CheckText first-error slot does not contain the shared mixed-zone diagnostic: %q", message)
	}
	for _, want := range []string{"commit check failed", "#11346", "MIXED", "to-zone B", "Write the combined", "fully nested"} {
		if !strings.Contains(message, want) {
			t.Errorf("CheckText first error %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "security policies security policies") {
		t.Fatalf("CheckText duplicated the shared mixed-shape prefix: %q", message)
	}
	if strings.Contains(message, "no to-zone context") {
		t.Fatalf("CheckText reported the wrong #12231 diagnostic before #11346: %q", message)
	}
}

func TestStoreLoadToZoneLessControlsRemainClean12231(t *testing.T) {
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
			tree, errs := config.NewParser(securityPolicyShapeText12231(tc.fromZone)).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse control: %v", errs)
			}
			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.db.WriteActive(tree); err != nil {
				t.Fatalf("write active control: %v", err)
			}
			if err := store.Load(); err != nil {
				t.Fatalf("Store.Load rejected control: %v", err)
			}
			active := store.ActiveConfig()
			if active == nil {
				t.Fatal("ActiveConfig is nil after Store.Load")
			}
			if len(active.Security.MalformedZonePairs) != 0 || config.LenientDroppedPolicyLocator(active) != "" {
				t.Fatalf("control was poisoned: malformed=%q poison=%q",
					active.Security.MalformedZonePairs, config.LenientDroppedPolicyLocator(active))
			}
		})
	}
}
