package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBracedFilterSchemaSlotsReject12090(t *testing.T) {
	cases := []struct {
		name string
		text string
		// wantGate selects the rejection gate. "#12090" pins the #12090
		// silent-drop gate; "" accepts any gate, requiring only that the
		// config is rejected and no filter hook is consumed. The two
		// arity-violating cells use "" because master #12093 made the
		// inet/inet6 `filter input|output` leaves scalar+blockValue, so
		// validateScalarValueLeaf rejects them before the #12090 prewalk
		// gate runs. Both spellings still fail closed either way.
		wantGate string
	}{
		{
			name:     "interface-unit-identity",
			text:     "interfaces { ge-0/0/0 { unit { 0 filter input f; } } }",
			wantGate: "#12090",
		},
		{
			name:     "sampling-instance-identity",
			text:     "forwarding-options { sampling { instance { s filter input f; } } }",
			wantGate: "#12090",
		},
		{
			name:     "relay-group-identity",
			text:     "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group { lan filter input f; lan { active-server-group sg; interface ge-0/0/0.0; } } } }",
			wantGate: "#12090",
		},
		{
			name:     "relay-group-filter-named-packed-filter",
			text:     "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group { filter filter input f; filter { active-server-group sg; interface ge-0/0/0.0; } } } }",
			wantGate: "#12090",
		},
		{
			name:     "relay-group-simple-filter-named-packed-simple-filter",
			text:     "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group { simple-filter simple-filter input f; simple-filter { active-server-group sg; interface ge-0/0/0.0; } } } }",
			wantGate: "#12090",
		},
		{
			name:     "flat-unit-control",
			text:     "interfaces { ge-0/0/0 { unit 0 filter input f; } }",
			wantGate: "#12090",
		},
		{
			name:     "fully-braced-unit-control",
			text:     "interfaces { ge-0/0/0 { unit { 0 { filter input f; } } } }",
			wantGate: "#12090",
		},
		{
			name:     "flat-instance-control",
			text:     "forwarding-options { sampling { instance s filter input f; } }",
			wantGate: "#12090",
		},
		{
			name:     "fully-braced-instance-control",
			text:     "forwarding-options { sampling { instance { s { filter input f; } } } }",
			wantGate: "#12090",
		},
		{
			name:     "relay-filter-child-control",
			text:     "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group lan { active-server-group sg; interface ge-0/0/0.0; filter { input f; } } } }",
			wantGate: "#12090",
		},
		{
			name: "braced-unit-filter-input-list-value",
			text: "interfaces { ge-0/0/0 { unit { 0 { family inet { filter { input [ f g ]; } } } } } }",
		},
		{
			name:     "braced-unit-filter-empty-m2-variant",
			text:     "interfaces { ge-0/0/0 { unit { 0 { family inet { filter; } } } } }",
			wantGate: "#12090",
		},
		{
			name: "braced-unit-filter-valued-input-child",
			text: "interfaces { ge-0/0/0 { unit { 0 { family inet { filter { input f { x; } } } } } } }",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatal("CheckText accepted unsupported or malformed filter")
			}
			if cfg != nil {
				t.Fatalf("CheckText returned compiled config after rejection: %#v", cfg)
			}
			if tc.wantGate != "" && !strings.Contains(err.Error(), tc.wantGate) {
				t.Fatalf("CheckText error = %v; want %q rejection", err, tc.wantGate)
			}

			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse test config: %v", parseErrors)
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warned := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#12090") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile warnings = %q; want #12090", compiled.Warnings)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err == nil {
				t.Fatal("Store Commit accepted unsupported or malformed filter")
			}
		})
	}
}

func TestBracedUnitIdentityFilterConsumersRetainHooks12090(t *testing.T) {
	for _, iface := range []string{"ge-0/0/0", "lo0"} {
		for _, family := range []string{"inet", "inet6"} {
			for _, shape := range []string{"compound", "split"} {
				t.Run(iface+"/"+family+"/"+shape, func(t *testing.T) {
					var binding string
					if shape == "compound" {
						binding = "family " + family + " { filter { input f; } }"
					} else {
						binding = "family { " + family + " { filter { input f; } } }"
					}
					text := "firewall { family { " + family +
						" { filter f { term t { then accept; } } } } } " +
						"interfaces { " + iface + " { unit { 0 { " + binding + " } } } }"
					compiled, err := CheckText(text, -1)
					if err != nil {
						t.Fatalf("CheckText rejected supported %s/%s filter: %v", iface, family, err)
					}
					ifaceConfig := compiled.Interfaces.Interfaces[iface]
					if ifaceConfig == nil || ifaceConfig.Units[0] == nil {
						t.Fatalf("compiled interface/unit missing: %#v", ifaceConfig)
					}
					unit := ifaceConfig.Units[0]
					got := unit.FilterInputV4
					if family == "inet6" {
						got = unit.FilterInputV6
					}
					if got != "f" {
						t.Fatalf("%s/%s filter hook = %q, want f", iface, family, got)
					}
					for _, warning := range compiled.Warnings {
						if strings.Contains(warning, "#12090") {
							t.Fatalf("supported filter emitted #12090 warning: %q", warning)
						}
					}
				})
			}
		}
	}
}

func TestBracedUnitIdentityBlockValueAndRepeatedFilterConsumers12090(t *testing.T) {
	firewall := "firewall { family inet { filter f { term t { then accept; } } " +
		"filter g { term t { then accept; } } } " +
		"family inet6 { filter f { term t { then accept; } } " +
		"filter f6 { term t { then accept; } } } } "
	cases := []struct {
		name, family, direction, binding, want string
	}{
		{
			name:      "block-value-input",
			family:    "inet",
			direction: "input",
			binding:   "family inet { filter { input { f; } } }",
			want:      "f",
		},
		{
			name:      "repeated-input-last-wins",
			family:    "inet",
			direction: "input",
			binding:   "family inet { filter { input f; input g; } }",
			want:      "g",
		},
		{
			name:      "repeated-inet6-output-last-wins",
			family:    "inet6",
			direction: "output",
			binding:   "family inet6 { filter { output f; output f6; } }",
			want:      "f6",
		},
		{
			name:      "split-family-repeated-input-last-wins",
			family:    "inet",
			direction: "input",
			binding:   "family { inet { filter { input f; input g; } } }",
			want:      "g",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := firewall + "interfaces { ge-0/0/0 { unit { 0 { " +
				tc.binding + " } } } }"
			compiled, err := CheckText(text, -1)
			if err != nil {
				t.Fatalf("CheckText rejected consumed %s filter: %v", tc.name, err)
			}
			unit := compiled.Interfaces.Interfaces["ge-0/0/0"].Units[0]
			var got string
			switch {
			case tc.family == "inet" && tc.direction == "input":
				got = unit.FilterInputV4
			case tc.family == "inet" && tc.direction == "output":
				got = unit.FilterOutputV4
			case tc.family == "inet6" && tc.direction == "input":
				got = unit.FilterInputV6
			case tc.family == "inet6" && tc.direction == "output":
				got = unit.FilterOutputV6
			}
			if got != tc.want {
				t.Fatalf("%s hook = %q, want last consumed value %q", tc.name, got, tc.want)
			}
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#12090") {
					t.Fatalf("consumed filter emitted #12090 warning: %q", warning)
				}
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Store Commit rejected consumed %s filter: %v", tc.name, err)
			}
		})
	}
}

func TestBracedUnitIdentityFilterListsRejected12090(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range []string{"compound", "split"} {
			for _, direction := range []string{"input-list", "output-list"} {
				for _, defined := range []bool{true, false} {
					name := family + "/" + shape + "/" + direction + "/undefined"
					value := "missing"
					firewall := ""
					if defined {
						name = family + "/" + shape + "/" + direction + "/defined"
						value = "f"
						firewall = "firewall { family " + family +
							" { filter f { term t { then accept; } } } } "
					}
					t.Run(name, func(t *testing.T) {
						filter := "filter { " + direction + " " + value + "; }"
						var binding string
						if shape == "compound" {
							binding = "family " + family + " { " + filter + " }"
						} else {
							binding = "family { " + family + " { " + filter + " } }"
						}
						text := firewall + "interfaces { lo0 { unit { 0 { " + binding +
							" } } } }"

						if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
							t.Fatalf("CheckText error = %v; want #12090 rejection", err)
						}

						tree, parseErrors := config.NewParser(text).Parse()
						if len(parseErrors) != 0 {
							t.Fatalf("parse test config: %v", parseErrors)
						}
						compiled, err := config.CompileConfigLenient(tree)
						if err != nil {
							t.Fatalf("lenient compile: %v", err)
						}
						warned := false
						for _, warning := range compiled.Warnings {
							if strings.Contains(warning, "#12090") {
								warned = true
								break
							}
						}
						if !warned {
							t.Fatalf("lenient compile warnings = %q; want #12090", compiled.Warnings)
						}

						store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
						if err := store.EnterConfigure(); err != nil {
							t.Fatalf("EnterConfigure: %v", err)
						}
						defer store.ExitConfigure()
						if err := store.LoadOverride(text); err != nil {
							t.Fatalf("LoadOverride: %v", err)
						}
						if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), "#12090") {
							t.Fatalf("Store Commit error = %v; want #12090 rejection", err)
						}
					})
				}
			}
		}
	}
}

func TestBracedUnitIdentityFilterPackedChildRejected12090(t *testing.T) {
	cases := []struct {
		name, text, wantError string
	}{
		{
			name: "defined-filter",
			text: "interfaces { ge-0/0/0 { unit { 0 { family inet { filter input f; } } } } } " +
				"firewall { family inet { filter f { term t { then accept; } } } }",
			wantError: "#12090",
		},
		{
			name:      "undefined-filter",
			text:      "interfaces { ge-0/0/0 { unit { 0 { family inet { filter input f; } } } } }",
			wantError: "#12090",
		},
		{
			name:      "semi-braced-undefined-filter-control",
			text:      "interfaces { ge-0/0/0 { unit 0 { family inet { filter input f; } } } }",
			wantError: "references undefined filter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("CheckText error = %v; want %q", err, tc.wantError)
			}

			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse test config: %v", parseErrors)
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warned := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, tc.wantError) {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile warnings = %q; want %q", compiled.Warnings, tc.wantError)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Store Commit error = %v; want %q", err, tc.wantError)
			}
		})
	}
}

func TestBracedUnitIdentityPackedFilterTailsRemainRejected12090(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range []string{"compound", "split"} {
			t.Run(family+"/"+shape, func(t *testing.T) {
				var binding string
				if shape == "compound" {
					binding = "family " + family + " filter input f;"
				} else {
					binding = "family { " + family + " filter input f; }"
				}
				text := "interfaces { ge-0/0/0 { unit { 0 { " + binding + " } } } }"
				if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
					t.Fatalf("unconsumed packed filter tail error = %v; want #12090", err)
				}
			})
		}
	}
}

func TestForwardingOptionsFilterNamedBracedIdentitiesRemainAccepted12090(t *testing.T) {
	for _, tc := range []struct {
		name     string
		text     string
		kind     string
		instance string
	}{
		{
			name:     "sampling-braced-filter",
			text:     "forwarding-options { sampling { instance { filter { input { rate 100; } } } } }",
			kind:     "sampling",
			instance: "filter",
		},
		{
			name:     "sampling-flat-filter",
			text:     "forwarding-options { sampling { instance filter { input { rate 100; } } } }",
			kind:     "sampling",
			instance: "filter",
		},
		{
			name:     "sampling-braced-simple-filter",
			text:     "forwarding-options { sampling { instance { simple-filter { input { rate 100; } } } } }",
			kind:     "sampling",
			instance: "simple-filter",
		},
		{
			name:     "sampling-flat-simple-filter",
			text:     "forwarding-options { sampling { instance simple-filter { input { rate 100; } } } }",
			kind:     "sampling",
			instance: "simple-filter",
		},
		{
			name:     "port-mirroring-braced-filter",
			text:     "forwarding-options { port-mirroring { instance { filter { input { rate 1; ingress { interface ge-0/0/0.0; } } output { interface ge-0/0/1.0; } } } } }",
			kind:     "port-mirroring",
			instance: "filter",
		},
		{
			name:     "port-mirroring-flat-filter",
			text:     "forwarding-options { port-mirroring { instance filter { input { rate 1; ingress { interface ge-0/0/0.0; } } output { interface ge-0/0/1.0; } } } }",
			kind:     "port-mirroring",
			instance: "filter",
		},
		{
			name:     "port-mirroring-braced-simple-filter",
			text:     "forwarding-options { port-mirroring { instance { simple-filter { input { rate 1; ingress { interface ge-0/0/0.0; } } output { interface ge-0/0/1.0; } } } } }",
			kind:     "port-mirroring",
			instance: "simple-filter",
		},
		{
			name:     "port-mirroring-flat-simple-filter",
			text:     "forwarding-options { port-mirroring { instance simple-filter { input { rate 1; ingress { interface ge-0/0/0.0; } } output { interface ge-0/0/1.0; } } } }",
			kind:     "port-mirroring",
			instance: "simple-filter",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("filter-named forwarding instance rejected: %v", err)
			}
			if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12090") {
				t.Fatalf("filter-named forwarding instance warned #12090: %q", cfg.Warnings)
			}
			switch tc.kind {
			case "sampling":
				if cfg.ForwardingOptions.Sampling == nil ||
					cfg.ForwardingOptions.Sampling.Instances[tc.instance] == nil {
					t.Fatalf("sampling instance %q was not compiled: %+v", tc.instance, cfg.ForwardingOptions.Sampling)
				}
			case "port-mirroring":
				if cfg.ForwardingOptions.PortMirroring == nil ||
					cfg.ForwardingOptions.PortMirroring.Instances[tc.instance] == nil {
					t.Fatalf("port-mirroring instance %q was not compiled: %+v", tc.instance, cfg.ForwardingOptions.PortMirroring)
				}
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Store Commit rejected filter-named forwarding instance: %v", err)
			}
		})
	}
}

func TestPackedCompoundFamilyFilterConsumersRetainHooks12090(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, direction := range []string{"input", "output"} {
			t.Run(family+"/"+direction, func(t *testing.T) {
				text := "firewall { family " + family +
					" { filter f { term t { then accept; } } } } " +
					"interfaces { ge-0/0/0 { unit 0 { family " + family +
					" filter " + direction + " f; } } }"
				cfg, err := CheckText(text, -1)
				if err != nil {
					t.Fatalf("packed %s %s consumer rejected: %v", family, direction, err)
				}
				unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
				got := unit.FilterInputV4
				if direction == "output" {
					got = unit.FilterOutputV4
				}
				if family == "inet6" {
					got = unit.FilterInputV6
					if direction == "output" {
						got = unit.FilterOutputV6
					}
				}
				if got != "f" {
					t.Fatalf("packed %s %s hook = %q, want f", family, direction, got)
				}

				store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
				if err := store.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				defer store.ExitConfigure()
				if err := store.LoadOverride(text); err != nil {
					t.Fatalf("LoadOverride: %v", err)
				}
				if _, err := store.Commit(); err != nil {
					t.Fatalf("Store Commit rejected packed %s %s consumer: %v", family, direction, err)
				}
			})
		}
	}
}
