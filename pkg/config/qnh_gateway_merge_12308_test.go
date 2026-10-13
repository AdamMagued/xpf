package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12308: every qualified-next-hop statement for one gateway compiles to ONE
// next-hop, whichever spelling, block, root or routing instance carries it.
// compiler_static_qnh_merge_12308.go has the mechanism and its boundaries.
//
// Each expectation is a NextHopEntry LITERAL compared with reflect.DeepEqual.
// That proves every authored setting survived, and it also fails if the
// compile-only provenance bit leaks out of the compiler, because DeepEqual
// reads unexported fields.

type qnhCase12308 struct {
	name   string
	tree   func(t *testing.T) *ConfigTree
	routes func(cfg *Config) []*StaticRoute // the list dest compiles into
	dest   string
	want   []NextHopEntry
}

func qnhGlobal12308(cfg *Config) []*StaticRoute { return cfg.RoutingOptions.StaticRoutes }

func qnhInet6_12308(cfg *Config) []*StaticRoute { return cfg.RoutingOptions.Inet6StaticRoutes }

func qnhVRF12308(cfg *Config) []*StaticRoute {
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "VRF-A" {
			return ri.StaticRoutes
		}
	}
	return nil
}

func qnhHier12308(text string) func(t *testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return hierTree(t, text) }
}

func qnhFlat12308(lines ...string) func(t *testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return flatTreeFromSets(t, lines...) }
}

// runQNHCases12308 compiles every case on BOTH paths. Strict commit must
// accept it (this issue's first draft refused valid `set` sequences), the
// tolerant path must not warn about the next-hop, and both must compile to
// exactly want.
func runQNHCases12308(t *testing.T, cases []qnhCase12308) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strict, err := CompileConfig(tc.tree(t))
			if err != nil {
				t.Fatalf("strict commit refused it: %v", err)
			}
			tolerant, err := CompileConfigLenient(tc.tree(t))
			if err != nil || tolerant == nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			for _, w := range tolerant.Warnings {
				if strings.Contains(w, "qualified-next-hop") {
					t.Errorf("tolerant compile warned about a statement it compiles correctly: %q", w)
				}
			}
			for _, got := range []struct {
				path string
				cfg  *Config
			}{{"strict", strict}, {"tolerant", tolerant}} {
				route := findStaticRoute3871(t, tc.routes(got.cfg), tc.dest)
				if !reflect.DeepEqual(route.NextHops, tc.want) {
					t.Errorf("%s: next-hops = %+v, want %+v", got.path, route.NextHops, tc.want)
				}
			}
		})
	}
}

const (
	qnhIfaceBlock12308 = `qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; }`
	qnhPrefBlock12308  = `qualified-next-hop 10.0.0.2 { preference 250; }`
)

// qnhMerged12308 is the one next-hop every re-opening below must compile to:
// the interface from one statement, the preference from the other.
var qnhMerged12308 = []NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/0.0", Preference: 250, HasPreference: true}}

// The hierarchical re-openings inside ONE route block. Measured before the
// fix: each compiled to two next-hops, {interface, no preference} and
// {preference 250}, in both orders.
func TestQualifiedNextHopStatementsMergeByGateway12308(t *testing.T) {
	route := func(body string) string {
		return `routing-options { static { route 10.5.0.0/16 { ` + body + ` } } }`
	}
	runQNHCases12308(t, []qnhCase12308{
		{"two blocks, interface then preference",
			qnhHier12308(route(qnhIfaceBlock12308 + " " + qnhPrefBlock12308)),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"two blocks, preference then interface",
			qnhHier12308(route(qnhPrefBlock12308 + " " + qnhIfaceBlock12308)),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"leaf form then block",
			qnhHier12308(route(`qualified-next-hop 10.0.0.2 interface ge-0/0/0.0; ` + qnhPrefBlock12308)),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"two leaf forms",
			qnhHier12308(route(`qualified-next-hop 10.0.0.2 interface ge-0/0/0.0; qualified-next-hop 10.0.0.2 preference 250;`)),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		// Later statements override PER SETTING, which is what flat-set replay
		// of the same statements does: the re-stated preference wins, and the
		// interface and metric the later block does not mention survive.
		{"a later statement overrides only what it authors",
			qnhHier12308(route(`qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; preference 100; metric 7; } ` + qnhPrefBlock12308)),
			qnhGlobal12308, "10.5.0.0/16",
			[]NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/0.0", Preference: 250, HasPreference: true, Metric: 7, HasMetric: true}}},
		{"rib inet6.0, two blocks",
			qnhHier12308(`routing-options { rib inet6.0 { static { route ::/0 { qualified-next-hop 2001:db8::1 { interface ge-0/0/0.0; } qualified-next-hop 2001:db8::1 { preference 250; } } } } }`),
			qnhInet6_12308, "::/0",
			[]NextHopEntry{{Address: "2001:db8::1", Interface: "ge-0/0/0.0", Preference: 250, HasPreference: true}}},
	})
}

// The flat `set` sequences an operator types. SetPath keeps a bare leaf and a
// modifier container for one gateway as two nodes, so before the fix the bare
// half compiled as a preference-5 copy of the backup in the PRIMARY tier, and
// a commit gate on repeated nodes would have refused these outright.
func TestQualifiedNextHopFlatSetStatementsMerge12308(t *testing.T) {
	const (
		primary = "set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1"
		bare    = "set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1"
		pref    = "set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 200"
		llBare  = "set routing-options static route ::/0 qualified-next-hop fe80::1"
		llIface = "set routing-options static route ::/0 qualified-next-hop fe80::1 interface reth2.0"
	)
	floating := []NextHopEntry{{Address: "10.0.0.1"}, {Address: "192.168.1.1", Preference: 200, HasPreference: true}}
	// The bare link-local half also had no interface, which a link-local
	// gateway needs to resolve (#3881).
	linkLocal := []NextHopEntry{{Address: "fe80::1", Interface: "reth2.0"}}
	runQNHCases12308(t, []qnhCase12308{
		{"bare then preference", qnhFlat12308(primary, bare, pref), qnhGlobal12308, "0.0.0.0/0", floating},
		{"preference then bare", qnhFlat12308(primary, pref, bare), qnhGlobal12308, "0.0.0.0/0", floating},
		{"link-local bare then interface", qnhFlat12308(llBare, llIface), qnhGlobal12308, "::/0", linkLocal},
		{"link-local interface then bare", qnhFlat12308(llIface, llBare), qnhGlobal12308, "::/0", linkLocal},
	})
}

// The merge must also span route blocks that compile into one route: a
// repeated `route <p>` block, a second routing-options root, `rib inet.0
// static` beside `static`, and the same shapes inside a routing instance.
// Measured before the fix: every one compiled clean, silently, to two halves.
func TestQualifiedNextHopMergesAcrossRouteBlocks12308(t *testing.T) {
	route := func(body string) string { return `route 10.5.0.0/16 { ` + body + ` }` }
	vrf := func(ro string) string {
		return `routing-instances { VRF-A { instance-type virtual-router; routing-options { ` + ro + ` } } }`
	}
	runQNHCases12308(t, []qnhCase12308{
		{"repeated route blocks",
			qnhHier12308(`routing-options { static { ` + route(qnhIfaceBlock12308) + " " + route(qnhPrefBlock12308) + ` } }`),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"repeated routing-options roots",
			qnhHier12308(`routing-options { static { ` + route(qnhIfaceBlock12308) + ` } } routing-options { static { ` + route(qnhPrefBlock12308) + ` } }`),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"rib inet.0 beside static",
			qnhHier12308(`routing-options { rib inet.0 { static { ` + route(qnhIfaceBlock12308) + ` } } static { ` + route(qnhPrefBlock12308) + ` } }`),
			qnhGlobal12308, "10.5.0.0/16", qnhMerged12308},
		{"routing instance, two blocks",
			qnhHier12308(vrf(`static { ` + route(qnhIfaceBlock12308+" "+qnhPrefBlock12308) + ` }`)),
			qnhVRF12308, "10.5.0.0/16", qnhMerged12308},
		{"routing instance rib, two blocks",
			qnhHier12308(vrf(`rib VRF-A.inet.0 { static { ` + route(qnhIfaceBlock12308+" "+qnhPrefBlock12308) + ` } }`)),
			qnhVRF12308, "10.5.0.0/16", qnhMerged12308},
		{"routing instance, repeated route blocks",
			qnhHier12308(vrf(`static { ` + route(qnhIfaceBlock12308) + " " + route(qnhPrefBlock12308) + ` }`)),
			qnhVRF12308, "10.5.0.0/16", qnhMerged12308},
		{"routing instance, flat set",
			qnhFlat12308(
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2",
				"set routing-instances VRF-A routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 interface ge-0/0/0.0",
				"set routing-instances VRF-A routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 preference 250"),
			qnhVRF12308, "10.5.0.0/16", qnhMerged12308},
	})
}

// OVER-REACH CONTROLS: the boundaries in compiler_static_qnh_merge_12308.go.
func TestQualifiedNextHopMergeKeepsDistinctNextHops12308(t *testing.T) {
	route := func(body string) string {
		return `routing-options { static { route 10.5.0.0/16 { ` + body + ` } } }`
	}
	plain := NextHopEntry{Address: "10.0.0.2"}
	backup := NextHopEntry{Address: "10.0.0.2", Preference: 250, HasPreference: true}
	twoRoutes := qnhHier12308(`routing-options { static { route 10.5.0.0/16 { ` + qnhIfaceBlock12308 +
		` } route 10.6.0.0/16 { ` + qnhPrefBlock12308 + ` } } }`)
	twoScopes := qnhHier12308(`routing-options { static { route 10.5.0.0/16 { ` + qnhIfaceBlock12308 + ` } } }
		routing-instances { VRF-A { instance-type virtual-router; routing-options { static {
			route 10.5.0.0/16 { ` + qnhPrefBlock12308 + ` } } } } }`)
	runQNHCases12308(t, []qnhCase12308{
		{"distinct gateways stay two backups",
			qnhHier12308(route(qnhIfaceBlock12308 + ` qualified-next-hop 10.0.0.3 { preference 250; }`)),
			qnhGlobal12308, "10.5.0.0/16",
			[]NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/0.0"}, {Address: "10.0.0.3", Preference: 250, HasPreference: true}}},
		// The plain next-hop is a primary ECMP member; folding the qualified
		// statement into it would move the primary to the backup's distance.
		{"a plain next-hop never absorbs a qualified one",
			qnhHier12308(route(`next-hop 10.0.0.2; ` + qnhPrefBlock12308)),
			qnhGlobal12308, "10.5.0.0/16", []NextHopEntry{plain, backup}},
		{"a plain next-hop never absorbs one from a later block",
			qnhHier12308(`routing-options { static { route 10.5.0.0/16 { next-hop 10.0.0.2; } route 10.5.0.0/16 { ` + qnhPrefBlock12308 + ` } } }`),
			qnhGlobal12308, "10.5.0.0/16", []NextHopEntry{plain, backup}},
		// Pre-#12308 behaviour, kept: a bare qualified next-hop identical to a
		// plain one is one forwarding member.
		{"a bare qualified twin of a plain next-hop collapses into it",
			qnhHier12308(route(`next-hop 10.0.0.2; qualified-next-hop 10.0.0.2;`)),
			qnhGlobal12308, "10.5.0.0/16", []NextHopEntry{plain}},
		// ...but only once nothing can change it. A later block still reaches
		// the qualified entry, never the plain one, in either order.
		{"the collapse waits for a later block (qualified first)",
			qnhHier12308(`routing-options { static { route 10.5.0.0/16 { qualified-next-hop 10.0.0.2; next-hop 10.0.0.2; } route 10.5.0.0/16 { ` + qnhPrefBlock12308 + ` } } }`),
			qnhGlobal12308, "10.5.0.0/16", []NextHopEntry{backup, plain}},
		{"the collapse waits for a later block (plain first)",
			qnhHier12308(`routing-options { static { route 10.5.0.0/16 { next-hop 10.0.0.2; qualified-next-hop 10.0.0.2; } route 10.5.0.0/16 { ` + qnhPrefBlock12308 + ` } } }`),
			qnhGlobal12308, "10.5.0.0/16", []NextHopEntry{plain, backup}},
		{"another route's statement for the gateway stays there (first route)",
			twoRoutes, qnhGlobal12308, "10.5.0.0/16",
			[]NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/0.0"}}},
		{"another route's statement for the gateway stays there (second route)",
			twoRoutes, qnhGlobal12308, "10.6.0.0/16", []NextHopEntry{backup}},
		{"a routing instance never shares the global entry (global)",
			twoScopes, qnhGlobal12308, "10.5.0.0/16",
			[]NextHopEntry{{Address: "10.0.0.2", Interface: "ge-0/0/0.0"}}},
		{"a routing instance never shares the global entry (instance)",
			twoScopes, qnhVRF12308, "10.5.0.0/16", []NextHopEntry{backup}},
	})
}

// The operator-visible consequence the issue is about. A primary next-hop plus
// one floating backup whose interface and preference are in separate blocks
// must install as two tiers: the primary alone, then the backup at 250. Before
// the fix the interface half had no preference of its own, inherited the
// route's 5 and joined the primary's ECMP tier, so traffic load-balanced onto
// the backup instead of failing over to it.
func TestMergedQualifiedNextHopKeepsItsFailoverTier12308(t *testing.T) {
	cfg, err := CompileConfig(hierTree(t, `routing-options { static { route 10.5.0.0/16 {
		next-hop 10.0.0.1; `+qnhIfaceBlock12308+` `+qnhPrefBlock12308+` } } }`))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	tiers := StaticRouteNextHopTiers(findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.5.0.0/16"))
	want := []StaticRouteNextHopTier{
		{Preference: 5, ManagementPrio: 5, NextHops: []NextHopEntry{{Address: "10.0.0.1"}}},
		{Preference: 250, ManagementPrio: 250, NextHops: qnhMerged12308},
	}
	if !reflect.DeepEqual(tiers, want) {
		t.Fatalf("failover tiers = %+v, want the primary alone at 5 and the backup at 250: %+v", tiers, want)
	}
}
