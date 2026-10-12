package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func parseTree12247(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// lenientCompile12247 tolerant-compiles tree for nodeID, or generically when
// nodeID is negative. Compiles clone the tree, so one tree serves every call.
func lenientCompile12247(t *testing.T, tree *config.ConfigTree, nodeID int) *config.Config {
	t.Helper()
	var cfg *config.Config
	var err error
	if nodeID < 0 {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfigForNodeLenient(tree, nodeID)
	}
	if err != nil {
		t.Fatalf("tolerant compile (node %d): %v", nodeID, err)
	}
	return cfg
}

// hermeticSnapshot12247 stubs the netlink ip-rule and link reads buildSnapshot
// performs, so a snapshot depends only on the compiled config.
func hermeticSnapshot12247(t *testing.T) {
	t.Helper()
	stubRuleListHermetic(t)
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 0, 0, "", nil
	}
}

func TestNodeScopedZoneQuarantineUsesThreeViewUnion12247(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree, errs := config.NewParser(`groups {
  node0 { security { zones { security-zone z174; } } }
  node1 { security { zones { security-zone z214; } } }
}
apply-groups "${node}";`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse node-scoped zones: %v", errs)
	}

	for _, tc := range []struct {
		name           string
		nodeID         int
		wantZone       string
		wantQuarantine bool
	}{
		{name: "node0", nodeID: 0, wantZone: "z174"},
		{name: "node1", nodeID: 1, wantZone: "z214", wantQuarantine: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfigForNodeLenient(tree, tc.nodeID)
			if err != nil {
				t.Fatalf("tolerant node%d compile: %v", tc.nodeID, err)
			}
			if len(cfg.ZoneQuarantineNames) != 2 ||
				cfg.ZoneQuarantineNames[0] != "z174" ||
				cfg.ZoneQuarantineNames[1] != "z214" {
				t.Fatalf("node%d quarantine-name union = %v, want [z174 z214]",
					tc.nodeID, cfg.ZoneQuarantineNames)
			}
			excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
			if _, ok := excluded["z214"]; !ok {
				t.Fatalf("node%d config exclusions = %v, want peer-union loser z214",
					tc.nodeID, excluded)
			}
			if _, ok := excluded["z174"]; ok {
				t.Fatalf("node%d config exclusions = %v, want survivor z174 retained",
					tc.nodeID, excluded)
			}
			if got := config.ZoneQuarantineExcludedReason("z214", cfg); got == "" {
				t.Fatalf("node%d did not report peer-union loser z214 as quarantined", tc.nodeID)
			}
			if len(cfg.Security.Zones) != 1 || cfg.Security.Zones[tc.wantZone] == nil {
				t.Fatalf("node%d zones = %v, want only %q", tc.nodeID, cfg.Security.Zones, tc.wantZone)
			}

			snap := &ConfigSnapshot{Config: cfg, Zones: buildZoneSnapshots(cfg)}
			collisions := quarantineCollidingZones(snap)
			if tc.wantQuarantine {
				if len(collisions) != 1 || collisions[0].Quarantined != "z214" || collisions[0].Survivor != "z174" {
					t.Fatalf("node%d collision records = %+v, want z214 quarantined in favor of z174", tc.nodeID, collisions)
				}
				if len(snap.Zones) != 0 {
					t.Fatalf("node%d published zones = %+v, want z214 quarantined", tc.nodeID, snap.Zones)
				}
				return
			}
			if len(collisions) != 0 || len(snap.Zones) != 1 || snap.Zones[0].Name != "z174" {
				t.Fatalf("node%d published zones = %+v, collisions = %+v; want survivor z174", tc.nodeID, snap.Zones, collisions)
			}
		})
	}
}

// TestGroupOnlyZoneNameDoesNotQuarantineLiveZone12247 pins the runtime name
// set to the main/node0/node1 views. Each row pairs a live zone with a
// colliding name only a groups block declares — a group nothing applies, a
// `<*>` wildcard template, a group applied under another stanza. No node
// installs that name, so it must not quarantine the live zone on any compile
// path: the live zone keeps its interface and stays published.
//
// The strict gate still counts View 1's raw groups scan and keeps rejecting
// these configs; that pre-existing false positive is unchanged here.
func TestGroupOnlyZoneNameDoesNotQuarantineLiveZone12247(t *testing.T) {
	const wildcardCollider = "z65162"
	if config.StableZoneID("<*>") != config.StableZoneID(wildcardCollider) {
		t.Fatalf("test premise broken: %q no longer folds to the id of `<*>`", wildcardCollider)
	}
	hermeticSnapshot12247(t)
	liveZone := func(name string) string {
		return "security { zones { security-zone " + name + ` { interfaces { ge-0/0/0.0; } } } }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`
	}
	for _, tc := range []struct {
		name    string
		text    string
		live    string
		phantom string
	}{
		{
			name:    "group nothing applies",
			text:    "groups { unused { security { zones { security-zone z174; } } } }\n" + liveZone("z214"),
			live:    "z214",
			phantom: "z174",
		},
		{
			name: "wildcard template",
			text: "groups { G { security { zones { security-zone <*> { tcp-rst; } } } } }\napply-groups G;\n" +
				liveZone(wildcardCollider),
			live:    wildcardCollider,
			phantom: "<*>",
		},
		{
			name: "group applied under another stanza",
			text: "groups { g1 { security { zones { security-zone z174; } } } }\nsystem { apply-groups g1; host-name p; }\n" +
				liveZone("z214"),
			live:    "z214",
			phantom: "z174",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree12247(t, tc.text)
			if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "zone id collision") {
				t.Fatalf("strict compile error = %v, want the unchanged View-1 zone id collision", err)
			}
			for _, nodeID := range []int{-1, 0, 1} {
				cfg := lenientCompile12247(t, tree, nodeID)
				if slices.Contains(cfg.ZoneQuarantineNames, tc.phantom) {
					t.Fatalf("node %d runtime names %v include group-only %q", nodeID, cfg.ZoneQuarantineNames, tc.phantom)
				}
				if !slices.Contains(cfg.ZoneQuarantineNames, tc.live) {
					t.Fatalf("node %d runtime names %v omit live %q", nodeID, cfg.ZoneQuarantineNames, tc.live)
				}
				if reason := config.ZoneQuarantineExcludedReason(tc.live, cfg); reason != "" {
					t.Fatalf("node %d quarantined live %q: %s", nodeID, tc.live, reason)
				}
				if got := buildInterfaceZoneMap(cfg)["ge-0/0/0.0"]; got != tc.live {
					t.Fatalf("node %d runtime zone of ge-0/0/0.0 = %q, want %q", nodeID, got, tc.live)
				}
				snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
				if err != nil {
					t.Fatalf("node %d snapshot build: %v", nodeID, err)
				}
				if len(snap.zoneIDCollisions) != 0 {
					t.Fatalf("node %d collision records = %+v, want none", nodeID, snap.zoneIDCollisions)
				}
				if !slices.ContainsFunc(snap.Zones, func(z ZoneSnapshot) bool { return z.Name == tc.live }) {
					t.Fatalf("node %d published zones %+v omit live %q", nodeID, snap.Zones, tc.live)
				}
			}
		})
	}
}

// TestGenericOnlyZoneNameDoesNotQuarantineOnClusterNodes12247 pins why the
// runtime name set counts the node0/node1 expansions but not the generic
// compile's: a group literally named "${node}" is applied only by the generic
// compile (no node variable), so its zone exists on no cluster node. The node
// compiles must not quarantine the live zone for it, while the generic compile,
// which installs both names, still quarantines its own collision.
func TestGenericOnlyZoneNameDoesNotQuarantineOnClusterNodes12247(t *testing.T) {
	tree := parseTree12247(t, `groups {
  "${node}" { security { zones { security-zone z174; } } }
  node0 { system { host-name n0; } }
  node1 { system { host-name n1; } }
}
apply-groups "${node}";
security { zones { security-zone z214; } }`)
	generic := lenientCompile12247(t, tree, -1)
	if generic.Security.Zones["z174"] == nil || config.ZoneQuarantineExcludedReason("z214", generic) == "" {
		t.Fatalf("generic compile: zones %v, want z174 installed and z214 quarantined by it", generic.Security.Zones)
	}
	for _, nodeID := range []int{0, 1} {
		cfg := lenientCompile12247(t, tree, nodeID)
		if cfg.Security.Zones["z174"] != nil || cfg.Security.Zones["z214"] == nil {
			t.Fatalf("node%d precondition: zones %v, want z214 without z174", nodeID, cfg.Security.Zones)
		}
		if slices.Contains(cfg.ZoneQuarantineNames, "z174") {
			t.Fatalf("node%d runtime names %v include generic-only z174", nodeID, cfg.ZoneQuarantineNames)
		}
		if reason := config.ZoneQuarantineExcludedReason("z214", cfg); reason != "" {
			t.Fatalf("node%d quarantined live z214 for a zone no cluster node installs: %s", nodeID, reason)
		}
	}
}
