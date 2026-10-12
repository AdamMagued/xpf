package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileLenient12249(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	return cfg
}

func zonePairLines12249(from, to, name string) []string {
	base := "set security policies from-zone " + from + " to-zone " + to + " policy " + name + " "
	return []string{
		base + "match source-address any",
		base + "match destination-address any",
		base + "match application any",
		base + "then permit",
	}
}

func policyNamed12249(rules []PolicyRuleSnapshot, name string) *PolicyRuleSnapshot {
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i]
		}
	}
	return nil
}

func hasSentinel12249(rule *PolicyRuleSnapshot) bool {
	if rule == nil {
		return false
	}
	for _, term := range rule.ApplicationTerms {
		if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
			return true
		}
	}
	return false
}

// A pre-#3055 persisted zone definition named `any` is kept by tolerant
// compilation but omitted from the dataplane zone set. Zone-pair rules naming
// it must be poisoned so they cannot reach the helper's wildcard indexes
// (#12249).
func TestDefinedAnyZonePairPoliciesArePoisoned12249(t *testing.T) {
	lines := []string{
		"set security zones security-zone any",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy deny-all",
	}
	lines = append(lines,
		zonePairLines12249("any", "untrust", "from-any")...)
	lines = append(lines,
		zonePairLines12249("trust", "any", "to-any")...)
	lines = append(lines,
		zonePairLines12249("any", "any", "both-any")...)
	lines = append(lines,
		zonePairLines12249("trust", "untrust", "healthy")...)

	cfg := compileLenient12249(t, lines)
	if _, ok := cfg.Security.Zones[config.ReservedWildcardZoneName]; !ok {
		t.Fatal("fixture no longer retains the legacy `any` definition on tolerant compile")
	}
	foundFromAny := false
	for _, zpp := range cfg.Security.Policies {
		if zpp != nil && zpp.FromZone == config.ReservedWildcardZoneName && zpp.ToZone == "untrust" {
			foundFromAny = true
		}
	}
	if !foundFromAny {
		t.Fatal("fixture no longer compiles the pre-#3055 from-zone any policy")
	}

	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build policy snapshots: %v", err)
	}
	for _, tc := range []struct{ name, side string }{
		{"from-any", "from-zone"},
		{"to-any", "to-zone"},
		{"both-any", "from-zone and to-zone"},
	} {
		rule := policyNamed12249(rules, tc.name)
		if rule == nil || !hasSentinel12249(rule) || rule.zonePairDefinedAnySide != tc.side {
			t.Errorf("defined-any policy %q was not poisoned for %s: %+v", tc.name, tc.side, rule)
			continue
		}
		wire, err := json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(wire), `"`+unsupportedApplicationSentinel+`"`) {
			t.Errorf("defined-any policy %q does not carry poison on the helper wire: %s", tc.name, wire)
		}
	}
	if healthy := policyNamed12249(rules, "healthy"); healthy == nil || hasSentinel12249(healthy) {
		t.Fatalf("unrelated rule was poisoned: %+v", healthy)
	}

	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 3 {
		t.Fatalf("want one whole-snapshot rejection per poisoned rule, got %v", reasons)
	}
	for _, name := range []string{"from-any", "to-any", "both-any"} {
		found := false
		for _, reason := range reasons {
			if strings.Contains(reason, "/"+name+" ") &&
				strings.Contains(reason, "REJECTS THE WHOLE POLICY SNAPSHOT") &&
				!strings.Contains(reason, "cannot represent") {
				found = true
			}
		}
		if !found {
			t.Errorf("no dedicated fail-closed reason for %q in %v", name, reasons)
		}
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("tolerant snapshot build: %v", err)
	}
	for _, zone := range snap.Zones {
		if zone.Name == config.ReservedWildcardZoneName {
			t.Fatal("reserved `any` definition was unexpectedly published")
		}
	}
	for _, name := range []string{"from-any", "to-any", "both-any"} {
		if rule := policyNamed12249(snap.Policies, name); rule == nil || !hasSentinel12249(rule) {
			t.Fatalf("tolerant snapshot would enforce %q as a wildcard instead of poisoning it: %+v", name, rule)
		}
	}
	if healthy := policyNamed12249(snap.Policies, "healthy"); healthy == nil || hasSentinel12249(healthy) {
		t.Fatalf("tolerant snapshot lost or poisoned the unrelated healthy policy: %+v", healthy)
	}
}

// With no zone definition named `any`, wildcard zone-pair policies remain
// valid and must keep their existing behavior (#12249 acceptance control).
func TestUndefinedAnyZoneWildcardPolicyStaysIntact12249(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy deny-all",
	}
	lines = append(lines, zonePairLines12249("any", "untrust", "wildcard")...)
	cfg := compileLenient12249(t, lines)
	if _, ok := cfg.Security.Zones[config.ReservedWildcardZoneName]; ok {
		t.Fatal("control fixture unexpectedly defines zone `any`")
	}

	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build policy snapshots: %v", err)
	}
	if rule := policyNamed12249(rules, "wildcard"); rule == nil || hasSentinel12249(rule) {
		t.Fatalf("legitimate from-zone any wildcard policy was dropped or poisoned without a defined any zone: %+v", rule)
	}

	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("legitimate wildcard config was reported refused: %v", reasons)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	if rule := policyNamed12249(snap.Policies, "wildcard"); rule == nil || hasSentinel12249(rule) {
		t.Fatalf("snapshot dropped or poisoned a legitimate wildcard policy without a defined any zone: %+v", rule)
	}
}

// TestAnyZoneOutsideThisNodeLeavesWildcardIntact12247 scopes the defined-`any`
// poison to the compiled node's own zones. An `any` defined only in a group
// nothing applies, or only in the peer node's group, installs nothing on this
// node, so the legitimate wildcard rule stays unpoisoned in the lowered and the
// published policies with no rejection reason — the published snapshot,
// policy lowering and the rejection mirror must agree. The node0 row is the
// control: there `any` is defined locally and the rule must be poisoned.
func TestAnyZoneOutsideThisNodeLeavesWildcardIntact12247(t *testing.T) {
	hermeticSnapshot12247(t)
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy deny-all",
	}
	base = append(base, zonePairLines12249("any", "untrust", "wildcard")...)
	nodeScopedAny := []string{
		"set groups node0 security zones security-zone any",
		"set groups node1 system host-name n1",
		`set apply-groups "${node}"`,
	}
	for _, tc := range []struct {
		name       string
		extra      []string
		nodeID     int // negative: generic compile
		wantPoison bool
	}{
		{name: "group nothing applies", extra: []string{"set groups unused security zones security-zone any"}, nodeID: -1},
		{name: "peer node0 group compiled for node1", extra: nodeScopedAny, nodeID: 1},
		{name: "own node0 group compiled for node0", extra: nodeScopedAny, nodeID: 0, wantPoison: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append(append([]string{}, base...), tc.extra...)
			cfg := lenientCompile12247(t, treeFromSet6722(t, lines), tc.nodeID)
			if _, localAny := cfg.Security.Zones[config.ReservedWildcardZoneName]; localAny != tc.wantPoison {
				t.Fatalf("fixture: compiled zones define `any` = %v, want %v", localAny, tc.wantPoison)
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build policy snapshots: %v", err)
			}
			lowered := policyNamed12249(rules, "wildcard")
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
			if err != nil {
				t.Fatalf("snapshot build: %v", err)
			}
			published := policyNamed12249(snap.Policies, "wildcard")
			if lowered == nil || published == nil {
				t.Fatalf("wildcard rule dropped: lowered=%+v published=%+v", lowered, published)
			}
			if hasSentinel12249(lowered) != tc.wantPoison || hasSentinel12249(published) != tc.wantPoison {
				t.Fatalf("wildcard poisoned: lowered=%v published=%v, want %v",
					hasSentinel12249(lowered), hasSentinel12249(published), tc.wantPoison)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if (len(reasons) != 0) != tc.wantPoison {
				t.Fatalf("rejection reasons = %v, want refused=%v", reasons, tc.wantPoison)
			}
		})
	}
}
