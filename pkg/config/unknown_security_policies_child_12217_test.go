package config

import (
	"strings"
	"testing"
)

const unknownSecurityPoliciesChildrenConfig12217 = `security {
 policies {
  globel { policy deny-bad { then { deny; } } }
  from-zon { x; }
 }
}`

func parseUnknownSecurityPoliciesChildren12217(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse config: %v", errs[0])
	}
	return tree
}

func TestUnknownSecurityPoliciesChildrenStrictAndLenient12217(t *testing.T) {
	tree := parseUnknownSecurityPoliciesChildren12217(t, unknownSecurityPoliciesChildrenConfig12217)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), `"globel"`) {
		t.Fatalf("strict CompileConfig error = %v, want rejection naming globel", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient CompileConfig: %v", err)
	}
	if got := cfg.Security.UnknownPoliciesChildren; len(got) != 2 || got[0] != "globel" || got[1] != "from-zon" {
		t.Fatalf("recorded unknown policy children = %v, want [globel from-zon]", got)
	}
	var warningCount, carrierCount int
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12217") {
			warningCount++
		}
	}
	for _, policy := range cfg.Security.GlobalPolicies {
		if policy != nil && policy.Name == "xpf-unknown-policies-child-poison" {
			carrierCount++
		}
	}
	if warningCount != 2 {
		t.Fatalf("#12217 warnings = %d, want 2: %v", warningCount, cfg.Warnings)
	}
	if carrierCount != 1 {
		t.Fatalf("unknown-policies poison carriers = %d, want exactly 1", carrierCount)
	}
}

func TestUnknownSecurityPoliciesApplyMacroIsNotRecorded12217(t *testing.T) {
	tree := parseUnknownSecurityPoliciesChildren12217(t,
		`security { policies { apply-macro M { k v; } } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected apply-macro control: %v", err)
	}
	if len(cfg.Security.UnknownPoliciesChildren) != 0 {
		t.Fatalf("apply-macro was recorded as an unknown policy child: %v", cfg.Security.UnknownPoliciesChildren)
	}
	for _, policy := range cfg.Security.GlobalPolicies {
		if policy != nil && policy.Name == "xpf-unknown-policies-child-poison" {
			t.Fatal("apply-macro control unexpectedly added an unknown-policies carrier")
		}
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12217") {
			t.Fatalf("apply-macro control emitted an unknown-policies warning: %q", warning)
		}
	}
}
