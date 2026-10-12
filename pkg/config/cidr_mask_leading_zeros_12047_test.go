package config

import (
	"strings"
	"testing"
)

// TestCIDRMaskHelperUnsupportedPaddingRejected12047 pins the book-row and
// inline-literal strict gates to spellings the userspace helper cannot parse.
func TestCIDRMaskHelperUnsupportedPaddingRejected12047(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-008", "10.0.0.0/008"},
		{"ipv4-024", "10.0.0.0/024"},
		{"ipv4-000", "10.0.0.0/000"},
		{"ipv6-0032", "2001:db8::/0032"},
		{"ipv6-0064", "2001:db8::/0064"},
	} {
		t.Run("book/"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security address-book global address padded " + tc.prefix,
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero mask digits") {
				t.Fatalf("strict commit did not diagnose helper-refused book mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about helper-refused mask %q; warnings=%v", tc.prefix, cfg.Warnings)
			}
		})

		t.Run("policy-inline/"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p1 match source-address " + tc.prefix,
				"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p1 match application any",
				"set security policies from-zone trust to-zone untrust policy p1 then permit",
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero") {
				t.Fatalf("strict commit did not diagnose helper-refused inline mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about helper-refused mask %q; warnings=%v", tc.prefix, cfg.Warnings)
			}
		})
	}
	for _, prefix := range []string{"10.0.0.0/008", "2001:db8::/0032"} {
		t.Run("zone-book/"+prefix, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust address-book address padded " + prefix,
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero mask digits") {
				t.Fatalf("strict commit did not diagnose helper-refused zone-local mask %q: %v", prefix, err)
			}
		})
	}
}

// TestCIDRMaskHelperAcceptedPaddingAllowed12178 covers masks ipnet accepts
// despite their leading zero: these must remain strict-commit compatible and
// must not trigger a tolerant-load warning.
func TestCIDRMaskHelperAcceptedPaddingAllowed12178(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-08", "10.0.0.0/08"},
		{"ipv4-00", "10.0.0.0/00"},
		{"ipv6-032", "2001:db8::/032"},
		{"ipv6-064", "2001:db8::/064"},
		{"ipv6-024", "2001:db8::/024"},
		{"ipv6-008", "2001:db8::/008"},
	} {
		for _, kind := range []string{"book", "policy-inline"} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				var lines []string
				if kind == "book" {
					lines = []string{
						"set security address-book global address padded " + tc.prefix,
					}
				} else {
					lines = []string{
						"set security zones security-zone trust",
						"set security zones security-zone untrust",
						"set security policies from-zone trust to-zone untrust policy p1 match source-address " + tc.prefix,
						"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
						"set security policies from-zone trust to-zone untrust policy p1 match application any",
						"set security policies from-zone trust to-zone untrust policy p1 then permit",
					}
				}
				tree := buildTree(t, lines)
				if CIDRMaskHelperRefusesPadding(tc.prefix) {
					t.Fatalf("helper-accepted mask %q was classified as helper-refused", tc.prefix)
				}
				if _, err := CompileConfig(tree); err != nil {
					t.Fatalf("strict commit rejected helper-accepted mask %q: %v", tc.prefix, err)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("tolerant load rejected helper-accepted mask %q: %v", tc.prefix, err)
				}
				if warningContains12047(cfg.Warnings) {
					t.Fatalf("tolerant load warned about helper-accepted mask %q: %v", tc.prefix, cfg.Warnings)
				}
			})
		}
	}
}

// TestCIDRMaskHelperRefusesPaddingFamilyAndValidity12178 pins the helper's
// family-specific width rule (including mapped IPv6 text) and keeps invalid
// Go CIDRs out of the helper-refusal diagnostic.
func TestCIDRMaskHelperRefusesPaddingFamilyAndValidity12178(t *testing.T) {
	for _, tc := range []struct {
		prefix  string
		refused bool
	}{
		{"10.0.0.0/08", false},
		{"10.0.0.0/008", true},
		{"2001:db8::/064", false},
		{"2001:db8::/0064", true},
		{"::ffff:10.0.0.0/096", false},
		{"::ffff:10.0.0.0/0096", true},
		{"10.0.0.0/0000", true},
		{"2001:db8::/0129", false},
	} {
		if got := CIDRMaskHelperRefusesPadding(tc.prefix); got != tc.refused {
			t.Errorf("CIDRMaskHelperRefusesPadding(%q) = %v, want %v",
				tc.prefix, got, tc.refused)
		}
	}
	err := policyMatchAddressError("", "p1", "source-address", "2001:db8::/0129")
	if !strings.Contains(err.Error(), "valid CIDR/IP address") ||
		strings.Contains(err.Error(), "userspace helper cannot parse") {
		t.Fatalf("invalid CIDR must keep the general address diagnostic, got %v", err)
	}
}

// TestCIDRMaskJunosHostProjectionNormalizesSupportedPadding12178 guards the
// direct kernel-enforcement path: strict-accepted padded masks must not make
// the entire ingress-zone junos-host program disappear.
func TestCIDRMaskJunosHostProjectionNormalizesSupportedPadding12178(t *testing.T) {
	lines := append([]string{}, junosHostBaseZones...)
	lines = append(lines,
		"set security address-book global address padded-v4 10.0.0.0/08",
		"set security address-book global address padded-v6 2001:db8::/032",
	)
	policies := []struct {
		name, source string
	}{
		{"block-canon", "bad-host"},
		{"block-v4-inline", "10.0.0.0/08"},
		{"block-v6-inline", "2001:db8::/064"},
		{"block-v4-book", "padded-v4"},
		{"block-v6-book", "padded-v6"},
	}
	for _, policy := range policies {
		prefix := "set security policies from-zone untrust to-zone junos-host policy " + policy.name
		lines = append(lines,
			prefix+" match source-address "+policy.source,
			prefix+" match destination-address any",
			prefix+" match application any",
			prefix+" then deny")
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("strict commit rejected helper-supported masks: %v", err)
	}
	projection := BuildJunosHostDenyProjection(cfg)
	if len(projection.Programs) != 1 {
		t.Fatalf("projection programs = %d, want 1: %+v", len(projection.Programs), projection.Programs)
	}
	program := projection.Programs[0]
	if !program.Representable || len(program.RulesV4) == 0 || len(program.RulesV6) == 0 {
		t.Fatalf("supported padded masks blacked out the ingress-zone program: %+v", program)
	}
	for _, policy := range policies {
		key := JunosHostZonePairPolicyKey("untrust", policy.name)
		if !projection.RenderedPolicyKeys[key] {
			t.Errorf("policy %q was not rendered: %+v", policy.name, projection.RenderedPolicyKeys)
		}
	}
	got := map[string]bool{}
	for _, rule := range append(program.RulesV4, program.RulesV6...) {
		for _, prefix := range rule.Src {
			got[prefix] = true
		}
	}
	for _, want := range []string{
		"10.0.0.5/32",
		"10.0.0.0/8",
		"2001:db8::/64",
		"2001:db8::/32",
	} {
		if !got[want] {
			t.Errorf("projected source prefixes omit normalized %q: %v", want, got)
		}
	}
}

func TestCIDRMaskCanonicalPrefixesRemainAccepted12047(t *testing.T) {
	for _, prefix := range []string{
		"10.0.0.0/0", "10.0.0.0/8", "10.0.0.0/32",
		"2001:db8::/0", "2001:db8::/32", "2001:db8::/128",
	} {
		t.Run(prefix, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security address-book global address canonical " + prefix,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected canonical mask %q: %v", prefix, err)
			}
		})
	}
}

func warningContains12047(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "redundant leading-zero") {
			return true
		}
	}
	return false
}
