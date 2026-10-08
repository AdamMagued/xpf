package config

import (
	"fmt"
	"strings"
	"testing"
)

// #12243: policy wildcard tokens are valid policy matches, not address-book
// entries. An unreferenced set bypasses the #3149 policy-side resolver mirror,
// but reaches compileAddressBook at apply; every wildcard then misses AddrIDs
// and aborts the whole apply. The book-wide gate must reject it at commit.
//
// The definedness pass names a direct `address` wildcard itself (#12243). It
// leaves a nested `address-set` wildcard to #12214's expansion pass, which
// reports it as a policy wildcard rather than an address-set; those cells pin
// that hand-off so the skipped member cannot slip through either pass.
func TestUnreferencedAddressSetWildcardRejectedAtCommit12243(t *testing.T) {
	for _, leaf := range []string{"address", "address-set"} {
		for _, keyword := range []string{"any", "any-ipv4", "any-ipv6", "any4", "any6"} {
			t.Run(leaf+"/"+keyword, func(t *testing.T) {
				tree := buildAppMatchTree(t,
					"set security address-book global address web 10.0.0.1/32",
					"set security address-book global address-set S "+leaf+" "+keyword,
					"set security address-book global address-set S address web",
				)
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("strict compile accepted unreferenced set S with wildcard %s member %q",
						leaf, keyword)
				}
				want := wildcardMemberRejection12243("S", leaf, keyword)
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("CompileConfig error %q does not contain %q", err, want)
				}
			})
		}
	}
}

// A zone-local set is folded into the global book under a synthetic
// zone-local/<zone>/<name> key; the diagnostic must name the authored set.
func TestZoneLocalAddressSetWildcardNamesAuthoredSet12243(t *testing.T) {
	for _, leaf := range []string{"address", "address-set"} {
		t.Run(leaf, func(t *testing.T) {
			tree := buildAppMatchTree(t,
				"set security zones security-zone trust",
				"set security zones security-zone trust address-book address web 10.0.0.1/32",
				"set security zones security-zone trust address-book address-set S "+leaf+" any",
				"set security zones security-zone trust address-book address-set S address web",
			)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile accepted zone-local set S with wildcard %s member %q",
					leaf, "any")
			}
			want := wildcardMemberRejection12243("S (security-zone trust)", leaf, "any")
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("CompileConfig error %q does not contain %q", err, want)
			}
			if strings.Contains(err.Error(), "zone-local/") {
				t.Fatalf("CompileConfig error %q leaks the synthetic zone-local key", err)
			}
		})
	}
}

// wildcardMemberRejection12243 is the diagnostic expected when set carries the
// wildcard keyword on leaf: #12243's definedness error for a direct `address`
// member, #12214's expansion error for a nested `address-set` member.
func wildcardMemberRejection12243(set, leaf, keyword string) string {
	if leaf == "address-set" {
		return fmt.Sprintf("address-set %s cannot be expanded: address-set %q is a "+
			"policy wildcard, not an address-set", set, keyword)
	}
	return fmt.Sprintf("address-set %s %s %q is a policy match-all wildcard", set, leaf, keyword)
}

func TestUnreferencedAddressSetWithNamedMembersStillCommits12243(t *testing.T) {
	tree := buildAppMatchTree(t,
		"set security address-book global address web 10.0.0.1/32",
		"set security address-book global address-set S address web",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile rejected an unreferenced set with a defined member: %v", err)
	}
}
