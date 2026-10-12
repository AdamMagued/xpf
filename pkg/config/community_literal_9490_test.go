package config

import (
	"strings"
	"testing"
)

// #9490: the non-regex community member check now mirrors FRR stable/10.6's
// community parser (bgpd/bgp_community.c community_gettoken, community_valid)
// instead of only its character set. Every accepted row is something that
// parser takes, and every refused row is something it rejects, which fails the
// whole frr-reload.
func TestNonRegexCommunityMemberIsAnFRRLiteral9490(t *testing.T) {
	for _, ok := range []string{
		"65000:1", "0:0", "65535:65535", "0065000:1",
		"no-export", "no-advertise", "local-AS", "no-peer", "blackhole",
		"graceful-shutdown", "accept-own", "accept-own-nexthop", "llgr-stale", "no-llgr",
		"route-filter-v4", "route-filter-translated-v6",
		"65000:1 65000:2", // FRR's standard list takes several communities per line
	} {
		if err := ValidCommunityMember(ok); err != nil {
			t.Errorf("%q is accepted by FRR's community parser but was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"xpfbogus9206", "v1", // the issue's rows
		"65536:1", "1:65536", ":1", "1:", "65000",
		"65000:1:2",           // a large community: a second `:` is community_token_unknown
		"target:65000:1",      // an extended community
		"no-export-subconfed", // the Junos spelling FRR does not have
		"internet", "LOCAL-AS",
		"65000:1 xpfbogus9206",
	} {
		if err := ValidCommunityMember(bad); err == nil {
			t.Errorf("%q committed, but FRR's community parser rejects it and fails the reload", bad)
		}
	}
	// Control: a regex member is still judged as a regex, not as a literal.
	for _, re := range []string{"65000:.*", "^65000:", "65000:1{2,3}"} {
		if err := ValidCommunityMember(re); err != nil {
			t.Errorf("regex member %q was refused: %v", re, err)
		}
	}
}

// The address-set member gate is strict on commit and a warning on the tolerant
// path. A persisted config with a dangling member must still boot (#1960).
func TestAddressSetMemberGateIsLenientOnLoad9490(t *testing.T) {
	cmds := []string{
		"set security address-book global address a1 10.0.0.0/24",
		"set security address-book global address-set s1 address a1",
		"set security address-book global address-set s1 address xpfbogus9206",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted an address-set member that names nothing")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "address-set members") && strings.Contains(w, "xpfbogus9206") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile did not warn about the dangling member; warnings: %v", cfg.Warnings)
	}
}

// #12214: the shared compiler expands every address-set, even unreferenced
// ones, and aborts apply when expansion exceeds depth five or revisits a set.
// Strict commit validation must reject those books first.
func TestAddressSetDepthAndCycleRejectedAtCommit12214(t *testing.T) {
	cases := []struct {
		name       string
		sets       []string
		wantSet    string
		wantDetail string
		wantAbsent string
	}{
		{
			name: "six-deep chain",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set s0 address a0",
				"set security address-book global address-set s1 address-set s0",
				"set security address-book global address-set s2 address-set s1",
				"set security address-book global address-set s3 address-set s2",
				"set security address-book global address-set s4 address-set s3",
				"set security address-book global address-set s5 address-set s4",
				"set security address-book global address-set s6 address-set s5",
			},
			wantSet:    "s6",
			wantDetail: "nesting too deep",
		},
		{
			name: "mutual cycle",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set cycA address a0",
				"set security address-book global address-set cycA address-set cycB",
				"set security address-book global address-set cycB address a0",
				"set security address-book global address-set cycB address-set cycA",
			},
			wantSet:    "cycA",
			wantDetail: "cycle detected",
		},
		{
			name: "five-deep boundary",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set s0 address a0",
				"set security address-book global address-set s1 address-set s0",
				"set security address-book global address-set s2 address-set s1",
				"set security address-book global address-set s3 address-set s2",
				"set security address-book global address-set s4 address-set s3",
				"set security address-book global address-set s5 address-set s4",
			},
		},
		{
			name: "shared-subset diamond",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set base address a0",
				"set security address-book global address-set left address-set base",
				"set security address-book global address-set right address-set base",
				"set security address-book global address-set top address-set left",
				"set security address-book global address-set top address-set right",
			},
		},
		{
			name: "boundary diamond",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set s0 address a0",
				"set security address-book global address-set s1 address-set s0",
				"set security address-book global address-set s2 address-set s1",
				"set security address-book global address-set s3 address-set s2",
				"set security address-book global address-set s4 address-set s3",
				"set security address-book global address-set d address-set s4",
				"set security address-book global address-set d address-set s3",
			},
		},
		{
			name: "address-set leaf names an address",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set S address-set a0",
			},
			wantSet:    "S",
			wantDetail: "names an address, not an address-set",
		},
		{
			name: "address-set leaf names a wildcard",
			sets: []string{
				"set security address-book global address a0 10.0.0.0/24",
				"set security address-book global address-set S address a0",
				"set security address-book global address-set S address-set any",
			},
			wantSet:    "S",
			wantDetail: "is a policy wildcard, not an address-set",
		},
		{
			name: "zone-local six-deep chain",
			sets: []string{
				"set security zones security-zone trust address-book address za0 10.1.0.0/24",
				"set security zones security-zone trust address-book address-set z0 address za0",
				"set security zones security-zone trust address-book address-set z1 address-set z0",
				"set security zones security-zone trust address-book address-set z2 address-set z1",
				"set security zones security-zone trust address-book address-set z3 address-set z2",
				"set security zones security-zone trust address-book address-set z4 address-set z3",
				"set security zones security-zone trust address-book address-set z5 address-set z4",
				"set security zones security-zone trust address-book address-set z6 address-set z5",
			},
			wantSet:    "z6 (security-zone trust)",
			wantDetail: "nesting too deep",
			wantAbsent: "zone-local/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, command := range tc.sets {
				path, err := ParseSetCommand(command)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", command, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", command, err)
				}
			}
			_, err := CompileConfig(tree)
			if tc.wantSet == "" {
				if err != nil {
					t.Fatalf("CompileConfig: valid %q rejected: %v", tc.name, err)
				}
				return
			}
			if err == nil ||
				!strings.Contains(err.Error(), tc.wantSet) ||
				!strings.Contains(err.Error(), tc.wantDetail) {
				t.Fatalf("CompileConfig error = %v, want rejection naming set %q for %q",
					err, tc.wantSet, tc.wantDetail)
			}
			if tc.wantAbsent != "" && strings.Contains(err.Error(), tc.wantAbsent) {
				t.Fatalf("CompileConfig error = %v, must not contain %q",
					err, tc.wantAbsent)
			}
		})
	}
}
