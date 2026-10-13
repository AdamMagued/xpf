package configstore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12308, on the operator path. Each sequence is ordinary `set` input that the
// candidate stores as a bare qualified-next-hop leaf beside a modifier
// container for the same gateway. CommitCheck must accept it and compile ONE
// next-hop carrying the modifier, both for interactive `set` and `load set`.
// Before the fix the bare half compiled as its own next-hop, and a commit gate
// on repeated nodes would have refused every later commit until the operator
// deleted and re-added the gateway.
func TestCommitCheckMergesQualifiedNextHopStatements12308(t *testing.T) {
	floating := []config.NextHopEntry{
		{Address: "10.0.0.1"},
		{Address: "192.168.1.1", Preference: 200, HasPreference: true},
	}
	linkLocal := []config.NextHopEntry{{Address: "fe80::1", Interface: "reth2.0"}}
	cases := []struct {
		name  string
		dest  string
		lines []string
		want  []config.NextHopEntry
	}{
		{"bare then preference", "0.0.0.0/0", []string{
			"set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1",
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1",
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 200",
		}, floating},
		{"preference then bare", "0.0.0.0/0", []string{
			"set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1",
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 200",
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1",
		}, floating},
		{"link-local bare then interface", "::/0", []string{
			"set routing-options static route ::/0 qualified-next-hop fe80::1",
			"set routing-options static route ::/0 qualified-next-hop fe80::1 interface reth2.0",
		}, linkLocal},
		{"link-local interface then bare", "::/0", []string{
			"set routing-options static route ::/0 qualified-next-hop fe80::1 interface reth2.0",
			"set routing-options static route ::/0 qualified-next-hop fe80::1",
		}, linkLocal},
	}
	for _, tc := range cases {
		for _, path := range []string{"set", "load set"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if path == "set" {
					for _, line := range tc.lines {
						if err := s.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
							t.Fatalf("SetFromInput(%q): %v", line, err)
						}
					}
				} else if _, err := s.LoadSet(strings.Join(tc.lines, "\n")); err != nil {
					t.Fatalf("LoadSet: %v", err)
				}
				cfg, err := s.CommitCheck()
				if err != nil {
					t.Fatalf("CommitCheck refused ordinary set input: %v", err)
				}
				var got []config.NextHopEntry
				for _, route := range cfg.RoutingOptions.StaticRoutes {
					if route.Destination == tc.dest {
						got = route.NextHops
					}
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("route %s next-hops = %+v, want %+v", tc.dest, got, tc.want)
				}
			})
		}
	}
}
