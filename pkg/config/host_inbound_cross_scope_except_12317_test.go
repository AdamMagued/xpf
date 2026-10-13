package config

import (
	"reflect"
	"strings"
	"testing"
)

const crossScopeExceptUnit12317 = "ge-0/0/0.0"

const (
	crossScopePhysical12317 = "set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic "
	crossScopeUnit12317     = "set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic "
)

func compileCrossScopeExcept12317(t *testing.T, lenient bool, directives ...string) *Config {
	t.Helper()
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	lines = append(lines, directives...)
	tree := flat10292(t, lines...)
	var cfg *Config
	var err error
	if lenient {
		cfg, err = CompileConfigLenient(tree)
	} else {
		cfg, err = CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile (lenient=%t): %v", lenient, err)
	}
	return cfg
}

func assertExceptSSHPorts12317(t *testing.T, services []string, wantSSH, wantNetconf, wantHTTP bool) {
	t.Helper()
	for _, family := range []string{"ip", "ip6"} {
		tuples := hostInboundAdmissionTupleSet12053(services, family)
		_, hasSSH := tuples[hostInboundTupleKey12053{proto: 6, port: 22, portSet: true}]
		_, hasNetconf := tuples[hostInboundTupleKey12053{proto: 6, port: 830, portSet: true}]
		_, hasHTTP := tuples[hostInboundTupleKey12053{proto: 6, port: 80, portSet: true}]
		if hasSSH != wantSSH || hasNetconf != wantNetconf || hasHTTP != wantHTTP {
			t.Errorf("services %v tuples on %s include ssh:22=%t netconf:830=%t http:80=%t; want %t,%t,%t",
				services, family, hasSSH, hasNetconf, hasHTTP, wantSSH, wantNetconf, wantHTTP)
		}
	}
}

func TestHostInboundCrossScopeExceptAliasUnion12317(t *testing.T) {
	cases := []struct {
		name       string
		directives []string
	}{
		{
			name: "physical-alias-unit-exclusion",
			directives: []string{
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services netconf-ssh",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except",
			},
		},
		{
			name: "physical-exclusion-unit-alias",
			directives: []string{
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh except",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services netconf-ssh",
			},
		},
	}
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
					effective := ResolveInterfaceHostInbound(cfg)[crossScopeExceptUnit12317]
					if effective == nil {
						t.Fatalf("no effective host-inbound override for %s", crossScopeExceptUnit12317)
					}
					assertExceptSSHPorts12317(t, effective.SystemServices, false, true, true)
					gate := buildHostInboundOverrideMapLocal(cfg)[crossScopeExceptUnit12317]
					if gate == nil {
						t.Fatalf("duplicate-address gate has no override for %s", crossScopeExceptUnit12317)
					}
					assertExceptSSHPorts12317(t, gate.SystemServices, false, true, true)
				})
			}
		})
	}
}

func TestHostInboundZoneAndInterfaceExceptRemainSeparate12317(t *testing.T) {
	cases := []struct {
		name              string
		directives        []string
		wantSSH, wantHTTP bool
	}{
		{
			name: "zone-exclusion-does-not-filter-replacing-interface-alias",
			directives: []string{
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services netconf-ssh",
			},
			wantSSH:  true,
			wantHTTP: false,
		},
		{
			name: "interface-exclusion-filters-alias-and-replaces-zone",
			directives: []string{
				"set security zones security-zone trust host-inbound-traffic system-services netconf-ssh",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except",
			},
			wantSSH:  false,
			wantHTTP: true,
		},
	}
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
					zone := cfg.Security.Zones["trust"]
					services, _, overridden := zone.InterfaceHostInboundEffective(crossScopeExceptUnit12317)
					if !overridden {
						t.Fatal("unit must have a replacing interface-level stanza")
					}
					assertExceptSSHPorts12317(t, services, tc.wantSSH, true, tc.wantHTTP)
				})
			}
		})
	}
}

func TestHostInboundCrossScopeExceptLegacyOverride12317(t *testing.T) {
	zone := &ZoneConfig{InterfaceHostInbound: map[string]*HostInboundTraffic{
		"ge-0/0/0": {
			SystemServices: []string{"netconf-ssh"},
		},
		"ge-0/0/0.0": {
			SystemServices:       hostInboundFilterExcept(HostInboundAllExpansionServices(), []string{"ssh"}, false),
			systemServicesExcept: []string{"ssh"},
		},
	}}
	services, _, declared := zone.InterfaceHostInboundOverride(crossScopeExceptUnit12317)
	if !declared {
		t.Fatal("hand-built zone lost its physical/unit override")
	}
	assertExceptSSHPorts12317(t, services, false, true, true)
}

func TestHostInboundSingleStanzaExceptControl12317(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			cfg := compileCrossScopeExcept12317(t, lenient,
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except",
			)
			services := cfg.Security.Zones["trust"].HostInboundTraffic.SystemServices
			assertExceptSSHPorts12317(t, services, false, true, true)
		})
	}
}

// forEachCompileMode12317 runs fn under the strict commit and the tolerant
// load compile paths.
func forEachCompileMode12317(t *testing.T, fn func(t *testing.T, lenient bool)) {
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) { fn(t, lenient) })
	}
}

// crossScopeOverrides12317 returns the unit's effective override from the
// runtime resolver and from the duplicate-address commit gate.
func crossScopeOverrides12317(t *testing.T, cfg *Config) []*HostInboundTraffic {
	t.Helper()
	resolved := ResolveInterfaceHostInbound(cfg)[crossScopeExceptUnit12317]
	gate := buildHostInboundOverrideMapLocal(cfg)[crossScopeExceptUnit12317]
	if resolved == nil || gate == nil {
		t.Fatalf("%s override missing: resolver=%v gate=%v", crossScopeExceptUnit12317, resolved, gate)
	}
	return []*HostInboundTraffic{resolved, gate}
}

// assertExceptOSPF12317 checks IPv4 OSPF (IP protocol 89) admission, with BGP
// (TCP/179) as the non-vacuity control every case keeps.
func assertExceptOSPF12317(t *testing.T, protocols []string, wantOSPF bool) {
	t.Helper()
	var ospf, bgp bool
	for _, token := range protocols {
		for _, m := range HostInboundProtocolMatch(token, "ip") {
			if m.Proto == 89 && len(m.Ports) == 0 {
				ospf = true
			}
			for _, ports := range m.Ports {
				if m.Proto == HostInboundProtoTCP && ports.Lo <= 179 && 179 <= ports.Hi {
					bgp = true
				}
			}
		}
	}
	if ospf != wantOSPF || !bgp {
		t.Errorf("protocols %v on ip admit ospf:89=%t bgp:179=%t; want %t,true", protocols, ospf, bgp, wantOSPF)
	}
}

// TestHostInboundCrossScopeProtocolExcept12317 is the protocols half of the
// alias case: a literal `protocols all` in one interface scope must not
// re-admit the OSPF the other scope excludes. Protocol exclusions subtract by
// family-scoped tuple (#12318); this pins that the subtraction survives the
// union in both scope orders, on the resolver and on the commit-time gate.
func TestHostInboundCrossScopeProtocolExcept12317(t *testing.T) {
	cases := []struct {
		name       string
		directives []string
	}{
		{
			name: "physical-all-unit-exclusion",
			directives: []string{
				crossScopePhysical12317 + "protocols all",
				crossScopeUnit12317 + "protocols all",
				crossScopeUnit12317 + "protocols ospf except",
			},
		},
		{
			name: "physical-exclusion-unit-all",
			directives: []string{
				crossScopePhysical12317 + "protocols all",
				crossScopePhysical12317 + "protocols ospf except",
				crossScopeUnit12317 + "protocols all",
			},
		},
	}
	forEachCompileMode12317(t, func(t *testing.T, lenient bool) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
				for _, hib := range crossScopeOverrides12317(t, cfg) {
					assertExceptOSPF12317(t, hib.Protocols, false)
				}
			})
		}
	})
}

// TestHostInboundCrossScopeExceptRemovesExplicitTokens12317 pins the rule the
// alias fix implies: an exclusion in either interface scope also removes a
// service or protocol the OTHER scope names explicitly. The provenance-free
// union before #12317 admitted TCP/22 and OSPF in both orders; the
// #12317 advisory names this narrowing at commit.
func TestHostInboundCrossScopeExceptRemovesExplicitTokens12317(t *testing.T) {
	exclusion := func(prefix string) []string {
		return []string{
			prefix + "system-services all",
			prefix + "system-services ssh except",
			prefix + "protocols all",
			prefix + "protocols ospf except",
		}
	}
	explicit := func(prefix string) []string {
		return []string{prefix + "system-services ssh", prefix + "protocols ospf"}
	}
	cases := []struct {
		name       string
		directives []string
	}{
		{
			name:       "physical-exclusion-unit-explicit",
			directives: append(exclusion(crossScopePhysical12317), explicit(crossScopeUnit12317)...),
		},
		{
			name:       "physical-explicit-unit-exclusion",
			directives: append(explicit(crossScopePhysical12317), exclusion(crossScopeUnit12317)...),
		},
	}
	forEachCompileMode12317(t, func(t *testing.T, lenient bool) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
				for _, hib := range crossScopeOverrides12317(t, cfg) {
					assertExceptSSHPorts12317(t, hib.SystemServices, false, true, true)
					assertExceptOSPF12317(t, hib.Protocols, false)
				}
			})
		}
	})
}

// TestHostInboundCrossScopeUnionStaysDeduplicated12317: reapplying the
// exclusions re-expands a literal `all` from the other scope, whose expansion
// overlaps tokens already in the union. The merge must still return each token
// once, as its exact-string dedup contract says.
func TestHostInboundCrossScopeUnionStaysDeduplicated12317(t *testing.T) {
	cfg := compileCrossScopeExcept12317(t, false,
		crossScopePhysical12317+"system-services all",
		crossScopeUnit12317+"system-services all",
		crossScopeUnit12317+"system-services ssh except",
	)
	for _, hib := range crossScopeOverrides12317(t, cfg) {
		seen := make(map[string]bool, len(hib.SystemServices))
		for _, token := range hib.SystemServices {
			if seen[token] {
				t.Errorf("merged services repeat %q: %v", token, hib.SystemServices)
			}
			seen[token] = true
		}
		assertExceptSSHPorts12317(t, hib.SystemServices, false, true, true)
	}
}

// TestMergeHostInboundTrafficSkipsSelfRefilter12317: every stanza was already
// filtered by its own exclusions at compile, so the merge copies a lone stanza
// and filters each input only by the OTHER input's exclusions. Both paths run
// for every unit a physical override fans down to; re-filtering the physical
// tokens there cost about 140 allocations per unit and multiplied resolver
// time several-fold for a 4000-unit physical `all; ssh except`.
func TestMergeHostInboundTrafficSkipsSelfRefilter12317(t *testing.T) {
	cfg := compileCrossScopeExcept12317(t, false,
		crossScopePhysical12317+"system-services all",
		crossScopePhysical12317+"system-services ssh except",
		crossScopeUnit12317+"system-services ping",
	)
	physical := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0"]
	unit := cfg.Security.Zones["trust"].InterfaceHostInbound[crossScopeExceptUnit12317]
	if physical == nil || len(physical.systemServicesExcept) == 0 || unit == nil {
		t.Fatalf("fixture precondition: physical stanza with retained exclusions and a unit stanza, got %+v / %+v",
			physical, unit)
	}
	for _, merged := range []*HostInboundTraffic{
		MergeHostInboundTraffic(nil, physical),
		MergeHostInboundTraffic(physical, nil),
	} {
		if !reflect.DeepEqual(merged.SystemServices, physical.SystemServices) {
			t.Fatalf("single-input merge changed the compiled stanza: got %v, want %v",
				merged.SystemServices, physical.SystemServices)
		}
	}
	want := append([]string(nil), physical.SystemServices...)
	hasPing := false
	for _, token := range want {
		hasPing = hasPing || token == "ping"
	}
	if !hasPing {
		want = append(want, "ping")
	}
	merged := MergeHostInboundTraffic(physical, unit)
	if !reflect.DeepEqual(merged.SystemServices, want) {
		t.Fatalf("cross-scope merge = %v, want the physical tokens plus the unit's ping %v", merged.SystemServices, want)
	}
	assertExceptSSHPorts12317(t, merged.SystemServices, false, true, true)
	for _, tc := range []struct {
		name      string
		a, b      *HostInboundTraffic
		maxAllocs float64
	}{
		{name: "single-input", b: physical, maxAllocs: 16},
		{name: "other-scope-exclusions-only", a: physical, b: unit, maxAllocs: 40},
	} {
		if allocs := testing.AllocsPerRun(100, func() { _ = MergeHostInboundTraffic(tc.a, tc.b) }); allocs > tc.maxAllocs {
			t.Errorf("%s merge made %v allocations, want <= %v: it re-filters tokens their own exclusions already filtered",
				tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestHostInboundCrossScopeExceptAdvisory12317 covers the commit-time notice
// for that narrowing: it names the unit, every contributing stanza and the
// tokens the union no longer fully admits, and stays silent where the union
// loses nothing.
func TestHostInboundCrossScopeExceptAdvisory12317(t *testing.T) {
	warned := []struct {
		name       string
		directives []string
		want       []string
	}{
		{
			name: "physical-exclusion-unit-explicit",
			directives: []string{
				crossScopePhysical12317 + "system-services all",
				crossScopePhysical12317 + "system-services ssh except",
				crossScopePhysical12317 + "protocols all",
				crossScopePhysical12317 + "protocols ospf except",
				crossScopeUnit12317 + "system-services ssh",
				crossScopeUnit12317 + "protocols ospf",
			},
			want: []string{"system-services [ssh]", "protocols [ospf]"},
		},
		{
			name: "physical-alias-unit-exclusion",
			directives: []string{
				crossScopePhysical12317 + "system-services netconf-ssh",
				crossScopeUnit12317 + "system-services all",
				crossScopeUnit12317 + "system-services ssh except",
			},
			want: []string{"system-services [netconf-ssh]"},
		},
		{
			name: "physical-all-unit-protocol-exclusion",
			directives: []string{
				crossScopePhysical12317 + "protocols all",
				crossScopeUnit12317 + "protocols all",
				crossScopeUnit12317 + "protocols ospf except",
			},
			want: []string{"protocols [all]"},
		},
	}
	for _, tc := range warned {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileCrossScopeExcept12317(t, false, tc.directives...)
			got := validateHostInboundCrossScopeExceptWarnings(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly one advisory, got %d: %v", len(got), got)
			}
			for _, want := range append([]string{
				`interface "ge-0/0/0.0"`,
				`zone "trust" interfaces "ge-0/0/0" and zone "trust" interfaces "ge-0/0/0.0"`,
				"#12317",
			}, tc.want...) {
				if !strings.Contains(got[0], want) {
					t.Errorf("advisory must mention %q, got: %s", want, got[0])
				}
			}
			registered := false
			for _, warning := range cfg.Warnings {
				registered = registered || warning == got[0]
			}
			if !registered {
				t.Errorf("advisory is not registered in ValidateConfig; compile warnings: %v", cfg.Warnings)
			}
		})
	}

	silent := []struct {
		name       string
		lenient    bool
		directives []string
	}{
		{
			name: "same-exclusion-in-both-scopes",
			directives: []string{
				crossScopePhysical12317 + "system-services all",
				crossScopePhysical12317 + "system-services ssh except",
				crossScopeUnit12317 + "system-services all",
				crossScopeUnit12317 + "system-services ssh except",
			},
		},
		{
			name: "exclusion-disjoint-from-other-scope",
			directives: []string{
				crossScopePhysical12317 + "system-services all",
				crossScopePhysical12317 + "system-services ssh except",
				crossScopeUnit12317 + "system-services netconf",
			},
		},
		{
			name: "zone-exclusion-replaced-by-interface",
			directives: []string{
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except",
				crossScopeUnit12317 + "system-services ssh",
			},
		},
		{
			// The union drops the unit's explicit ssh, but any-service still
			// full-admits TCP/22, so nothing is narrowed.
			name:    "full-admit-union-narrows-nothing",
			lenient: true,
			directives: []string{
				crossScopePhysical12317 + "system-services all",
				crossScopePhysical12317 + "system-services ssh except",
				crossScopeUnit12317 + "system-services any-service",
				crossScopeUnit12317 + "system-services ssh",
			},
		},
	}
	for _, tc := range silent {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileCrossScopeExcept12317(t, tc.lenient, tc.directives...)
			if got := validateHostInboundCrossScopeExceptWarnings(cfg); len(got) != 0 {
				t.Fatalf("the union loses nothing here; want no advisory, got: %v", got)
			}
		})
	}
}

// TestHostInboundCrossScopeExceptAdvisorySkipsLifelines12317: lifeline
// interfaces are outside host-inbound deny scoping, so a narrowed union there
// changes nothing and must not warn. The ge-0/0/9 control proves the lifeline
// skip, not the fixture, silences fxp0.
func TestHostInboundCrossScopeExceptAdvisorySkipsLifelines12317(t *testing.T) {
	build := func(base string) *Config {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			base: {Name: base, Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}
		cfg.Security.Zones = map[string]*ZoneConfig{"mgmt": {
			Name:       "mgmt",
			Interfaces: []string{base + ".0"},
			InterfaceHostInbound: map[string]*HostInboundTraffic{
				base: {
					SystemServices:       hostInboundFilterExcept([]string{"all"}, []string{"ssh"}, false),
					systemServicesExcept: []string{"ssh"},
				},
				base + ".0": {SystemServices: []string{"ssh"}},
			},
		}}
		return cfg
	}
	if got := validateHostInboundCrossScopeExceptWarnings(build("ge-0/0/9")); len(got) != 1 {
		t.Fatalf("control: a narrowed non-lifeline unit must warn once, got: %v", got)
	}
	if got := validateHostInboundCrossScopeExceptWarnings(build("fxp0")); len(got) != 0 {
		t.Fatalf("fxp0 is excluded from host-inbound deny scoping; want no advisory, got: %v", got)
	}
}

// TestHostInboundCrossScopeExceptAdvisoryIdleWithoutExclusions12317:
// ValidateConfig also backs the alarm views, so a config whose interface
// stanzas carry no exclusion must not pay the advisory's two resolver walks.
func TestHostInboundCrossScopeExceptAdvisoryIdleWithoutExclusions12317(t *testing.T) {
	cfg := compileCrossScopeExcept12317(t, false,
		crossScopePhysical12317+"system-services all",
		crossScopeUnit12317+"system-services ssh",
	)
	if len(ResolveInterfaceHostInbound(cfg)) == 0 {
		t.Fatal("fixture precondition: the resolver must have overrides to walk")
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = validateHostInboundCrossScopeExceptWarnings(cfg) }); allocs != 0 {
		t.Fatalf("advisory made %v allocations on a config without exclusions, want 0", allocs)
	}
}
