package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12317 on the two enforcement planes. config.ResolveInterfaceHostInbound
// reapplies every contributing stanza's exclusions to the physical∪unit union,
// and zones_override.go requires that breaking it reds an enforcement test as
// well as the pkg/config advisories. This cell reads what the planes consume:
// the kernel-nft input views (BuildZoneHostInboundViews) and the per-interface
// set shipped to the Rust dataplane on the unit row (buildInterfaceSnapshots).
//
// RED on revert: drop the exclusion union in config.MergeHostInboundTraffic and
// the physical netconf-ssh alias re-admits TCP/22 on both planes (the reported
// `tcp dport { 22, 830 } accept`), and the explicit unit `ospf` re-admits IP
// protocol 89.

const (
	crossScopeUnit12317   = "ge-0/0/0.0"
	crossScopeV4Addr12317 = "10.0.2.1"
	crossScopeV6Addr12317 = "2001:db8:2::1"
)

func TestHostInboundCrossScopeExceptReachesEnforcement12317(t *testing.T) {
	exclusion := []string{
		"system-services all",
		"system-services ssh except",
		"protocols all",
		"protocols ospf except",
	}
	positive := []string{"system-services netconf-ssh", "protocols ospf"}
	cases := []struct {
		name           string
		physical, unit []string
	}{
		{name: "physical-alias-unit-exclusion", physical: positive, unit: exclusion},
		{name: "physical-exclusion-unit-alias", physical: exclusion, unit: positive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set interfaces ge-0/0/0 unit 0 family inet address " + crossScopeV4Addr12317 + "/24",
				"set interfaces ge-0/0/0 unit 0 family inet6 address " + crossScopeV6Addr12317 + "/64",
				"set security zones security-zone trust interfaces " + crossScopeUnit12317,
			}
			for _, d := range tc.physical {
				lines = append(lines, "set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic "+d)
			}
			for _, d := range tc.unit {
				lines = append(lines, "set security zones security-zone trust interfaces "+crossScopeUnit12317+" host-inbound-traffic "+d)
			}
			cfg, err := config.CompileConfig(treeFromSet6722(t, lines))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}

			// Kernel nft: every view scoping the unit's addresses must deny
			// TCP/22 and IPv4 OSPF while keeping the independent services.
			viewsV4, viewsV6 := 0, 0
			for _, v := range BuildZoneHostInboundViews(cfg) {
				hasV4, hasV6 := containsStr(v.V4Addrs, crossScopeV4Addr12317), containsStr(v.V6Addrs, crossScopeV6Addr12317)
				if hasV4 {
					viewsV4++
					assertCrossScopeAdmission12317(t, "kernel-nft view (ip)", "ip", v.SystemServices, v.Protocols)
				}
				if hasV6 {
					viewsV6++
					assertCrossScopeAdmission12317(t, "kernel-nft view (ip6)", "ip6", v.SystemServices, v.Protocols)
				}
			}
			if viewsV4 == 0 || viewsV6 == 0 {
				t.Fatalf("no kernel-nft view scopes %s/%s (v4 views %d, v6 views %d); the assertions would be vacuous",
					crossScopeV4Addr12317, crossScopeV6Addr12317, viewsV4, viewsV6)
			}

			// AF_XDP: the unit row's per-interface set is what the Rust
			// LocalDelivery check enforces.
			var found bool
			for _, snap := range buildInterfaceSnapshots(cfg) {
				if snap.Name != crossScopeUnit12317 {
					continue
				}
				found = true
				if !snap.HostInboundConfigured {
					t.Fatalf("unit row carries no host-inbound override stamp: %+v", snap)
				}
				for _, family := range []string{"ip", "ip6"} {
					assertCrossScopeAdmission12317(t, "AF_XDP unit row", family,
						snap.HostInboundSystemServices, snap.HostInboundProtocols)
				}
			}
			if !found {
				t.Fatalf("no %s snapshot row", crossScopeUnit12317)
			}
		})
	}
}

// assertCrossScopeAdmission12317 checks one plane's token sets in one family:
// TCP/22 and IPv4 OSPF denied; TCP/830 (netconf), TCP/80 and BGP admitted as
// the non-vacuity controls.
func assertCrossScopeAdmission12317(t *testing.T, plane, family string, services, protocols []string) {
	t.Helper()
	ssh := admitsHostInbound12317(services, false, family, config.HostInboundProtoTCP, 22)
	netconf := admitsHostInbound12317(services, false, family, config.HostInboundProtoTCP, 830)
	http := admitsHostInbound12317(services, false, family, config.HostInboundProtoTCP, 80)
	bgp := admitsHostInbound12317(protocols, true, family, config.HostInboundProtoTCP, 179)
	if ssh || !netconf || !http || !bgp {
		t.Errorf("%s on %s admits ssh:22=%t netconf:830=%t http:80=%t bgp:179=%t; want false,true,true,true\nservices=%v\nprotocols=%v",
			plane, family, ssh, netconf, http, bgp, services, protocols)
	}
	if family == "ip" && admitsHostInbound12317(protocols, true, family, 89, 0) {
		t.Errorf("%s on ip admits OSPF (IP protocol 89) excluded by the other scope: %v", plane, protocols)
	}
}

// admitsHostInbound12317 reports whether tokens admit proto/port in family
// through the shared SSOT matchers. port 0 asks for a bare IP-protocol match.
func admitsHostInbound12317(tokens []string, protocols bool, family string, proto uint8, port uint16) bool {
	for _, token := range tokens {
		matches := config.HostInboundServiceMatch(token, family)
		if protocols {
			matches = config.HostInboundProtocolMatch(token, family)
		}
		for _, m := range matches {
			if m.Reject || m.Proto != proto {
				continue
			}
			if port == 0 && len(m.Ports) == 0 && m.ICMPType == nil {
				return true
			}
			for _, r := range m.Ports {
				if r.Lo <= port && port <= r.Hi {
					return true
				}
			}
		}
	}
	return false
}
