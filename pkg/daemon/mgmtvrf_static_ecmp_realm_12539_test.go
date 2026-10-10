package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// FAIL-ON-REVERT (#12539): kernel 7.2.8 rejects RTA_FLOW on multipath
// routes, so ECMP mgmt statics must carry NO realm while single-path
// routes keep the xpf ownership tag. Reverting the fix stamps the realm
// on the ECMP route and this test FAILS.
func TestMgmtStaticRoutesDesiredECMPOmitsRealm12539(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.3 interface fxp0",
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 interface fxp0",
	})
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
	mgmtSet := map[string]bool{"fxp0": true}
	desired := mgmtStaticRoutesDesired(fake, store.ActiveConfig(), mgmtSet, [2][]netlink.Route{})

	byDst := map[string]netlink.Route{}
	for _, target := range desired {
		route := target.route
		if route.Dst != nil {
			byDst[route.Dst.String()] = route
		}
	}
	ecmp, ok := byDst["198.51.100.0/24"]
	if !ok {
		t.Fatal("ECMP static 198.51.100.0/24 missing from desired set")
	}
	if len(ecmp.MultiPath) != 2 {
		t.Fatalf("ECMP route has %d legs, want 2", len(ecmp.MultiPath))
	}
	if ecmp.Realm != 0 {
		t.Fatalf("ECMP route carries realm %#x; kernel rejects RTA_FLOW on multipath", ecmp.Realm)
	}
	if ecmp.Gw != nil || ecmp.LinkIndex != 0 {
		t.Fatalf("ECMP route has single-path fields set: gw=%v ifindex=%d", ecmp.Gw, ecmp.LinkIndex)
	}
	legs := map[string]bool{}
	for _, hop := range ecmp.MultiPath {
		legs[hop.Gw.String()] = true
	}
	if !legs["192.0.2.1"] || !legs["192.0.2.3"] {
		t.Fatalf("ECMP legs = %v, want .1 and .3", legs)
	}
	single, ok := byDst["203.0.113.0/24"]
	if !ok {
		t.Fatal("single-path static 203.0.113.0/24 missing from desired set")
	}
	if len(single.MultiPath) != 0 {
		t.Fatalf("single-path route unexpectedly multipath: %+v", single.MultiPath)
	}
	if single.Realm != mgmtStaticRouteRealm {
		t.Fatalf("single-path route realm = %#x, want %#x", single.Realm, mgmtStaticRouteRealm)
	}
	if single.Gw == nil || !single.Gw.Equal(net.ParseIP("192.0.2.1")) || single.LinkIndex != 7 {
		t.Fatalf("single-path route = gw %v ifindex %d, want .1/7", single.Gw, single.LinkIndex)
	}
}
