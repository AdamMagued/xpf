package config

import (
	"strings"
	"testing"
)

// #8704. #8436's conservation census binds "conserved, refused, or LISTED".
// It does not bind "conserved, refused, or REPORTED", so a listed exception is
// permitted to be SILENT — and six of the nine were, including an IPsec
// traffic-selector that loses its local-ip on a clean strict commit.
//
// An exception mechanism that does not require the exception to be visible
// turns a guard into a registration desk: every future silent site is
// compliant by construction, and the census can run forever without flagging
// one.
//
// This is the binding it lacks: a container that loses configuration to a
// repeated block must SAY SO — on both paths.
func TestEveryNotConservedContainerIsReported8704(t *testing.T) {
	var silent []string
	checked := 0
	for _, s := range collectDupSites8436() {
		if strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		named := s.keyword + " xpfname"
		ctx := contextFor(s.container)
		dupText := nest(s.container, ctx+named+" { "+s.leafA+" "+s.valA+"; } "+named+" { "+s.leafB+" "+s.valB+"; }")
		mergedText := nest(s.container, ctx+named+" { "+s.leafA+" "+s.valA+"; "+s.leafB+" "+s.valB+"; }")
		cd, cm := compileText(t, dupText), compileText(t, mergedText)
		if cd == nil || cm == nil {
			continue
		}
		onlyA := compileText(t, nest(s.container, ctx+named+" { "+s.leafA+" "+s.valA+"; }"))
		if onlyA == nil || cfgEqual(cm, onlyA) {
			continue // vacuous: leafB not observable
		}
		if cfgEqual(cd, cm) {
			continue // conserved — nothing to report
		}
		// NOT CONSERVED. It must be reported on the tolerant path.
		checked++
		tree, errs := NewParser(dupText).Parse()
		if len(errs) > 0 {
			continue
		}
		cfg, err := CompileConfigLenient(tree)
		if cfg == nil || err != nil {
			continue
		}
		reported := false
		for _, w := range cfg.Warnings {
			lw := strings.ToLower(w)
			if strings.Contains(lw, "duplicate") || strings.Contains(w, "#5180") {
				reported = true
			}
		}
		key := strings.Join(s.container, " ") + " " + s.keyword
		if !reported {
			if _, exempt := deepDupUnreportable[key]; !exempt {
				silent = append(silent, key)
			}
			continue
		}
		// A container that IS reported must not also carry an exemption — a
		// stale exemption is a standing claim that reporting it would break
		// something, and the next reader will believe it.
		if reason, exempt := deepDupUnreportable[key]; exempt {
			t.Errorf("container %q is reported AND listed in deepDupUnreportable (%q). The "+
				"exemption is stale: delete it, or the file claims a hazard that no longer "+
				"exists", key, reason)
		}
	}
	// DEGENERACY CONTROL: with nothing not-conserved the loop asserts nothing
	// and would pass on any registry at all.
	if checked == 0 {
		t.Fatal("no not-conserved containers found — this cell cannot see a silent one and its " +
			"silence means nothing. Re-derive it against whatever now distinguishes them")
	}
	// Every exemption must correspond to a container the census still finds
	// not-conserved. An exemption for a container that no longer exists, or
	// that now conserves, is dead weight that reads as a live hazard.
	if len(deepDupUnreportable) == 0 {
		t.Log("no exemptions recorded — every not-conserved container is reported")
	}
	for _, s := range silent {
		t.Errorf("container %q loses configuration to a repeated block and reports NOTHING on the "+
			"tolerant path. A listed exception that is silent is compliant with #8436's census by "+
			"construction, which is how these went unseen — add a namedDupRules or deepDupRules "+
			"row with a MEASURED effect (#8704)", s)
	}
	t.Logf("#8704: %d not-conserved containers checked, %d silent, %d exempted with a measured reason",
		checked, len(silent), len(deepDupUnreportable))
}

// #12308: measure why this census divergence is not generically reported.
// Both modifiers survive on separate entries; a generic dropped-block report
// would overstate what this measurement establishes.
func TestQualifiedNextHopCensusExemptionIsMeasured8704(t *testing.T) {
	const dupAB = `routing-options { static { route 0.0.0.0/0 {
		qualified-next-hop 192.168.1.1 { interface ge-0/0/1.0; }
		qualified-next-hop 192.168.1.1 { metric 100; }
	} } }`
	const dupBA = `routing-options { static { route 0.0.0.0/0 {
		qualified-next-hop 192.168.1.1 { metric 100; }
		qualified-next-hop 192.168.1.1 { interface ge-0/0/1.0; }
	} } }`
	parse := func(text string) *ConfigTree {
		tree, errs := NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse repeated QNH fixture: %v", errs[0])
		}
		return tree
	}
	assertSplitEntries := func(name, text string) {
		t.Helper()
		cfg, err := CompileConfig(parse(text))
		if err != nil {
			t.Fatalf("%s strict compile: %v", name, err)
		}
		if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
			len(cfg.RoutingOptions.StaticRoutes[0].NextHops) != 2 {
			t.Fatalf("%s should retain two next-hop entries: %+v", name, cfg.RoutingOptions.StaticRoutes)
		}
		haveInterface, haveMetric := false, false
		for _, nh := range cfg.RoutingOptions.StaticRoutes[0].NextHops {
			if nh.Interface != "" {
				haveInterface = true
				if nh.HasMetric {
					t.Fatalf("%s unexpectedly merged modifiers onto one entry: %+v", name, nh)
				}
			}
			if nh.HasMetric {
				haveMetric = nh.Metric == 100
				if nh.Interface != "" {
					t.Fatalf("%s unexpectedly merged modifiers onto one entry: %+v", name, nh)
				}
			}
		}
		if !haveInterface || !haveMetric {
			t.Fatalf("%s did not retain interface and metric separately", name)
		}
	}
	assertSplitEntries("interface-then-metric", dupAB)
	assertSplitEntries("metric-then-interface", dupBA)

	flat, err := CompileConfig(flatTreeFromSets(t,
		"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 interface ge-0/0/1.0",
		"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric 100"))
	if err != nil {
		t.Fatalf("flat-set control compile: %v", err)
	}
	if len(flat.RoutingOptions.StaticRoutes) != 1 ||
		len(flat.RoutingOptions.StaticRoutes[0].NextHops) != 1 {
		t.Fatalf("flat-set control should merge modifiers onto one next-hop: %+v",
			flat.RoutingOptions.StaticRoutes)
	}
	merged := flat.RoutingOptions.StaticRoutes[0].NextHops[0]
	if merged.Interface != "ge-0/0/1.0" || !merged.HasMetric || merged.Metric != 100 {
		t.Fatalf("flat-set control did not preserve both modifiers: %+v", merged)
	}
	key := "routing-options static route xpfname qualified-next-hop"
	if reason := deepDupUnreportable[key]; reason == "" {
		t.Fatalf("the measured QNH divergence must have a recorded #8704 disposition")
	} else if !strings.Contains(reason, "#12308") {
		t.Fatalf("the measured QNH exemption must cite #12308: %q", reason)
	}
}

// The finding that made this issue severe, asserted on the compiled config.
// A traffic selector decides which traffic enters the tunnel; it renders into
// swanctl.conf, so a dropped local-ip negotiates an SA against a selector the
// operator did not write.
func TestReopenedTrafficSelectorIsRejectedAndReported8704(t *testing.T) {
	const dup = `security { ipsec { vpn v1 { bind-interface st0; traffic-selector ts1 { local-ip 10.0.0.0/24; } traffic-selector ts1 { remote-ip 10.1.0.0/24; } } } }`
	const merged = `security { ipsec { vpn v1 { bind-interface st0; traffic-selector ts1 { local-ip 10.0.0.0/24; remote-ip 10.1.0.0/24; } } } }`

	// POSITIVE HALF: the merged spelling must carry both halves, or the loss
	// asserted below is not attributable to the re-opening.
	mc := compileText(t, merged)
	if mc == nil {
		t.Fatal("the merged control must compile")
	}
	var mLocal, mRemote string
	for _, v := range mc.Security.IPsec.VPNs {
		for _, ts := range v.TrafficSelectors {
			mLocal, mRemote = ts.LocalIP, ts.RemoteIP
		}
	}
	if mLocal == "" || mRemote == "" {
		t.Fatalf("the merged control lost a half itself (local=%q remote=%q); the fixture no "+
			"longer isolates the re-opening", mLocal, mRemote)
	}

	tree, errs := NewParser(dup).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a re-opened traffic-selector still COMMITS CLEAN. It loses its local-ip, and a " +
			"traffic selector decides which traffic enters the tunnel (#8704)")
	}
	t2, _ := NewParser(dup).Parse()
	cfg, err := CompileConfigLenient(t2)
	if err != nil || cfg == nil {
		t.Fatalf("the tolerant path must not hard-fail: %v", err)
	}
	found := ""
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "traffic-selector") {
			found = w
		}
	}
	if found == "" {
		t.Error("the tolerant path loses the local-ip and reports nothing (#8704)")
	}
	// The message must state what was DROPPED, not something inferred. Three
	// diagnostics on this board today misdescribed their outcome, and a wrong
	// one is worse than none: it is specific, credible, and sends the remedy
	// the wrong way. Measured in both orders, the later block wins.
	if found != "" && !strings.Contains(found, "LAST") {
		t.Errorf("the warning does not say the LAST block wins, which is what was measured in "+
			"both authoring orders: %q", found)
	}
}

// OVER-REACH CONTROL. Two different VPNs may each carry a selector of the same
// name — they are distinct objects, and a rule-wide duplicate map would reject
// working configuration. This is why the walk scopes `seen` to the immediate
// holder rather than to the rule.
func TestSameSelectorNameInTwoVPNsIsNotADuplicate8704(t *testing.T) {
	const twoVPN = `security { ipsec { vpn v1 { bind-interface st0; traffic-selector ts1 { local-ip 10.0.0.0/24; remote-ip 10.1.0.0/24; } } vpn v2 { bind-interface st0; traffic-selector ts1 { local-ip 10.2.0.0/24; remote-ip 10.3.0.0/24; } } } }`
	tree, errs := NewParser(twoVPN).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("two VPNs each with a selector named ts1 is valid configuration and must still "+
			"commit; the duplicate scope has leaked across holders: %v", err)
	}
	cfg := compileText(t, twoVPN)
	if cfg == nil {
		t.Fatal("must compile")
	}
	total := 0
	for _, v := range cfg.Security.IPsec.VPNs {
		total += len(v.TrafficSelectors)
	}
	// POSITIVE HALF: if the fixture produced one selector the assertion above
	// would pass for the wrong reason.
	if total != 2 {
		t.Errorf("expected 2 selectors across the 2 VPNs, got %d — the fixture no longer "+
			"exercises two distinct holders", total)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "traffic-selector") {
			t.Errorf("valid config warned about a duplicate: %q", w)
		}
	}
}
