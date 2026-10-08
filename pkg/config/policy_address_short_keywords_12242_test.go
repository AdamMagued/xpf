package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12242: strict commit accepts the internal short forms `any4` / `any6`, so a
// committed config can carry them, and every surface that classifies a policy
// address keyword must recognise the same set — PolicyAddressWildcardFamilies.
// The junos-host projection kept a private long-form table. `any4` fell through
// to its literal parser, failed, marked the term unrepresentable, and withdrew
// the WHOLE ingress-zone kernel DROP program, correctly spelled denies included,
// behind only the generic #4168 advisory. Before the strict gate accepted the
// short forms that config was rejected at commit, so a partial alignment turns a
// fail-closed reject into weaker enforcement.

// policyLines12242 renders one from-zone trust to-zone junos-host policy whose
// `field` address dimension ("source" or "destination") is tok and whose other
// address dimension is `any`.
func policyLines12242(name, field, tok, app, action string) []string {
	src, dst := "any", "any"
	if field == "source" {
		src = tok
	} else {
		dst = tok
	}
	p := junosHost9572Pol + name + " "
	return []string{
		p + "match source-address " + src,
		p + "match destination-address " + dst,
		p + "match application " + app,
		p + "then " + action,
	}
}

// TestJunosHostKeywordSetIsTheSSOT12242 pins every keyword arm of the junos-host
// resolver, and both scope predicates the #4146 warning uses, to the SSOT.
func TestJunosHostKeywordSetIsTheSSOT12242(t *testing.T) {
	for _, kw := range []string{"any", "any-ipv4", "any4", "any-ipv6", "any6"} {
		wantV4, wantV6, isKW := PolicyAddressWildcardFamilies(kw)
		if !isKW {
			t.Fatalf("fixture premise broken: %q is not a policy match-all keyword", kw)
		}
		cfg := &Config{}
		cfg.Security.AddressBook = &AddressBook{
			Addresses: map[string]*Address{
				// The TOKEN arm runs before any name lookup (#9523), so an object
				// named after the keyword, which only the tolerant channel can
				// carry, must not capture it.
				kw: {Name: kw, Value: "10.98.0.0/16"},
				// The VALUE arm (addCIDR). The compiler never stores a keyword as
				// an address value (looksLikeIPOrCIDR), but the arm must not keep a
				// private copy of the keyword table either.
				"kw-value": {Name: "kw-value", Value: kw},
			},
		}
		for _, arm := range []struct {
			name   string
			tokens []string
		}{
			{"token", []string{kw}},
			{"address value", []string{"kw-value"}},
		} {
			v4, v6, anyV4, anyV6, ok := junosHostResolveAddrSet(cfg, arm.tokens, nil)
			if !ok || anyV4 != wantV4 || anyV6 != wantV6 || len(v4) != 0 || len(v6) != 0 {
				t.Errorf("%s arm, %q: junosHostResolveAddrSet = v4=%v v6=%v any=(%v,%v) ok=%v, want any=(%v,%v) ok=true and no prefixes",
					arm.name, kw, v4, v6, anyV4, anyV6, ok, wantV4, wantV6)
			}
		}
		if junosHostAddrScoped([]string{kw}) {
			t.Errorf("junosHostAddrScoped([%q]) = true; a match-all keyword is not an address scope", kw)
		}
		for _, m := range []PolicyMatch{
			{SourceAddresses: []string{kw}, DestinationAddresses: []string{"any"}},
			{SourceAddresses: []string{"any"}, DestinationAddresses: []string{kw}},
		} {
			if stricter, why := junosHostPolicyStricterThanCoarseGate(PolicyPermit, m); stricter || why != "" {
				t.Errorf("permit %+v: junosHostPolicyStricterThanCoarseGate = (%v, %q), want (false, \"\"); a match-all permit adds nothing the coarse gate lacks",
					m, stricter, why)
			}
		}
	}

	// Controls: the near-miss `any5` is a name, not a keyword. It fails to
	// resolve and IS a scope in either dimension, so the predicates above are not
	// vacuously true.
	if _, _, _, _, ok := junosHostResolveAddrSet(&Config{}, []string{"any5"}, nil); ok {
		t.Error("control: the non-keyword any5 resolved")
	}
	for _, c := range []struct {
		m   PolicyMatch
		why string
	}{
		{PolicyMatch{SourceAddresses: []string{"any5"}, DestinationAddresses: []string{"any"}}, "source-restricted permit"},
		{PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any5"}}, "destination-restricted permit"},
	} {
		if stricter, why := junosHostPolicyStricterThanCoarseGate(PolicyPermit, c.m); !stricter || why != c.why {
			t.Errorf("control: permit %+v = (%v, %q), want (true, %q)", c.m, stricter, why, c.why)
		}
	}
}

// TestJunosHostShortFamilyKeywordsProjectLikeLongForms12242 is the end-to-end
// parity pin on the strict channel. For each family pair and each address
// dimension, the short spelling must project EXACTLY what the long spelling
// projects, and draw exactly the same warnings.
//
// "deny" is a deny scoped by the keyword alone. Before the fix it committed and
// projected nothing. "poison" is the wider consequence: the correctly spelled
// #6705 deny p2 (source NET9) followed by a permit spelled with the keyword. One
// unrepresentable term withdraws the whole ingress-zone program, so p2 lost its
// kernel DROP and the #11065 terminal deny, and direct ssh from 10.0.9.0/24 fell
// back to the coarse permit-by-service gate. The short-form permit also drew a
// spurious #4146 "restricted permit" warning.
func TestJunosHostShortFamilyKeywordsProjectLikeLongForms12242(t *testing.T) {
	fixtures := []struct {
		name     string
		policies func(field, tok string) []string
		deny     string // the deny whose kernel DROP must be rendered
	}{
		{"deny", func(field, tok string) []string {
			return policyLines12242("d1", field, tok, "junos-ssh", "deny")
		}, "d1"},
		{"poison", func(field, tok string) []string {
			return append(junosHost6705Deny(), policyLines12242("p3", field, tok, "junos-ssh", "permit")...)
		}, "p2"},
	}
	for _, pair := range []struct{ long, short string }{{"any-ipv4", "any4"}, {"any-ipv6", "any6"}} {
		for _, field := range []string{"source", "destination"} {
			for _, fx := range fixtures {
				t.Run(fx.name+"/"+field+"/"+pair.short, func(t *testing.T) {
					build := func(tok string) (*Config, JunosHostDenyProjection) {
						cfg, err := compileJunosHost9572(t, true, append(junosHost6705Base(), fx.policies(field, tok)...)...)
						if err != nil {
							t.Fatalf("strict commit with %s-address %s: %v", field, tok, err)
						}
						return cfg, BuildJunosHostDenyProjection(cfg)
					}
					longCfg, longProj := build(pair.long)
					shortCfg, shortProj := build(pair.short)
					key := JunosHostZonePairPolicyKey("trust", fx.deny)

					long := junosHost9572Program(longProj)
					if long == nil || !long.Representable || !longProj.RenderedPolicyKeys[key] {
						t.Fatalf("premise broken: %s did not project an enforced %s: program=%+v rendered=%v",
							pair.long, fx.deny, long, longProj.RenderedPolicyKeys[key])
					}
					short := junosHost9572Program(shortProj)
					if short == nil || short.Representable != long.Representable ||
						!reflect.DeepEqual(short.RulesV4, long.RulesV4) || !reflect.DeepEqual(short.RulesV6, long.RulesV6) {
						t.Fatalf("%s-address %s projected differently from %s:\n  short=%+v\n  long =%+v",
							field, pair.short, pair.long, short, long)
					}
					if !shortProj.RenderedPolicyKeys[key] {
						t.Fatalf("%s-address %s: deny %s lost its kernel DROP (not rendered)", field, pair.short, fx.deny)
					}
					if !reflect.DeepEqual(shortProj, longProj) {
						t.Fatalf("%s-address %s: projection bookkeeping differs from %s:\n  short=%+v\n  long =%+v",
							field, pair.short, pair.long, shortProj, longProj)
					}
					if !reflect.DeepEqual(shortCfg.Warnings, longCfg.Warnings) {
						t.Errorf("%s-address %s: warnings differ from %s:\n  short=%q\n  long =%q",
							field, pair.short, pair.long, shortCfg.Warnings, longCfg.Warnings)
					}
				})
			}
		}
	}
}

// TestJunosHostKeywordBeatsASameNamedObjectOnTheTolerantPath12242 pins the ORDER
// of the resolver's keyword check (#9523: keywords before any name lookup).
// Strict commit rejects an object named after a keyword, so only the tolerant
// channel (persisted load, HA peer sync) can carry one, and only there is a
// resolver that consults the book first captured by it. The strict parity pin
// cannot see the order: with no such object a short keyword that reaches the
// literal parser's keyword arm projects the same way.
func TestJunosHostKeywordBeatsASameNamedObjectOnTheTolerantPath12242(t *testing.T) {
	for _, kw := range []string{"any-ipv4", "any4", "any-ipv6", "any6"} {
		t.Run(kw, func(t *testing.T) {
			policy := policyLines12242("d1", "source", kw, "junos-ssh", "deny")
			withObject := append(append(junosHost6705Base(),
				"set security address-book global address "+kw+" 10.98.0.0/16"), policy...)
			if _, err := compileJunosHost9572(t, true, withObject...); err == nil {
				t.Fatalf("fixture premise broken: strict commit accepted an address named %q (#9523), so this cell no longer measures the tolerant path", kw)
			}
			shadowed, err := compileJunosHost9572(t, false, withObject...)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			plain, err := compileJunosHost9572(t, false, append(junosHost6705Base(), policy...)...)
			if err != nil {
				t.Fatalf("lenient compile without the object: %v", err)
			}
			want := junosHost9572Program(BuildJunosHostDenyProjection(plain))
			if want == nil || !want.Representable {
				t.Fatalf("the keyword %q alone did not project a representable program: %+v", kw, want)
			}
			got := junosHost9572Program(BuildJunosHostDenyProjection(shadowed))
			if got == nil || !reflect.DeepEqual(*got, *want) {
				t.Fatalf("the address named %q captured the keyword:\n  got =%+v\n  want=%+v", kw, got, want)
			}
		})
	}
}

// TestShortFamilyKeywordSkipsTheAddressSetMemberGate12242 pins the keyword arm
// of the #3149 member gate (validatePolicyMatchAddressSetMembersStrict). Strict
// commit rejects an object named after a keyword (#9523), so no strict fixture
// can observe the arm. On the tolerant channel a set named `any4` with a
// dangling member must not be blamed on a policy whose `any4` is the keyword.
// The ordinary name is the control: the same channel does report its dangling
// set.
func TestShortFamilyKeywordSkipsTheAddressSetMemberGate12242(t *testing.T) {
	for _, tc := range []struct {
		tok      string
		wantWarn bool
	}{
		{"any4", false},
		{"any6", false},
		{"corp", true},
	} {
		t.Run(tc.tok, func(t *testing.T) {
			p := "set security policies from-zone trust to-zone untrust policy fam "
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security address-book global address-set " + tc.tok + " address ghost",
				p + "match source-address " + tc.tok,
				p + "match destination-address any",
				p + "match application any",
				p + "then permit",
			}))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var got []string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "does not fully resolve") {
					got = append(got, w)
				}
			}
			if (len(got) > 0) != tc.wantWarn {
				t.Fatalf("source-address %q: 'does not fully resolve' warnings = %q, want present=%v",
					tc.tok, got, tc.wantWarn)
			}
		})
	}
}

// TestShortFamilyKeywordsDrawNoTolerantPathWarnings12242 pins the shared
// recognition predicate (policyMatchAddressTokenRecognized) on the channel where
// both of its callers are visible: the tolerant compile downgrades the #2008
// strict reject to a warning, and the #3958 ValidateConfig pass reuses the
// predicate for its "not in address-book" advisory. Before #12242 a lenient
// compile of any4/any6 drew three such warnings. The near-miss row is the
// control: both warnings still fire for a real typo.
func TestShortFamilyKeywordsDrawNoTolerantPathWarnings12242(t *testing.T) {
	for _, tc := range []struct {
		src, dst string
		wantWarn bool
	}{
		{"any4", "any6", false},
		{"any5", "any7", true},
	} {
		t.Run(tc.src+"/"+tc.dst, func(t *testing.T) {
			p := "set security policies from-zone trust to-zone untrust policy fam "
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				p + "match source-address " + tc.src,
				p + "match destination-address " + tc.dst,
				p + "match application any",
				p + "then permit",
			}))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var got []string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, `"`+tc.src+`"`) || strings.Contains(w, `"`+tc.dst+`"`) {
					got = append(got, w)
				}
			}
			if !tc.wantWarn {
				if len(got) != 0 {
					t.Fatalf("keywords %s/%s drew tolerant-path warnings: %q", tc.src, tc.dst, got)
				}
				return
			}
			for _, want := range []string{"is not a defined address-book entry", "not in address-book"} {
				found := false
				for _, w := range got {
					found = found || strings.Contains(w, want)
				}
				if !found {
					t.Errorf("control %s/%s: no %q warning; got %q", tc.src, tc.dst, want, got)
				}
			}
		})
	}
}
