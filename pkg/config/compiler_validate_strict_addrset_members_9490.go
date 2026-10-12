package config

import (
	"errors"
	"fmt"
	"sort"
)

// validateAddressSetMembersDefinedStrict (#9490/#11822) refuses address-set
// members that name no address or address-set, and unknown member statements
// that the lenient compiler would otherwise drop. A dangling member leaves the
// set short at runtime; an unknown statement silently drops an authored member
// outright. Either can narrow a DENY policy and permit traffic the operator
// meant to block.
//
// It runs on the compiled global book, after resolveZoneLocalAddressBooks has
// folded zone-local books in and qualified the members they define locally.
// This definedness pass accepts a member if it is either an address or an
// address-set, matching the runtime resolver; policy wildcards are also
// admissible here. #12214's following expansion pass mirrors ExpandAddressSet
// instead: each `address-set`-leaf member must be an address-set, not merely an
// address or wildcard. It also refuses cycles and nesting beyond five edges,
// matching the apply-time expansion failures for cycles and 6+ edges.
func validateAddressSetMembersDefinedStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.AddressBook == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	defined := func(name string) bool {
		if IsPolicyAddressWildcardKeyword(name) {
			return true
		}
		if _, ok := ab.Addresses[name]; ok {
			return true
		}
		_, ok := ab.AddressSets[name]
		return ok
	}
	show := func(name string) string {
		if zone, local, ok := ZoneLocalUnqualify(name); ok {
			return fmt.Sprintf("%s (security-zone %s)", local, zone)
		}
		return name
	}
	names := make([]string, 0, len(ab.AddressSets))
	for n := range ab.AddressSets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		set := ab.AddressSets[name]
		if set == nil {
			continue
		}
		if len(set.UnknownMembers) > 0 {
			return fmt.Errorf("address-set %s: unknown member statement %q; the "+
				"unrecognized keyword is silently dropped, leaving the set under-populated "+
				"and a deny policy referencing it able to permit traffic meant to be blocked",
				show(name), set.UnknownMembers[0])
		}
		for _, kind := range []struct {
			leaf    string
			members []string
		}{{"address", set.Addresses}, {"address-set", set.AddressSets}} {
			for _, m := range kind.members {
				if !defined(m) {
					return fmt.Errorf("address-set %s %s %q is not a defined address or "+
						"address-set; the member resolves to nothing, so the set "+
						"silently matches less than it lists", show(name), kind.leaf, show(m))
				}
			}
		}
	}

	// #12214: compileAddressBook expands every set during the shared prepass,
	// including sets unused by policies. Reject the same depth/cycle failures at
	// commit instead of allowing a green commit to abort every apply.
	for _, name := range names {
		if err := validateAddressSetDepthAndCycles(name, ab); err != nil {
			detail := err.Error()
			var expansionErr *addressSetExpansionError
			if errors.As(err, &expansionErr) {
				detail = expansionErr.displayName(show)
			}
			return fmt.Errorf("address-set %s cannot be expanded: %s", show(name), detail)
		}
	}

	return nil
}
